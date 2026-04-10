use std::collections::{BTreeSet, HashMap};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::model::{
    DiskDiff, PathDiff, Recommendation, RecommendationChange, RecommendationChangeKind, Report,
    ReportDiff, ReportImportResult, ReportSummary,
};

const APP_DIR_NAME: &str = "storage-strategist";
const STORE_DIR_NAME: &str = "report-store";
const REPORTS_DIR_NAME: &str = "reports";
const INDEX_FILE_NAME: &str = "index.json";
const HISTORY_FILE_NAME: &str = "history.json";

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct ReportIndex {
    #[serde(default)]
    reports: Vec<ReportSummary>,
}

pub fn default_report_store_dir() -> PathBuf {
    if cfg!(target_os = "windows") {
        env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(env::temp_dir)
            .join(APP_DIR_NAME)
            .join(STORE_DIR_NAME)
    } else if let Some(state_home) = env::var_os("XDG_STATE_HOME") {
        PathBuf::from(state_home)
            .join(APP_DIR_NAME)
            .join(STORE_DIR_NAME)
    } else if let Some(home) = env::var_os("HOME") {
        PathBuf::from(home)
            .join(".local")
            .join("state")
            .join(APP_DIR_NAME)
            .join(STORE_DIR_NAME)
    } else {
        env::temp_dir().join(APP_DIR_NAME).join(STORE_DIR_NAME)
    }
}

pub fn resolve_report_store_dir(custom_dir: Option<&Path>) -> PathBuf {
    custom_dir
        .map(PathBuf::from)
        .unwrap_or_else(default_report_store_dir)
}

pub fn history_file_path(custom_dir: Option<&Path>) -> PathBuf {
    resolve_report_store_dir(custom_dir).join(HISTORY_FILE_NAME)
}

pub fn report_path_for_scan(scan_id: &str, custom_dir: Option<&Path>) -> PathBuf {
    reports_dir(custom_dir).join(format!("{scan_id}.json"))
}

pub fn list_reports(custom_dir: Option<&Path>) -> Result<Vec<ReportSummary>> {
    let mut index = load_index(custom_dir)?;
    let changed = cleanup_orphaned_entries(&mut index);
    sort_reports(&mut index.reports);
    if changed {
        save_index(custom_dir, &index)?;
    }
    Ok(index.reports)
}

pub fn store_report(
    report: &Report,
    custom_dir: Option<&Path>,
    source_path: Option<&Path>,
    imported: bool,
) -> Result<ReportSummary> {
    ensure_store_layout(custom_dir)?;

    let stored_report_path = report_path_for_scan(&report.scan_id, custom_dir);
    let payload = serde_json::to_string_pretty(report).context("failed to serialize report")?;
    fs::write(&stored_report_path, payload).with_context(|| {
        format!(
            "failed to write stored report {}",
            stored_report_path.display()
        )
    })?;

    let mut index = load_index(custom_dir)?;
    cleanup_orphaned_entries(&mut index);

    let summary = build_summary(report, &stored_report_path, source_path, imported);
    index
        .reports
        .retain(|entry| entry.scan_id != summary.scan_id);
    index.reports.push(summary.clone());
    sort_reports(&mut index.reports);
    save_index(custom_dir, &index)?;

    Ok(summary)
}

pub fn import_report(
    path: impl AsRef<Path>,
    custom_dir: Option<&Path>,
) -> Result<ReportImportResult> {
    let source_path = path.as_ref();
    let payload = fs::read_to_string(source_path)
        .with_context(|| format!("failed to read report {}", source_path.display()))?;
    let report: Report = serde_json::from_str(&payload)
        .with_context(|| format!("failed to parse {}", source_path.display()))?;
    let summary = store_report(&report, custom_dir, Some(source_path), true)?;
    Ok(ReportImportResult { summary })
}

pub fn get_report(scan_id: &str, custom_dir: Option<&Path>) -> Result<Report> {
    let path = report_path_for_scan(scan_id, custom_dir);
    let payload = fs::read_to_string(&path)
        .with_context(|| format!("failed to read stored report {}", path.display()))?;
    let report: Report = serde_json::from_str(&payload)
        .with_context(|| format!("failed to parse stored report {}", path.display()))?;
    Ok(report)
}

pub fn compare_reports(
    left_scan_id: &str,
    right_scan_id: &str,
    custom_dir: Option<&Path>,
) -> Result<ReportDiff> {
    let left = get_report(left_scan_id, custom_dir)?;
    let right = get_report(right_scan_id, custom_dir)?;
    Ok(build_report_diff(&left, &right))
}

pub fn build_report_diff(left: &Report, right: &Report) -> ReportDiff {
    ReportDiff {
        left_scan_id: left.scan_id.clone(),
        right_scan_id: right.scan_id.clone(),
        left_generated_at: left.generated_at.clone(),
        right_generated_at: right.generated_at.clone(),
        duplicate_wasted_bytes_delta: signed_delta(
            Some(total_duplicate_waste(left)),
            Some(total_duplicate_waste(right)),
        ),
        disk_diffs: build_disk_diffs(left, right),
        path_diffs: build_path_diffs(left, right),
        recommendation_changes: build_recommendation_changes(left, right),
    }
}

fn build_disk_diffs(left: &Report, right: &Report) -> Vec<DiskDiff> {
    let left_by_mount = left
        .disks
        .iter()
        .map(|disk| (disk.mount_point.clone(), disk))
        .collect::<HashMap<_, _>>();
    let right_by_mount = right
        .disks
        .iter()
        .map(|disk| (disk.mount_point.clone(), disk))
        .collect::<HashMap<_, _>>();

    let mounts = left_by_mount
        .keys()
        .chain(right_by_mount.keys())
        .cloned()
        .collect::<BTreeSet<_>>();

    mounts
        .into_iter()
        .filter_map(|mount_point| {
            let left_disk = left_by_mount.get(&mount_point);
            let right_disk = right_by_mount.get(&mount_point);
            let delta = signed_delta(
                left_disk.map(|disk| disk.free_space_bytes),
                right_disk.map(|disk| disk.free_space_bytes),
            );

            if delta == 0 && left_disk.is_some() == right_disk.is_some() {
                return None;
            }

            Some(DiskDiff {
                mount_point,
                name: right_disk.or(left_disk).map(|disk| disk.name.clone()),
                left_free_space_bytes: left_disk.map(|disk| disk.free_space_bytes),
                right_free_space_bytes: right_disk.map(|disk| disk.free_space_bytes),
                free_space_delta_bytes: delta,
            })
        })
        .collect()
}

fn build_path_diffs(left: &Report, right: &Report) -> Vec<PathDiff> {
    let left_by_root = left
        .paths
        .iter()
        .map(|path| (path.root_path.clone(), path))
        .collect::<HashMap<_, _>>();
    let right_by_root = right
        .paths
        .iter()
        .map(|path| (path.root_path.clone(), path))
        .collect::<HashMap<_, _>>();

    let roots = left_by_root
        .keys()
        .chain(right_by_root.keys())
        .cloned()
        .collect::<BTreeSet<_>>();

    roots
        .into_iter()
        .filter_map(|root_path| {
            let left_path = left_by_root.get(&root_path);
            let right_path = right_by_root.get(&root_path);
            let bytes_delta = signed_delta(
                left_path.map(|path| path.total_size_bytes),
                right_path.map(|path| path.total_size_bytes),
            );
            let file_count_delta = signed_delta(
                left_path.map(|path| path.file_count),
                right_path.map(|path| path.file_count),
            );

            if bytes_delta == 0
                && file_count_delta == 0
                && left_path.is_some() == right_path.is_some()
            {
                return None;
            }

            Some(PathDiff {
                root_path,
                left_total_size_bytes: left_path.map(|path| path.total_size_bytes),
                right_total_size_bytes: right_path.map(|path| path.total_size_bytes),
                total_size_delta_bytes: bytes_delta,
                left_file_count: left_path.map(|path| path.file_count),
                right_file_count: right_path.map(|path| path.file_count),
                file_count_delta,
            })
        })
        .collect()
}

fn build_recommendation_changes(left: &Report, right: &Report) -> Vec<RecommendationChange> {
    let left_by_id = left
        .recommendations
        .iter()
        .map(|recommendation| (recommendation.id.clone(), recommendation))
        .collect::<HashMap<_, _>>();
    let right_by_id = right
        .recommendations
        .iter()
        .map(|recommendation| (recommendation.id.clone(), recommendation))
        .collect::<HashMap<_, _>>();

    let ids = left_by_id
        .keys()
        .chain(right_by_id.keys())
        .cloned()
        .collect::<BTreeSet<_>>();

    let mut changes = Vec::new();
    for id in ids {
        let left_rec = left_by_id.get(&id).copied();
        let right_rec = right_by_id.get(&id).copied();

        match (left_rec, right_rec) {
            (None, Some(right_rec)) => changes.push(change_entry(
                &id,
                RecommendationChangeKind::Added,
                None,
                Some(right_rec),
            )),
            (Some(left_rec), None) => changes.push(change_entry(
                &id,
                RecommendationChangeKind::Removed,
                Some(left_rec),
                None,
            )),
            (Some(left_rec), Some(right_rec)) => {
                if (left_rec.confidence - right_rec.confidence).abs() > 0.001 {
                    changes.push(change_entry(
                        &id,
                        RecommendationChangeKind::ConfidenceChanged,
                        Some(left_rec),
                        Some(right_rec),
                    ));
                }
                if left_rec.target_mount != right_rec.target_mount {
                    changes.push(change_entry(
                        &id,
                        RecommendationChangeKind::TargetChanged,
                        Some(left_rec),
                        Some(right_rec),
                    ));
                }
                if left_rec.risk_level != right_rec.risk_level {
                    changes.push(change_entry(
                        &id,
                        RecommendationChangeKind::RiskChanged,
                        Some(left_rec),
                        Some(right_rec),
                    ));
                }
                if left_rec.rationale != right_rec.rationale {
                    changes.push(change_entry(
                        &id,
                        RecommendationChangeKind::RationaleChanged,
                        Some(left_rec),
                        Some(right_rec),
                    ));
                }
            }
            (None, None) => {}
        }
    }

    changes
}

fn change_entry(
    id: &str,
    change: RecommendationChangeKind,
    left: Option<&Recommendation>,
    right: Option<&Recommendation>,
) -> RecommendationChange {
    RecommendationChange {
        id: id.to_string(),
        change,
        left_confidence: left.map(|recommendation| recommendation.confidence),
        right_confidence: right.map(|recommendation| recommendation.confidence),
        left_target_mount: left.and_then(|recommendation| recommendation.target_mount.clone()),
        right_target_mount: right.and_then(|recommendation| recommendation.target_mount.clone()),
        left_risk_level: left.map(|recommendation| recommendation.risk_level.clone()),
        right_risk_level: right.map(|recommendation| recommendation.risk_level.clone()),
    }
}

fn build_summary(
    report: &Report,
    stored_report_path: &Path,
    source_path: Option<&Path>,
    imported: bool,
) -> ReportSummary {
    ReportSummary {
        scan_id: report.scan_id.clone(),
        generated_at: report.generated_at.clone(),
        report_version: report.report_version.clone(),
        roots: report.scan.roots.clone(),
        backend: report.scan.backend.clone(),
        warnings_count: report.warnings.len() as u64,
        recommendation_count: report.recommendations.len() as u64,
        stored_report_path: stored_report_path.to_string_lossy().to_string(),
        source_path: source_path.map(|path| path.to_string_lossy().to_string()),
        imported,
    }
}

fn ensure_store_layout(custom_dir: Option<&Path>) -> Result<()> {
    let root = resolve_report_store_dir(custom_dir);
    fs::create_dir_all(root.join(REPORTS_DIR_NAME)).with_context(|| {
        format!(
            "failed to create report store {}",
            root.join(REPORTS_DIR_NAME).display()
        )
    })?;
    Ok(())
}

fn reports_dir(custom_dir: Option<&Path>) -> PathBuf {
    resolve_report_store_dir(custom_dir).join(REPORTS_DIR_NAME)
}

fn index_file_path(custom_dir: Option<&Path>) -> PathBuf {
    resolve_report_store_dir(custom_dir).join(INDEX_FILE_NAME)
}

fn load_index(custom_dir: Option<&Path>) -> Result<ReportIndex> {
    let path = index_file_path(custom_dir);
    if !path.exists() {
        return Ok(ReportIndex::default());
    }

    let payload = fs::read_to_string(&path)
        .with_context(|| format!("failed to read report index {}", path.display()))?;
    let index = serde_json::from_str(&payload)
        .with_context(|| format!("failed to parse report index {}", path.display()))?;
    Ok(index)
}

fn save_index(custom_dir: Option<&Path>, index: &ReportIndex) -> Result<()> {
    ensure_store_layout(custom_dir)?;
    let path = index_file_path(custom_dir);
    let payload =
        serde_json::to_string_pretty(index).context("failed to serialize report index payload")?;
    fs::write(&path, payload)
        .with_context(|| format!("failed to write report index {}", path.display()))?;
    Ok(())
}

fn cleanup_orphaned_entries(index: &mut ReportIndex) -> bool {
    let before = index.reports.len();
    index
        .reports
        .retain(|entry| Path::new(&entry.stored_report_path).exists());
    before != index.reports.len()
}

fn sort_reports(reports: &mut [ReportSummary]) {
    reports.sort_by(|left, right| right.generated_at.cmp(&left.generated_at));
}

fn total_duplicate_waste(report: &Report) -> u64 {
    report
        .duplicates
        .iter()
        .map(|duplicate_group| duplicate_group.total_wasted_bytes)
        .sum()
}

fn signed_delta(left: Option<u64>, right: Option<u64>) -> i64 {
    let left = left.unwrap_or(0) as i128;
    let right = right.unwrap_or(0) as i128;
    let delta = right - left;
    delta.try_into().unwrap_or(if delta.is_negative() {
        i64::MIN
    } else {
        i64::MAX
    })
}

#[cfg(test)]
mod tests {
    use super::{build_report_diff, store_report};
    use crate::model::{
        EstimatedImpact, Recommendation, RecommendationEvidence, RecommendationEvidenceKind,
        Report, RiskLevel, ScanBackendKind, ScanMetadata, ScanMetrics,
    };
    use tempfile::tempdir;

    #[test]
    fn stores_report_and_indexes_summary() {
        let dir = tempdir().expect("temp dir");
        let report = sample_report("scan-1", 100, 1);

        let summary = store_report(&report, Some(dir.path()), None, false).expect("stored report");

        assert_eq!(summary.scan_id, "scan-1");
        assert!(dir.path().join("reports").join("scan-1.json").exists());
    }

    #[test]
    fn diff_reports_tracks_space_and_recommendation_changes() {
        let left = sample_report("scan-1", 100, 1);
        let right = sample_report("scan-2", 60, 2);

        let diff = build_report_diff(&left, &right);

        assert_eq!(diff.disk_diffs.len(), 1);
        assert_eq!(diff.path_diffs.len(), 1);
        assert_eq!(diff.recommendation_changes.len(), 1);
        assert!(diff.duplicate_wasted_bytes_delta > 0);
    }

    fn sample_report(
        scan_id: &str,
        free_space_bytes: u64,
        recommendation_confidence: u64,
    ) -> Report {
        Report {
            report_version: "1.3.0".to_string(),
            generated_at: format!("{scan_id}-generated"),
            scan_id: scan_id.to_string(),
            scan: ScanMetadata {
                roots: vec!["D:\\".to_string()],
                max_depth: None,
                excludes: Vec::new(),
                dedupe: false,
                dedupe_min_size: 0,
                dry_run: true,
                backend: ScanBackendKind::Native,
                progress: false,
                min_ratio: None,
                emit_progress_events: false,
                progress_interval_ms: 250,
            },
            scan_metrics: ScanMetrics::default(),
            scan_progress_summary: Default::default(),
            backend_parity: None,
            disks: vec![crate::model::DiskInfo {
                name: "Disk".to_string(),
                mount_point: "D:\\".to_string(),
                total_space_bytes: 200,
                free_space_bytes,
                disk_kind: crate::model::DiskKind::Ssd,
                file_system: Some("ntfs".to_string()),
                storage_type: Default::default(),
                locality_class: Default::default(),
                locality_confidence: 1.0,
                locality_rationale: "fixture".to_string(),
                is_os_drive: false,
                is_removable: false,
                vendor: None,
                model: None,
                interface: None,
                rotational: None,
                hybrid: None,
                performance_class: Default::default(),
                performance_confidence: 1.0,
                performance_rationale: "fixture".to_string(),
                eligible_for_local_target: true,
                ineligible_reasons: Vec::new(),
                metadata_notes: Vec::new(),
                role_hint: Default::default(),
                target_role_eligibility: Vec::new(),
            }],
            paths: vec![crate::model::PathStats {
                root_path: "D:\\Games".to_string(),
                disk_mount: Some("D:\\".to_string()),
                total_size_bytes: 100 + recommendation_confidence,
                file_count: 10 + recommendation_confidence,
                directory_count: 3,
                largest_files: crate::model::LargestFiles {
                    entries: Vec::new(),
                },
                largest_directories: Vec::new(),
                file_type_summary: crate::model::FileTypeSummary {
                    top_extensions: Vec::new(),
                    other_files: 0,
                    other_bytes: 0,
                    total_files: 0,
                    total_bytes: 0,
                },
                activity: crate::model::ActivitySignals {
                    recent_files: 0,
                    stale_files: 0,
                    unknown_modified_files: 0,
                },
            }],
            categories: Vec::new(),
            duplicates: vec![crate::model::DuplicateGroup {
                size_bytes: 10,
                hash: "hash-1".to_string(),
                files: Vec::new(),
                total_wasted_bytes: 5 + recommendation_confidence,
                intent: crate::model::DuplicateIntent {
                    label: crate::model::DuplicateIntentLabel::LikelyRedundant,
                    rationale: "fixture".to_string(),
                },
            }],
            recommendations: vec![Recommendation {
                id: "rec-1".to_string(),
                title: "Recommendation".to_string(),
                rationale: "Fixture recommendation".to_string(),
                confidence: recommendation_confidence as f32,
                target_mount: Some("D:\\".to_string()),
                policy_safe: true,
                policy_rules_applied: vec!["safe_target_policy".to_string()],
                policy_rules_blocked: Vec::new(),
                evidence: vec![RecommendationEvidence {
                    kind: RecommendationEvidenceKind::Disk,
                    label: "Target disk".to_string(),
                    detail: "Fixture evidence".to_string(),
                    path: None,
                    mount_point: Some("D:\\".to_string()),
                    duplicate_hash: None,
                }],
                next_steps: vec!["Review disk usage".to_string()],
                estimated_impact: EstimatedImpact {
                    space_saving_bytes: Some(10),
                    performance: None,
                    risk_notes: None,
                },
                risk_level: RiskLevel::Low,
            }],
            policy_decisions: Vec::new(),
            rule_traces: Vec::new(),
            warnings: Vec::new(),
        }
    }
}
