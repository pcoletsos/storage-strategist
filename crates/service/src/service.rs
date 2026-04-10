use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::thread;

use anyhow::{anyhow, Context, Result};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use storage_strategist_core::{
    build_diagnostics_bundle, build_scenario_plan, collect_doctor_info,
    compare_reports as compare_saved_reports, generate_recommendation_bundle,
    get_report as load_saved_report, import_report as import_saved_report,
    list_reports as list_saved_reports, render_markdown_summary, run_scan_with_callback,
    store_report, write_diagnostics_bundle, DiagnosticsBundle, DoctorInfo, RecommendationBundle,
    Report, ReportDiff, ReportImportResult, ReportSummary, ScanBackendKind, ScanOptions,
    ScanProgressEvent, ScenarioPlan,
};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRequest {
    #[serde(default)]
    pub scan_id: Option<String>,
    #[serde(default)]
    pub paths: Vec<PathBuf>,
    #[serde(default)]
    pub output: Option<PathBuf>,
    #[serde(default)]
    pub max_depth: Option<usize>,
    #[serde(default)]
    pub excludes: Vec<String>,
    #[serde(default)]
    pub dedupe: bool,
    #[serde(default = "default_dedupe_min_size")]
    pub dedupe_min_size: u64,
    #[serde(default)]
    pub backend: ScanBackendKind,
    #[serde(default)]
    pub progress: bool,
    #[serde(default)]
    pub min_ratio: Option<f32>,
    #[serde(default)]
    pub emit_progress_events: bool,
    #[serde(default = "default_progress_interval")]
    pub progress_interval_ms: u64,
    #[serde(default = "default_incremental_cache")]
    pub incremental_cache: bool,
    #[serde(default)]
    pub cache_dir: Option<PathBuf>,
    #[serde(default = "default_cache_ttl_seconds")]
    pub cache_ttl_seconds: u64,
    #[serde(default = "default_record_history")]
    pub record_history: bool,
    #[serde(default)]
    pub report_store_dir: Option<PathBuf>,
}

fn default_dedupe_min_size() -> u64 {
    1_048_576
}

fn default_progress_interval() -> u64 {
    250
}

fn default_incremental_cache() -> bool {
    true
}

fn default_cache_ttl_seconds() -> u64 {
    900
}

fn default_record_history() -> bool {
    true
}

impl Default for ScanRequest {
    fn default() -> Self {
        Self {
            scan_id: None,
            paths: Vec::new(),
            output: None,
            max_depth: None,
            excludes: Vec::new(),
            dedupe: false,
            dedupe_min_size: default_dedupe_min_size(),
            backend: ScanBackendKind::Native,
            progress: false,
            min_ratio: None,
            emit_progress_events: true,
            progress_interval_ms: default_progress_interval(),
            incremental_cache: default_incremental_cache(),
            cache_dir: None,
            cache_ttl_seconds: default_cache_ttl_seconds(),
            record_history: default_record_history(),
            report_store_dir: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScanSessionStatus {
    Running,
    Completed,
    Cancelled,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSessionSnapshot {
    pub scan_id: String,
    pub status: ScanSessionStatus,
    pub report_path: Option<PathBuf>,
    pub error: Option<String>,
    pub total_events: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CancelScanResponse {
    pub scan_id: String,
    pub status: ScanSessionStatus,
}

#[derive(Debug, Clone)]
struct ScanSession {
    status: ScanSessionStatus,
    report_path: Option<PathBuf>,
    report: Option<Report>,
    error: Option<String>,
    events: Vec<ScanProgressEvent>,
    cancel_flag: Arc<AtomicBool>,
}

static SESSIONS: Lazy<Mutex<HashMap<String, ScanSession>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

pub fn start_scan(request: ScanRequest) -> Result<String> {
    let scan_id = request
        .scan_id
        .clone()
        .unwrap_or_else(|| Uuid::new_v4().to_string());
    let cancel_flag = Arc::new(AtomicBool::new(false));

    {
        let mut sessions = lock_sessions()?;
        sessions.insert(
            scan_id.clone(),
            ScanSession {
                status: ScanSessionStatus::Running,
                report_path: request.output.clone(),
                report: None,
                error: None,
                events: Vec::new(),
                cancel_flag: Arc::clone(&cancel_flag),
            },
        );
    }

    let thread_scan_id = scan_id.clone();
    thread::spawn(move || {
        let output_path = request.output.clone();
        let report_store_dir = request.report_store_dir.clone();
        let options = ScanOptions {
            paths: request.paths,
            max_depth: request.max_depth,
            excludes: request.excludes,
            dedupe: request.dedupe,
            dedupe_min_size: request.dedupe_min_size,
            dry_run: true,
            backend: request.backend,
            progress: request.progress,
            min_ratio: request.min_ratio,
            scan_id: Some(thread_scan_id.clone()),
            emit_progress_events: request.emit_progress_events,
            progress_interval_ms: request.progress_interval_ms,
            incremental_cache: request.incremental_cache,
            cache_dir: request.cache_dir,
            cache_ttl_seconds: request.cache_ttl_seconds,
            record_history: request.record_history,
            report_store_dir: report_store_dir.clone(),
            cancel_flag: Some(Arc::clone(&cancel_flag)),
            ..ScanOptions::default()
        };

        let run_result = run_scan_with_callback(&options, |event| {
            if let Ok(mut sessions) = lock_sessions() {
                if let Some(session) = sessions.get_mut(&thread_scan_id) {
                    session.events.push(event);
                }
            }
        });

        match run_result {
            Ok(report) => {
                if let Some(path) = &output_path {
                    let write_result = serde_json::to_string_pretty(&report)
                        .context("failed to serialize report payload")
                        .and_then(|payload| {
                            fs::write(path, payload).with_context(|| {
                                format!("failed to write report to {}", path.display())
                            })
                        });

                    if let Err(err) = write_result {
                        if let Ok(mut sessions) = lock_sessions() {
                            if let Some(session) = sessions.get_mut(&thread_scan_id) {
                                session.status = ScanSessionStatus::Failed;
                                session.error = Some(err.to_string());
                            }
                        }
                        return;
                    }
                }

                let store_result = store_report(
                    &report,
                    report_store_dir.as_deref(),
                    output_path.as_deref(),
                    false,
                );
                let stored_summary = match store_result {
                    Ok(summary) => summary,
                    Err(err) => {
                        if let Ok(mut sessions) = lock_sessions() {
                            if let Some(session) = sessions.get_mut(&thread_scan_id) {
                                session.status = ScanSessionStatus::Failed;
                                session.error = Some(err.to_string());
                            }
                        }
                        return;
                    }
                };

                if let Ok(mut sessions) = lock_sessions() {
                    if let Some(session) = sessions.get_mut(&thread_scan_id) {
                        session.report = Some(report);
                        session.report_path =
                            Some(PathBuf::from(&stored_summary.stored_report_path));
                        session.status = if cancel_flag.load(Ordering::Relaxed) {
                            ScanSessionStatus::Cancelled
                        } else {
                            ScanSessionStatus::Completed
                        };
                        session.error = None;
                    }
                }
            }
            Err(err) => {
                if let Ok(mut sessions) = lock_sessions() {
                    if let Some(session) = sessions.get_mut(&thread_scan_id) {
                        session.status = ScanSessionStatus::Failed;
                        session.error = Some(err.to_string());
                    }
                }
            }
        }
    });

    Ok(scan_id)
}

pub fn poll_scan_events(scan_id: &str, from_seq: u64) -> Result<Vec<ScanProgressEvent>> {
    let sessions = lock_sessions()?;
    let session = sessions
        .get(scan_id)
        .ok_or_else(|| anyhow!("scan session not found: {scan_id}"))?;

    Ok(session
        .events
        .iter()
        .filter(|event| event.seq > from_seq)
        .cloned()
        .collect())
}

pub fn cancel_scan(scan_id: &str) -> Result<CancelScanResponse> {
    let mut sessions = lock_sessions()?;
    let session = sessions
        .get_mut(scan_id)
        .ok_or_else(|| anyhow!("scan session not found: {scan_id}"))?;

    session.cancel_flag.store(true, Ordering::Relaxed);
    if session.status == ScanSessionStatus::Running {
        session.status = ScanSessionStatus::Cancelled;
    }

    Ok(CancelScanResponse {
        scan_id: scan_id.to_string(),
        status: session.status.clone(),
    })
}

pub fn load_report(path: impl AsRef<Path>) -> Result<Report> {
    let path = path.as_ref();
    let data = fs::read_to_string(path)
        .with_context(|| format!("failed to read report {}", path.display()))?;
    let report: Report = serde_json::from_str(&data)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    Ok(report)
}

pub fn list_reports(report_store_dir: Option<&Path>) -> Result<Vec<ReportSummary>> {
    list_saved_reports(report_store_dir)
}

pub fn get_report(scan_id: &str, report_store_dir: Option<&Path>) -> Result<Report> {
    load_saved_report(scan_id, report_store_dir)
}

pub fn import_report(
    path: impl AsRef<Path>,
    report_store_dir: Option<&Path>,
) -> Result<ReportImportResult> {
    import_saved_report(path, report_store_dir)
}

pub fn compare_reports(
    left_scan_id: &str,
    right_scan_id: &str,
    report_store_dir: Option<&Path>,
) -> Result<ReportDiff> {
    compare_saved_reports(left_scan_id, right_scan_id, report_store_dir)
}

pub fn generate_recommendations_from_report(report: &Report) -> RecommendationBundle {
    generate_recommendation_bundle(report)
}

pub fn plan_scenarios_from_report(report: &Report) -> ScenarioPlan {
    build_scenario_plan(report)
}

pub fn export_diagnostics_bundle(
    report: &Report,
    output: impl AsRef<Path>,
    source_report_path: Option<PathBuf>,
) -> Result<DiagnosticsBundle> {
    let bundle = build_diagnostics_bundle(report, source_report_path.as_deref());
    write_diagnostics_bundle(&bundle, output)?;
    Ok(bundle)
}

pub fn export_markdown_summary(report: &Report, output: impl AsRef<Path>) -> Result<()> {
    let markdown = render_markdown_summary(report, &report.recommendations);
    fs::write(output.as_ref(), markdown).with_context(|| {
        format!(
            "failed to write markdown summary to {}",
            output.as_ref().display()
        )
    })?;
    Ok(())
}

pub fn export_report_diff(diff: &ReportDiff, output: impl AsRef<Path>) -> Result<()> {
    let payload =
        serde_json::to_string_pretty(diff).context("failed to serialize report diff payload")?;
    fs::write(output.as_ref(), payload).with_context(|| {
        format!(
            "failed to write report diff to {}",
            output.as_ref().display()
        )
    })?;
    Ok(())
}

pub fn doctor() -> DoctorInfo {
    collect_doctor_info()
}

pub fn get_scan_session(scan_id: &str) -> Result<ScanSessionSnapshot> {
    let sessions = lock_sessions()?;
    let session = sessions
        .get(scan_id)
        .ok_or_else(|| anyhow!("scan session not found: {scan_id}"))?;

    Ok(ScanSessionSnapshot {
        scan_id: scan_id.to_string(),
        status: session.status.clone(),
        report_path: session.report_path.clone(),
        error: session.error.clone(),
        total_events: session.events.len() as u64,
    })
}

fn lock_sessions() -> Result<std::sync::MutexGuard<'static, HashMap<String, ScanSession>>> {
    SESSIONS
        .lock()
        .map_err(|_| anyhow!("scan session registry lock poisoned"))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::{Duration, Instant};

    use super::{
        cancel_scan, doctor, get_report, get_scan_session, import_report, poll_scan_events,
        start_scan, ScanRequest, ScanSessionStatus,
    };
    use storage_strategist_core::model::{ActivitySignals, LargestFiles};
    use storage_strategist_core::{
        DiskInfo, DiskKind, DiskRole, DiskRoleHint, DiskStorageType, DuplicateGroup,
        DuplicateIntent, DuplicateIntentLabel, EstimatedImpact, LocalityClass, PathStats,
        PerformanceClass, Recommendation, RecommendationEvidence, RecommendationEvidenceKind,
        Report, RiskLevel, ScanBackendKind, ScanMetadata, ScanMetrics,
    };
    use tempfile::tempdir;

    #[test]
    fn start_scan_creates_session_and_events() {
        let request = ScanRequest {
            paths: vec![std::env::current_dir().expect("cwd")],
            max_depth: Some(1),
            emit_progress_events: true,
            record_history: false,
            ..ScanRequest::default()
        };
        let scan_id = start_scan(request).expect("scan succeeds");

        let started = Instant::now();
        let snapshot = loop {
            let snapshot = get_scan_session(&scan_id).expect("session exists");
            if matches!(
                snapshot.status,
                ScanSessionStatus::Completed
                    | ScanSessionStatus::Cancelled
                    | ScanSessionStatus::Failed
            ) {
                break snapshot;
            }
            assert!(started.elapsed() < Duration::from_secs(30));
            std::thread::sleep(Duration::from_millis(25));
        };
        assert!(snapshot.total_events >= 1);

        let events = poll_scan_events(&scan_id, 0).expect("events");
        assert!(events
            .iter()
            .any(|event| event.phase == storage_strategist_core::ScanPhase::Done));

        let cancel = cancel_scan(&scan_id).expect("cancel response");
        assert_eq!(cancel.scan_id, scan_id);
    }

    #[test]
    fn doctor_returns_runtime_snapshot() {
        let info = doctor();
        assert!(info.read_only_mode);
    }

    #[test]
    fn imported_reports_round_trip_through_service_without_reanalysis() {
        let dir = tempdir().expect("temp dir");
        let source = dir.path().join("legacy-report.json");
        let report = sample_report("../legacy-report");
        fs::write(
            &source,
            serde_json::to_string_pretty(&report).expect("serialize report"),
        )
        .expect("write source report");

        let result = import_report(&source, Some(dir.path())).expect("import report");
        let loaded = get_report(&report.scan_id, Some(dir.path())).expect("load imported report");

        assert_eq!(loaded.recommendations, report.recommendations);
        assert_eq!(loaded.policy_decisions, report.policy_decisions);
        assert_eq!(loaded.rule_traces, report.rule_traces);
        assert_eq!(
            loaded.scan_metrics.contradiction_count,
            report.scan_metrics.contradiction_count
        );
        assert!(result.summary.imported);
    }

    fn sample_report(scan_id: &str) -> Report {
        Report {
            report_version: "1.3.0".to_string(),
            generated_at: "2026-04-10T00:00:00Z".to_string(),
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
            scan_metrics: ScanMetrics {
                contradiction_count: 2,
                ..ScanMetrics::default()
            },
            scan_progress_summary: Default::default(),
            backend_parity: None,
            disks: vec![DiskInfo {
                name: "Disk".to_string(),
                mount_point: "D:\\".to_string(),
                total_space_bytes: 1_000,
                free_space_bytes: 400,
                disk_kind: DiskKind::Ssd,
                file_system: Some("ntfs".to_string()),
                storage_type: DiskStorageType::Ssd,
                locality_class: LocalityClass::LocalPhysical,
                locality_confidence: 1.0,
                locality_rationale: "fixture".to_string(),
                is_os_drive: false,
                is_removable: false,
                vendor: None,
                model: None,
                interface: None,
                rotational: None,
                hybrid: None,
                performance_class: PerformanceClass::Balanced,
                performance_confidence: 1.0,
                performance_rationale: "fixture".to_string(),
                eligible_for_local_target: true,
                ineligible_reasons: Vec::new(),
                metadata_notes: Vec::new(),
                role_hint: DiskRoleHint {
                    role: DiskRole::ActiveWorkload,
                    confidence: 0.8,
                    evidence: vec!["fixture".to_string()],
                },
                target_role_eligibility: Vec::new(),
            }],
            paths: vec![PathStats {
                root_path: "D:\\Demo".to_string(),
                disk_mount: Some("D:\\".to_string()),
                total_size_bytes: 600,
                file_count: 12,
                directory_count: 4,
                largest_files: LargestFiles {
                    entries: Vec::new(),
                },
                largest_directories: Vec::new(),
                file_type_summary: storage_strategist_core::FileTypeSummary {
                    top_extensions: Vec::new(),
                    other_files: 0,
                    other_bytes: 0,
                    total_files: 0,
                    total_bytes: 0,
                },
                activity: ActivitySignals {
                    recent_files: 0,
                    stale_files: 0,
                    unknown_modified_files: 0,
                },
            }],
            categories: Vec::new(),
            duplicates: vec![DuplicateGroup {
                size_bytes: 10,
                hash: "hash-1".to_string(),
                files: Vec::new(),
                total_wasted_bytes: 5,
                intent: DuplicateIntent {
                    label: DuplicateIntentLabel::LikelyRedundant,
                    rationale: "fixture".to_string(),
                },
            }],
            recommendations: vec![Recommendation {
                id: "stored-rec".to_string(),
                title: "Stored recommendation".to_string(),
                rationale: "Persisted rationale".to_string(),
                confidence: 0.42,
                target_mount: Some("D:\\".to_string()),
                policy_safe: false,
                policy_rules_applied: vec!["stored_policy".to_string()],
                policy_rules_blocked: vec!["blocked_policy".to_string()],
                evidence: vec![RecommendationEvidence {
                    kind: RecommendationEvidenceKind::Warning,
                    label: "Stored evidence".to_string(),
                    detail: "Imported reports should round-trip unchanged.".to_string(),
                    path: Some("D:\\Demo".to_string()),
                    mount_point: Some("D:\\".to_string()),
                    duplicate_hash: None,
                }],
                next_steps: vec!["Review stored evidence".to_string()],
                estimated_impact: EstimatedImpact {
                    space_saving_bytes: Some(10),
                    performance: Some("Stored performance note".to_string()),
                    risk_notes: Some("Stored risk note".to_string()),
                },
                risk_level: RiskLevel::High,
            }],
            policy_decisions: vec![storage_strategist_core::PolicyDecision {
                policy_id: "stored_policy".to_string(),
                recommendation_id: "stored-rec".to_string(),
                action: storage_strategist_core::PolicyAction::Blocked,
                rationale: "Stored policy rationale".to_string(),
            }],
            rule_traces: vec![storage_strategist_core::RuleTrace {
                rule_id: "stored_rule".to_string(),
                status: storage_strategist_core::RuleTraceStatus::Rejected,
                detail: "Stored trace detail".to_string(),
                recommendation_id: Some("stored-rec".to_string()),
                confidence: Some(0.13),
            }],
            warnings: vec!["stored warning".to_string()],
        }
    }
}
