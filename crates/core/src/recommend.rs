use std::collections::{HashMap, HashSet};
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::analyzers::{run_analyzers, AnalyzerContext};
use crate::model::{
    Category, DiskInfo, DiskStorageType, DuplicateIntentLabel, EstimatedImpact, LocalityClass,
    PerformanceClass, Recommendation, RecommendationEvidence, RecommendationEvidenceKind, Report,
    RiskLevel, RuleTrace, RuleTraceStatus,
};
use crate::policy::enforce_recommendation_policies;

const OS_HEADROOM_MIN_RATIO: f64 = 0.15;
const MIN_SOURCE_SCAN_COVERAGE_RATIO: f64 = 0.35;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RecommendationBundle {
    pub recommendations: Vec<Recommendation>,
    pub rule_traces: Vec<RuleTrace>,
    pub policy_decisions: Vec<crate::model::PolicyDecision>,
    pub contradiction_count: u64,
}

pub fn generate_recommendations(report: &Report) -> Vec<Recommendation> {
    generate_recommendation_bundle(report).recommendations
}

pub fn generate_recommendation_bundle(report: &Report) -> RecommendationBundle {
    generate_recommendation_bundle_with_context(report, &AnalyzerContext::default())
}

pub fn generate_recommendation_bundle_with_context(
    report: &Report,
    analyzer_context: &AnalyzerContext,
) -> RecommendationBundle {
    let disk_scores = category_scores_by_disk(report);
    let mut candidates = Vec::new();
    let mut traces = Vec::new();

    emit_optional(
        "active_workload_placement",
        active_workload_placement_rule(report, &disk_scores),
        &mut candidates,
        &mut traces,
    );
    emit_optional(
        "consolidation_opportunity",
        consolidation_rule(report),
        &mut candidates,
        &mut traces,
    );
    emit_many(
        "risky_disk",
        risky_disk_rule(report, &disk_scores),
        &mut candidates,
        &mut traces,
    );
    emit_optional(
        "backup_gap",
        backup_gap_rule(report, &disk_scores),
        &mut candidates,
        &mut traces,
    );
    emit_optional(
        "duplicate_cleanup",
        duplicate_cleanup_rule(report),
        &mut candidates,
        &mut traces,
    );
    emit_optional(
        "os_headroom",
        os_headroom_rule(report, &disk_scores),
        &mut candidates,
        &mut traces,
    );
    emit_optional(
        "cloud_exclusion_notice",
        cloud_exclusion_notice_rule(report),
        &mut candidates,
        &mut traces,
    );
    for result in run_analyzers(report, analyzer_context) {
        candidates.extend(result.recommendations);
        traces.extend(result.traces);
    }

    let policy_outcome = enforce_recommendation_policies(report, candidates);
    traces.extend(policy_outcome.rejection_traces);
    let mut recommendations = policy_outcome.recommendations;
    enrich_recommendations(report, &mut recommendations);

    RecommendationBundle {
        recommendations,
        rule_traces: traces,
        policy_decisions: policy_outcome.decisions,
        contradiction_count: policy_outcome.contradiction_count,
    }
}

fn enrich_recommendations(report: &Report, recommendations: &mut [Recommendation]) {
    for recommendation in recommendations {
        if recommendation.evidence.is_empty() {
            recommendation.evidence = gather_recommendation_evidence(report, recommendation);
        }
        if recommendation.next_steps.is_empty() {
            recommendation.next_steps = recommendation_next_steps(recommendation);
        }
    }
}

fn gather_recommendation_evidence(
    report: &Report,
    recommendation: &Recommendation,
) -> Vec<RecommendationEvidence> {
    let mut evidence = Vec::new();

    if let Some(target_mount) = &recommendation.target_mount {
        if let Some(disk) = report
            .disks
            .iter()
            .find(|disk| &disk.mount_point == target_mount)
        {
            evidence.push(RecommendationEvidence {
                kind: RecommendationEvidenceKind::Disk,
                label: "Target disk".to_string(),
                detail: format!(
                    "{} | role {:?} | locality {:?} | perf {:?}",
                    disk.name, disk.role_hint.role, disk.locality_class, disk.performance_class
                ),
                path: None,
                mount_point: Some(disk.mount_point.clone()),
                duplicate_hash: None,
            });
        }
    }

    if recommendation.id.contains("duplicate") {
        if let Some(group) = report
            .duplicates
            .iter()
            .filter(|group| group.intent.label == DuplicateIntentLabel::LikelyRedundant)
            .max_by_key(|group| group.total_wasted_bytes)
        {
            evidence.push(RecommendationEvidence {
                kind: RecommendationEvidenceKind::DuplicateGroup,
                label: "Largest redundant duplicate group".to_string(),
                detail: format!(
                    "{} file(s), wasted {} bytes",
                    group.files.len(),
                    group.total_wasted_bytes
                ),
                path: group.files.first().map(|file| file.path.clone()),
                mount_point: group.files.first().and_then(|file| file.disk_mount.clone()),
                duplicate_hash: Some(group.hash.clone()),
            });
        }
    }

    if recommendation.id.starts_with("cleanup-") {
        if let Some(directory) = report
            .paths
            .iter()
            .flat_map(|path| path.largest_directories.iter())
            .max_by_key(|directory| directory.size_bytes)
        {
            evidence.push(RecommendationEvidence {
                kind: RecommendationEvidenceKind::Directory,
                label: "Largest matching directory".to_string(),
                detail: format!("{} bytes", directory.size_bytes),
                path: Some(directory.path.clone()),
                mount_point: None,
                duplicate_hash: None,
            });
        }
    }

    if recommendation.id.starts_with("disk-growth-")
        || recommendation.id.starts_with("path-growth-")
    {
        evidence.push(RecommendationEvidence {
            kind: RecommendationEvidenceKind::HistoryDelta,
            label: "Historical change".to_string(),
            detail: recommendation.rationale.clone(),
            path: None,
            mount_point: recommendation.target_mount.clone(),
            duplicate_hash: None,
        });
    }

    if recommendation.id.contains("cloud") {
        for disk in report
            .disks
            .iter()
            .filter(|disk| !disk.eligible_for_local_target)
            .take(2)
        {
            evidence.push(RecommendationEvidence {
                kind: RecommendationEvidenceKind::Disk,
                label: "Excluded destination".to_string(),
                detail: disk.ineligible_reasons.join(" | "),
                path: None,
                mount_point: Some(disk.mount_point.clone()),
                duplicate_hash: None,
            });
        }
    }

    if let Some(path_stats) = report
        .paths
        .iter()
        .find(|path| recommendation.target_mount.as_ref() == path.disk_mount.as_ref())
    {
        if let Some(directory) = path_stats.largest_directories.first() {
            evidence.push(RecommendationEvidence {
                kind: RecommendationEvidenceKind::Directory,
                label: "Largest scanned directory on related root".to_string(),
                detail: format!("{} bytes", directory.size_bytes),
                path: Some(directory.path.clone()),
                mount_point: path_stats.disk_mount.clone(),
                duplicate_hash: None,
            });
        }
    }

    for warning in report.warnings.iter().take(1) {
        evidence.push(RecommendationEvidence {
            kind: RecommendationEvidenceKind::Warning,
            label: "Scan warning".to_string(),
            detail: warning.clone(),
            path: None,
            mount_point: None,
            duplicate_hash: None,
        });
    }

    if evidence.is_empty() {
        evidence.push(RecommendationEvidence {
            kind: RecommendationEvidenceKind::Other,
            label: "Rule rationale".to_string(),
            detail: recommendation.rationale.clone(),
            path: None,
            mount_point: recommendation.target_mount.clone(),
            duplicate_hash: None,
        });
    }

    evidence
}

fn recommendation_next_steps(recommendation: &Recommendation) -> Vec<String> {
    if recommendation.id == "active-workload-placement" {
        return vec![
            "Confirm the target disk has enough free space for active workloads.".to_string(),
            "Review the suggested move manually before changing any library paths.".to_string(),
        ];
    }

    if recommendation.id == "backup-gap" {
        return vec![
            "Verify there is a second local or offline copy of the library.".to_string(),
            "Prefer backup/archive targets over active-use disks when adding redundancy."
                .to_string(),
        ];
    }

    if recommendation.id.contains("duplicate") {
        return vec![
            "Inspect the duplicate group and keep the authoritative copy first.".to_string(),
            "Use the diagnostics bundle if you need to review the full context before cleanup."
                .to_string(),
        ];
    }

    if recommendation.id.starts_with("cleanup-") {
        return vec![
            "Inspect the evidence paths and estimate the reclaimable space before cleanup."
                .to_string(),
            "Use tool-native cleanup commands where possible instead of manual deletion."
                .to_string(),
        ];
    }

    vec![
        "Review the linked evidence before taking action.".to_string(),
        "Export diagnostics if you want to compare or share the recommendation context."
            .to_string(),
    ]
}

fn emit_optional(
    rule_id: &str,
    recommendation: Option<Recommendation>,
    out: &mut Vec<Recommendation>,
    traces: &mut Vec<RuleTrace>,
) {
    if let Some(rec) = recommendation {
        traces.push(RuleTrace {
            rule_id: rule_id.to_string(),
            status: RuleTraceStatus::Emitted,
            detail: "Rule produced one recommendation.".to_string(),
            recommendation_id: Some(rec.id.clone()),
            confidence: Some(rec.confidence),
        });
        out.push(rec);
    } else {
        traces.push(RuleTrace {
            rule_id: rule_id.to_string(),
            status: RuleTraceStatus::Skipped,
            detail: "Rule conditions were not met.".to_string(),
            recommendation_id: None,
            confidence: None,
        });
    }
}

fn emit_many(
    rule_id: &str,
    recommendations: Vec<Recommendation>,
    out: &mut Vec<Recommendation>,
    traces: &mut Vec<RuleTrace>,
) {
    if recommendations.is_empty() {
        traces.push(RuleTrace {
            rule_id: rule_id.to_string(),
            status: RuleTraceStatus::Skipped,
            detail: "Rule conditions were not met.".to_string(),
            recommendation_id: None,
            confidence: None,
        });
        return;
    }

    let ids = recommendations
        .iter()
        .map(|r| r.id.clone())
        .collect::<Vec<_>>()
        .join(", ");
    let avg_confidence =
        recommendations.iter().map(|r| r.confidence).sum::<f32>() / recommendations.len() as f32;
    traces.push(RuleTrace {
        rule_id: rule_id.to_string(),
        status: RuleTraceStatus::Emitted,
        detail: format!(
            "Rule produced {} recommendation(s): {}",
            recommendations.len(),
            ids
        ),
        recommendation_id: None,
        confidence: Some(avg_confidence),
    });
    out.extend(recommendations);
}

fn active_workload_placement_rule(
    report: &Report,
    disk_scores: &HashMap<String, HashMap<Category, f32>>,
) -> Option<Recommendation> {
    let target = fastest_eligible_disk(report)?;
    let target_rank = performance_rank(target);

    let mut candidate: Option<(&DiskInfo, f32)> = None;
    for source in eligible_non_os_local_targets(report) {
        if source.mount_point == target.mount_point {
            continue;
        }
        let source_rank = performance_rank(source);
        if source_rank >= target_rank {
            continue;
        }

        let scores = disk_scores.get(&source.mount_point);
        let active_score = score_sum(scores, &[Category::Work, Category::Games]);
        let cold_score = score_sum(scores, &[Category::Media, Category::Archive]);
        if active_score <= cold_score + 0.25 {
            continue;
        }

        let score = active_score - cold_score + (target_rank - source_rank);
        match candidate {
            Some((_, best_score)) if best_score >= score => {}
            _ => candidate = Some((source, score)),
        }
    }

    let (source, score) = candidate?;
    Some(Recommendation {
        id: "active-workload-placement".to_string(),
        title: "Review active workload placement on faster non-OS local storage".to_string(),
        rationale: format!(
            "Disk {} appears to host active work/game content while {} is a faster eligible non-OS local target. Consider reviewing placement to keep active workloads on faster local physical storage.",
            source.mount_point, target.mount_point
        ),
        confidence: (0.65 + (score * 0.1)).min(0.92),
        target_mount: Some(target.mount_point.clone()),
        policy_safe: true,
        policy_rules_applied: vec!["safe_target_policy".to_string()],
        policy_rules_blocked: Vec::new(),
        evidence: Vec::new(),
        next_steps: Vec::new(),
        estimated_impact: EstimatedImpact {
            space_saving_bytes: None,
            performance: Some(
                "Potential responsiveness gain by aligning active workloads with faster storage."
                    .to_string(),
            ),
            risk_notes: Some(
                "Manual review required; recommendation excludes cloud/network/virtual destinations."
                    .to_string(),
            ),
        },
        risk_level: RiskLevel::Low,
    })
}

fn consolidation_rule(report: &Report) -> Option<Recommendation> {
    let eligible_targets = eligible_non_os_local_targets(report);
    if eligible_targets.len() < 2 {
        return None;
    }
    let disk_scores = category_scores_by_disk(report);
    let observed_bytes = observed_bytes_by_disk(report);

    let mut best_candidate: Option<(&DiskInfo, &DiskInfo, u64)> = None;
    for source in &eligible_targets {
        let source_used = used_space(source);
        if source_used < 50 * 1024 * 1024 * 1024 {
            continue;
        }
        if !has_sufficient_scan_coverage(source, observed_bytes.get(&source.mount_point).copied()) {
            continue;
        }

        let source_scores = disk_scores.get(&source.mount_point);
        let source_active = score_sum(source_scores, &[Category::Work, Category::Games]);
        let source_cold = score_sum(
            source_scores,
            &[Category::Media, Category::Archive, Category::Backup],
        );

        for target in &eligible_targets {
            if source.mount_point == target.mount_point {
                continue;
            }
            if !has_sufficient_scan_coverage(
                target,
                observed_bytes.get(&target.mount_point).copied(),
            ) {
                continue;
            }

            let target_scores = disk_scores.get(&target.mount_point);
            let target_active = score_sum(target_scores, &[Category::Work, Category::Games]);
            let target_cold = score_sum(
                target_scores,
                &[Category::Media, Category::Archive, Category::Backup],
            );
            let source_rank = performance_rank(source);
            let target_rank = performance_rank(target);

            // Prevent unsafe role inversion: do not push active/game-heavy data onto
            // a colder media/archive/backup profile, especially when target is slower.
            if source_active > source_cold + 0.25
                && target_cold > target_active + 0.25
                && target_rank <= source_rank
            {
                continue;
            }

            if target.free_space_bytes > (source_used as f64 * 1.25_f64) as u64 {
                let score = source_used;
                match best_candidate {
                    Some((_, _, best_score)) if best_score >= score => {}
                    _ => best_candidate = Some((source, target, score)),
                }
            }
        }
    }

    let (source, target, source_used) = best_candidate?;
    Some(Recommendation {
        id: "consolidation-opportunity".to_string(),
        title: "Consolidation opportunity detected on local physical disks".to_string(),
        rationale: format!(
            "Disk {} has about {} in use, and eligible local disk {} has enough free space to likely absorb it with safety margin. Consider a staged review and verification plan.",
            source.mount_point,
            human_bytes(source_used),
            target.mount_point
        ),
        confidence: 0.74,
        target_mount: Some(target.mount_point.clone()),
        policy_safe: true,
        policy_rules_applied: vec!["safe_target_policy".to_string()],
        policy_rules_blocked: Vec::new(),
        evidence: Vec::new(),
        next_steps: Vec::new(),
        estimated_impact: EstimatedImpact {
            space_saving_bytes: Some(source_used),
            performance: Some("Potentially fewer active local disks to manage.".to_string()),
            risk_notes: Some(
                "Verify backups and data criticality before any manual migration.".to_string(),
            ),
        },
        risk_level: RiskLevel::Medium,
    })
}

fn risky_disk_rule(
    report: &Report,
    disk_scores: &HashMap<String, HashMap<Category, f32>>,
) -> Vec<Recommendation> {
    let mut output = Vec::new();

    for disk in report.disks.iter().filter(|disk| {
        matches!(
            disk.locality_class,
            LocalityClass::LocalPhysical | LocalityClass::Unknown
        )
    }) {
        if disk.total_space_bytes == 0 {
            continue;
        }
        let free_ratio = disk.free_space_bytes as f64 / disk.total_space_bytes as f64;
        if free_ratio > 0.12 {
            continue;
        }

        let scores = disk_scores.get(&disk.mount_point);
        let important = score_sum(scores, &[Category::Work, Category::Games, Category::Media]);
        let has_backup = score_sum(scores, &[Category::Backup]) >= 0.6;
        if important < 0.8 || has_backup {
            continue;
        }

        output.push(Recommendation {
            id: format!("risky-disk-{}", sanitize_id(&disk.mount_point)),
            title: format!("Review low-free-space risk on {}", disk.mount_point),
            rationale: format!(
                "Disk {} is low on free space ({:.1}% free) and appears to contain important active categories without clear backup indicators. Verify backup coverage and growth headroom.",
                disk.mount_point,
                free_ratio * 100.0
            ),
            confidence: 0.82,
            target_mount: None,
            policy_safe: true,
            policy_rules_applied: vec!["safe_target_policy".to_string()],
            policy_rules_blocked: Vec::new(),
            evidence: Vec::new(),
            next_steps: Vec::new(),
            estimated_impact: EstimatedImpact {
                space_saving_bytes: None,
                performance: Some(
                    "Low free-space conditions can degrade reliability and performance."
                        .to_string(),
                ),
                risk_notes: Some(
                    "Prioritize backup verification before any cleanup decisions.".to_string(),
                ),
            },
            risk_level: RiskLevel::High,
        });
    }

    output
}

fn backup_gap_rule(
    report: &Report,
    disk_scores: &HashMap<String, HashMap<Category, f32>>,
) -> Option<Recommendation> {
    let eligible_mounts = eligible_non_os_local_targets(report)
        .into_iter()
        .map(|disk| disk.mount_point.clone())
        .collect::<HashSet<_>>();
    let os_mount = report
        .disks
        .iter()
        .find(|disk| disk.is_os_drive)
        .map(|disk| disk.mount_point.clone());

    let mut has_work = false;
    let mut has_backup = false;

    for (mount, score) in disk_scores {
        if !eligible_mounts.contains(mount) && os_mount.as_deref() != Some(mount) {
            continue;
        }
        if *score.get(&Category::Work).unwrap_or(&0.0) >= 0.5 {
            has_work = true;
        }
        if *score.get(&Category::Backup).unwrap_or(&0.0) >= 0.5 {
            has_backup = true;
        }
    }

    if has_work && !has_backup {
        return Some(Recommendation {
            id: "backup-gap".to_string(),
            title: "Workload appears present without backup indicators".to_string(),
            rationale:
                "Work/project signals were detected on local storage, but no disk strongly matches backup patterns. Consider verifying backup strategy and restore path."
                    .to_string(),
            confidence: 0.8,
            target_mount: None,
            policy_safe: true,
            policy_rules_applied: vec!["safe_target_policy".to_string()],
            policy_rules_blocked: Vec::new(),
            evidence: Vec::new(),
            next_steps: Vec::new(),
            estimated_impact: EstimatedImpact {
                space_saving_bytes: None,
                performance: None,
                risk_notes: Some(
                    "Data-loss risk can be high when active work data lacks verified backups."
                        .to_string(),
                ),
            },
            risk_level: RiskLevel::High,
        });
    }

    None
}

fn duplicate_cleanup_rule(report: &Report) -> Option<Recommendation> {
    let redundant_groups = report
        .duplicates
        .iter()
        .filter(|group| {
            group.intent.label == DuplicateIntentLabel::LikelyRedundant
                && group.total_wasted_bytes >= 64 * 1024 * 1024
        })
        .collect::<Vec<_>>();

    if redundant_groups.is_empty() {
        return None;
    }

    let total_wasted = redundant_groups
        .iter()
        .map(|group| group.total_wasted_bytes)
        .sum::<u64>();

    if total_wasted < 256 * 1024 * 1024 {
        return None;
    }

    Some(Recommendation {
        id: "duplicate-cleanup-candidate".to_string(),
        title: "Review duplicate cleanup candidates".to_string(),
        rationale: format!(
            "{} redundant duplicate group(s) account for about {} of potential reclaimable space. Review each set before manual cleanup.",
            redundant_groups.len(),
            human_bytes(total_wasted)
        ),
        confidence: 0.7,
        target_mount: None,
        policy_safe: true,
        policy_rules_applied: vec!["safe_target_policy".to_string()],
        policy_rules_blocked: Vec::new(),
        evidence: Vec::new(),
        next_steps: Vec::new(),
        estimated_impact: EstimatedImpact {
            space_saving_bytes: Some(total_wasted),
            performance: Some("Potential capacity relief and reduced indexing load.".to_string()),
            risk_notes: Some("Validate ownership and backup expectations before removal.".to_string()),
        },
        risk_level: RiskLevel::Medium,
    })
}

fn os_headroom_rule(
    report: &Report,
    disk_scores: &HashMap<String, HashMap<Category, f32>>,
) -> Option<Recommendation> {
    let os_disk = report.disks.iter().find(|disk| disk.is_os_drive)?;
    if os_disk.total_space_bytes == 0 {
        return None;
    }
    let free_ratio = os_disk.free_space_bytes as f64 / os_disk.total_space_bytes as f64;
    if free_ratio >= OS_HEADROOM_MIN_RATIO {
        return None;
    }

    let scores = disk_scores.get(&os_disk.mount_point);
    let cold_score = score_sum(scores, &[Category::Media, Category::Archive]);

    Some(Recommendation {
        id: "os-headroom".to_string(),
        title: "Protect OS drive free-space headroom".to_string(),
        rationale: format!(
            "OS drive {} is at {:.1}% free, below the {:.0}% safety threshold. Review cold data placement and preserve headroom for updates, paging, and recovery workflows.",
            os_disk.mount_point,
            free_ratio * 100.0,
            OS_HEADROOM_MIN_RATIO * 100.0
        ),
        confidence: if cold_score > 0.6 { 0.86 } else { 0.72 },
        target_mount: None,
        policy_safe: true,
        policy_rules_applied: vec!["safe_target_policy".to_string()],
        policy_rules_blocked: Vec::new(),
        evidence: Vec::new(),
        next_steps: Vec::new(),
        estimated_impact: EstimatedImpact {
            space_saving_bytes: None,
            performance: Some(
                "Maintaining OS drive headroom reduces operational and update risk.".to_string(),
            ),
            risk_notes: Some(
                "Do not use cloud/network/virtual targets for local performance placement."
                    .to_string(),
            ),
        },
        risk_level: RiskLevel::High,
    })
}

fn cloud_exclusion_notice_rule(report: &Report) -> Option<Recommendation> {
    let cloud_disks = report
        .disks
        .iter()
        .filter(|disk| matches!(disk.locality_class, LocalityClass::CloudBacked))
        .collect::<Vec<_>>();
    if cloud_disks.is_empty() {
        return None;
    }

    let mounts = cloud_disks
        .iter()
        .map(|disk| format!("{} ({})", disk.name, disk.mount_point))
        .collect::<Vec<_>>()
        .join(", ");
    Some(Recommendation {
        id: "cloud-backed-target-exclusion".to_string(),
        title: "Cloud-backed drives excluded from local placement targets".to_string(),
        rationale: format!(
            "Detected cloud-backed drive(s): {}. These are analyzed for visibility but excluded as local target destinations in optimization recommendations.",
            mounts
        ),
        confidence: 0.95,
        target_mount: None,
        policy_safe: true,
        policy_rules_applied: vec!["safe_target_policy".to_string()],
        policy_rules_blocked: Vec::new(),
        evidence: Vec::new(),
        next_steps: Vec::new(),
        estimated_impact: EstimatedImpact {
            space_saving_bytes: None,
            performance: None,
            risk_notes: Some(
                "Exclusion avoids misleading local-performance recommendations for virtual/cloud mounts."
                    .to_string(),
            ),
        },
        risk_level: RiskLevel::Low,
    })
}

fn category_scores_by_disk(report: &Report) -> HashMap<String, HashMap<Category, f32>> {
    let mut output: HashMap<String, HashMap<Category, f32>> = HashMap::new();
    for suggestion in &report.categories {
        let mount = suggestion
            .disk_mount
            .clone()
            .or_else(|| infer_mount_from_target(&report.disks, &suggestion.target));
        let Some(mount) = mount else {
            continue;
        };
        let category_scores = output.entry(mount).or_default();
        *category_scores
            .entry(suggestion.category.clone())
            .or_insert(0.0) += suggestion.confidence;
    }
    output
}

fn infer_mount_from_target(disks: &[DiskInfo], target: &str) -> Option<String> {
    let target_path = Path::new(target);
    let mut best: Option<(&DiskInfo, usize)> = None;
    for disk in disks {
        let mount = Path::new(&disk.mount_point);
        if !target_path.starts_with(mount) {
            continue;
        }
        let score = disk.mount_point.len();
        match best {
            Some((_, best_score)) if best_score >= score => {}
            _ => best = Some((disk, score)),
        }
    }
    best.map(|(disk, _)| disk.mount_point.clone())
}

fn eligible_non_os_local_targets(report: &Report) -> Vec<&DiskInfo> {
    report
        .disks
        .iter()
        .filter(|disk| {
            disk.eligible_for_local_target
                && !disk.is_os_drive
                && matches!(disk.locality_class, LocalityClass::LocalPhysical)
        })
        .collect::<Vec<_>>()
}

fn fastest_eligible_disk(report: &Report) -> Option<&DiskInfo> {
    eligible_non_os_local_targets(report)
        .into_iter()
        .max_by(|a, b| performance_rank(a).total_cmp(&performance_rank(b)))
}

fn performance_rank(disk: &DiskInfo) -> f32 {
    let base = match disk.performance_class {
        PerformanceClass::Fast => 3.0,
        PerformanceClass::Balanced => 2.0,
        PerformanceClass::Slow => 1.0,
        PerformanceClass::Unknown => 0.5,
    };
    let storage_bonus = match disk.storage_type {
        DiskStorageType::Nvme => 0.5,
        DiskStorageType::Ssd => 0.3,
        DiskStorageType::Hdd => 0.0,
        DiskStorageType::Usb => -0.1,
        DiskStorageType::CloudBacked | DiskStorageType::Network => -0.3,
        DiskStorageType::Virtual | DiskStorageType::Unknown => -0.2,
    };
    base + storage_bonus + disk.performance_confidence * 0.2
}

fn score_sum(scores: Option<&HashMap<Category, f32>>, categories: &[Category]) -> f32 {
    categories
        .iter()
        .map(|category| {
            scores
                .and_then(|map| map.get(category))
                .copied()
                .unwrap_or(0.0)
        })
        .sum()
}

fn used_space(disk: &DiskInfo) -> u64 {
    disk.total_space_bytes.saturating_sub(disk.free_space_bytes)
}

fn human_bytes(value: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    if value == 0 {
        return "0 B".to_string();
    }
    let mut size = value as f64;
    let mut unit = 0;
    while size >= 1024.0 && unit < UNITS.len() - 1 {
        size /= 1024.0;
        unit += 1;
    }
    format!("{size:.1} {}", UNITS[unit])
}

fn observed_bytes_by_disk(report: &Report) -> HashMap<String, u64> {
    let mut totals = HashMap::new();
    for path in &report.paths {
        let Some(mount) = &path.disk_mount else {
            continue;
        };
        let entry = totals.entry(mount.clone()).or_insert(0_u64);
        *entry = entry.saturating_add(path.total_size_bytes);
    }
    totals
}

fn has_sufficient_scan_coverage(disk: &DiskInfo, observed_bytes: Option<u64>) -> bool {
    let Some(observed_bytes) = observed_bytes else {
        return false;
    };
    let used = used_space(disk);
    if used == 0 {
        return false;
    }
    (observed_bytes as f64 / used as f64) >= MIN_SOURCE_SCAN_COVERAGE_RATIO
}

fn sanitize_id(value: &str) -> String {
    value
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{generate_recommendation_bundle, generate_recommendations};
    use crate::model::{
        CategorySuggestion, DiskInfo, DiskKind, DiskStorageType, LocalityClass, PerformanceClass,
        Report, ScanBackendKind, ScanMetrics,
    };

    #[test]
    fn fixture_triggers_expected_recommendation_ids() {
        let fixture = include_str!("../../../fixtures/sample-report.json");
        let report: Report = serde_json::from_str(fixture).expect("valid fixture");
        let recommendations = generate_recommendations(&report);
        let ids = recommendations
            .into_iter()
            .map(|item| item.id)
            .collect::<Vec<_>>();

        assert!(ids.iter().any(|id| id == "duplicate-cleanup-candidate"));
        assert!(ids.iter().any(|id| id == "backup-gap"));
        assert!(ids.iter().any(|id| id == "cloud-backed-target-exclusion"));
    }

    #[test]
    fn excludes_cloud_drives_from_consolidation_targeting() {
        let local = disk(
            "Data",
            "D:\\",
            DiskStorageType::Hdd,
            LocalityClass::LocalPhysical,
            false,
            true,
            1_000_000_000_000,
            100_000_000_000,
        );
        let cloud = disk(
            "Google Drive",
            "J:\\",
            DiskStorageType::CloudBacked,
            LocalityClass::CloudBacked,
            false,
            false,
            10_000_000_000_000,
            9_000_000_000_000,
        );

        let report = minimal_report(vec![local, cloud]);
        let ids = generate_recommendations(&report)
            .into_iter()
            .map(|item| item.id)
            .collect::<Vec<_>>();

        assert!(!ids.iter().any(|id| id == "consolidation-opportunity"));
    }

    #[test]
    fn avoids_consolidation_when_roles_conflict_active_to_media() {
        let d = disk(
            "Black Rider (Games and Apps)",
            "D:\\",
            DiskStorageType::Ssd,
            LocalityClass::LocalPhysical,
            false,
            true,
            1_000_000_000_000,
            300_000_000_000,
        );
        let g = disk(
            "RED (Photos)",
            "G:\\",
            DiskStorageType::Hdd,
            LocalityClass::LocalPhysical,
            false,
            true,
            4_000_000_000_000,
            3_000_000_000_000,
        );

        let report = Report {
            report_version: "1.2.0".to_string(),
            generated_at: "2026-02-11T00:00:00Z".to_string(),
            scan_id: "test-scan".to_string(),
            scan: crate::model::ScanMetadata {
                roots: vec!["D:\\".to_string(), "G:\\".to_string()],
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
            scan_progress_summary: crate::model::ScanProgressSummary::default(),
            backend_parity: None,
            disks: vec![d, g],
            paths: vec![
                crate::model::PathStats {
                    root_path: "D:\\".to_string(),
                    disk_mount: Some("D:\\".to_string()),
                    total_size_bytes: 500_000_000_000,
                    file_count: 1,
                    directory_count: 0,
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
                },
                crate::model::PathStats {
                    root_path: "G:\\".to_string(),
                    disk_mount: Some("G:\\".to_string()),
                    total_size_bytes: 600_000_000_000,
                    file_count: 1,
                    directory_count: 0,
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
                },
            ],
            categories: vec![
                CategorySuggestion {
                    target: "D:\\".to_string(),
                    disk_mount: Some("D:\\".to_string()),
                    category: crate::model::Category::Games,
                    confidence: 0.9,
                    rationale: "test".to_string(),
                    evidence: vec!["games".to_string()],
                },
                CategorySuggestion {
                    target: "G:\\".to_string(),
                    disk_mount: Some("G:\\".to_string()),
                    category: crate::model::Category::Media,
                    confidence: 0.9,
                    rationale: "test".to_string(),
                    evidence: vec!["photos".to_string()],
                },
            ],
            duplicates: Vec::new(),
            recommendations: Vec::new(),
            policy_decisions: Vec::new(),
            rule_traces: Vec::new(),
            warnings: Vec::new(),
        };

        let ids = generate_recommendations(&report)
            .into_iter()
            .map(|item| item.id)
            .collect::<Vec<_>>();
        assert!(!ids.iter().any(|id| id == "consolidation-opportunity"));
    }

    #[test]
    fn bundle_contains_rule_traces() {
        let fixture = include_str!("../../../fixtures/sample-report.json");
        let report: Report = serde_json::from_str(fixture).expect("valid fixture");
        let bundle = generate_recommendation_bundle(&report);
        assert!(!bundle.rule_traces.is_empty());
        assert!(!bundle.policy_decisions.is_empty());
    }

    fn minimal_report(disks: Vec<DiskInfo>) -> Report {
        Report {
            report_version: "1.2.0".to_string(),
            generated_at: "2026-02-11T00:00:00Z".to_string(),
            scan_id: "test-scan".to_string(),
            scan: crate::model::ScanMetadata {
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
            scan_progress_summary: crate::model::ScanProgressSummary::default(),
            backend_parity: None,
            disks,
            paths: Vec::new(),
            categories: vec![CategorySuggestion {
                target: "D:\\Work".to_string(),
                disk_mount: Some("D:\\".to_string()),
                category: crate::model::Category::Work,
                confidence: 0.9,
                rationale: "test".to_string(),
                evidence: vec!["work".to_string()],
            }],
            duplicates: Vec::new(),
            recommendations: Vec::new(),
            policy_decisions: Vec::new(),
            rule_traces: Vec::new(),
            warnings: Vec::new(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn disk(
        name: &str,
        mount_point: &str,
        storage_type: DiskStorageType,
        locality_class: LocalityClass,
        is_os_drive: bool,
        eligible_for_local_target: bool,
        total_space_bytes: u64,
        free_space_bytes: u64,
    ) -> DiskInfo {
        DiskInfo {
            name: name.to_string(),
            mount_point: mount_point.to_string(),
            total_space_bytes,
            free_space_bytes,
            disk_kind: DiskKind::Unknown,
            file_system: Some("ntfs".to_string()),
            storage_type,
            locality_class,
            locality_confidence: 0.9,
            locality_rationale: "test".to_string(),
            is_os_drive,
            is_removable: false,
            vendor: None,
            model: None,
            interface: None,
            rotational: None,
            hybrid: None,
            performance_class: PerformanceClass::Balanced,
            performance_confidence: 0.6,
            performance_rationale: "test".to_string(),
            eligible_for_local_target,
            ineligible_reasons: Vec::new(),
            metadata_notes: Vec::new(),
            role_hint: Default::default(),
            target_role_eligibility: Vec::new(),
        }
    }
}
