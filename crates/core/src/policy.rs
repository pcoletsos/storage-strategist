use std::collections::{HashMap, HashSet};

use crate::model::{
    DiskRole, PolicyAction, PolicyDecision, Recommendation, Report, RuleTrace, RuleTraceStatus,
};

pub struct PolicyOutcome {
    pub recommendations: Vec<Recommendation>,
    pub decisions: Vec<PolicyDecision>,
    pub contradiction_count: u64,
    pub rejection_traces: Vec<RuleTrace>,
}

pub fn enforce_recommendation_policies(
    report: &Report,
    candidates: Vec<Recommendation>,
) -> PolicyOutcome {
    let disk_by_mount = report
        .disks
        .iter()
        .map(|disk| (disk.mount_point.clone(), disk))
        .collect::<HashMap<_, _>>();

    let mut recommendations = Vec::new();
    let mut decisions = Vec::new();
    let mut rejection_traces = Vec::new();

    for mut recommendation in candidates {
        let mut allowed = true;
        let mut rejection_rationale: Option<String> = None;
        let mut rejection_rule_id = "safe_target_policy".to_string();

        if let Some(target_mount) = &recommendation.target_mount {
            if let Some(disk) = disk_by_mount.get(target_mount) {
                if !disk.eligible_for_local_target {
                    allowed = false;
                    let rationale = format!(
                        "Target mount {} is not eligible for local placement: {}",
                        target_mount,
                        disk.ineligible_reasons.join(" | ")
                    );
                    rejection_rule_id = "safe_target_policy".to_string();
                    rejection_rationale = Some(rationale.clone());
                    recommendation
                        .policy_rules_blocked
                        .push("safe_target_policy".to_string());
                    decisions.push(PolicyDecision {
                        policy_id: "safe_target_policy".to_string(),
                        recommendation_id: recommendation.id.clone(),
                        action: PolicyAction::Blocked,
                        rationale,
                    });
                } else {
                    recommendation
                        .policy_rules_applied
                        .push("safe_target_policy".to_string());
                    decisions.push(PolicyDecision {
                        policy_id: "safe_target_policy".to_string(),
                        recommendation_id: recommendation.id.clone(),
                        action: PolicyAction::Allowed,
                        rationale: "Target mount passed local placement eligibility checks."
                            .to_string(),
                    });
                }
            } else {
                allowed = false;
                let rationale = format!(
                    "Target mount {} was not found in disk inventory; recommendation blocked.",
                    target_mount
                );
                rejection_rule_id = "safe_target_policy".to_string();
                rejection_rationale = Some(rationale.clone());
                recommendation
                    .policy_rules_blocked
                    .push("safe_target_policy".to_string());
                decisions.push(PolicyDecision {
                    policy_id: "safe_target_policy".to_string(),
                    recommendation_id: recommendation.id.clone(),
                    action: PolicyAction::Blocked,
                    rationale,
                });
            }
        } else {
            recommendation
                .policy_rules_applied
                .push("safe_target_policy".to_string());
            decisions.push(PolicyDecision {
                policy_id: "safe_target_policy".to_string(),
                recommendation_id: recommendation.id.clone(),
                action: PolicyAction::Allowed,
                rationale: "Recommendation does not target a mount and passed eligibility checks."
                    .to_string(),
            });
        }

        if allowed && recommendation_targets_active_placement(&recommendation.id) {
            if let Some(target_mount) = &recommendation.target_mount {
                if let Some(disk) = disk_by_mount.get(target_mount) {
                    if matches!(
                        disk.role_hint.role,
                        DiskRole::MediaLibrary | DiskRole::Archive | DiskRole::BackupTarget
                    ) {
                        allowed = false;
                        let rationale = format!(
                            "Target mount {} role {:?} is reserved for colder/backup data; blocked active workload placement recommendation.",
                            target_mount, disk.role_hint.role
                        );
                        rejection_rule_id = "role_aware_target_policy".to_string();
                        rejection_rationale = Some(rationale.clone());
                        recommendation
                            .policy_rules_blocked
                            .push("role_aware_target_policy".to_string());
                        decisions.push(PolicyDecision {
                            policy_id: "role_aware_target_policy".to_string(),
                            recommendation_id: recommendation.id.clone(),
                            action: PolicyAction::Blocked,
                            rationale,
                        });
                    } else {
                        recommendation
                            .policy_rules_applied
                            .push("role_aware_target_policy".to_string());
                        decisions.push(PolicyDecision {
                            policy_id: "role_aware_target_policy".to_string(),
                            recommendation_id: recommendation.id.clone(),
                            action: PolicyAction::Allowed,
                            rationale: "Target role is compatible with active workload placement."
                                .to_string(),
                        });
                    }
                }
            }
        }

        recommendation.policy_safe = allowed;

        if allowed {
            recommendations.push(recommendation);
        } else {
            rejection_traces.push(RuleTrace {
                rule_id: rejection_rule_id,
                status: RuleTraceStatus::Rejected,
                detail: rejection_rationale.unwrap_or_else(|| {
                    "Recommendation blocked by safety policy checks.".to_string()
                }),
                recommendation_id: Some(recommendation.id),
                confidence: None,
            });
        }
    }

    let mut deduped = Vec::new();
    let mut seen = HashSet::new();
    let mut contradiction_count = 0_u64;
    for mut recommendation in recommendations {
        if seen.insert(recommendation.id.clone()) {
            deduped.push(recommendation);
            continue;
        }
        recommendation
            .policy_rules_blocked
            .push("contradiction_detector".to_string());
        contradiction_count = contradiction_count.saturating_add(1);
        decisions.push(PolicyDecision {
            policy_id: "contradiction_detector".to_string(),
            recommendation_id: recommendation.id.clone(),
            action: PolicyAction::Blocked,
            rationale: "Duplicate recommendation id detected; later instance removed.".to_string(),
        });
        rejection_traces.push(RuleTrace {
            rule_id: "contradiction_detector".to_string(),
            status: RuleTraceStatus::Rejected,
            detail: "Duplicate recommendation id detected; later instance removed.".to_string(),
            recommendation_id: Some(recommendation.id),
            confidence: None,
        });
    }

    PolicyOutcome {
        recommendations: deduped,
        decisions,
        contradiction_count,
        rejection_traces,
    }
}

fn recommendation_targets_active_placement(recommendation_id: &str) -> bool {
    recommendation_id == "active-workload-placement"
}

#[cfg(test)]
mod tests {
    use super::enforce_recommendation_policies;
    use crate::model::{
        DiskInfo, DiskKind, DiskStorageType, EstimatedImpact, LocalityClass, PerformanceClass,
        Recommendation, Report, RiskLevel, ScanBackendKind, ScanMetadata, ScanMetrics,
    };

    #[test]
    fn blocks_recommendation_to_cloud_target_mount() {
        let cloud_disk = DiskInfo {
            name: "Google Drive".to_string(),
            mount_point: "J:\\".to_string(),
            total_space_bytes: 1,
            free_space_bytes: 1,
            disk_kind: DiskKind::Unknown,
            file_system: Some("google".to_string()),
            storage_type: DiskStorageType::CloudBacked,
            locality_class: LocalityClass::CloudBacked,
            locality_confidence: 0.9,
            locality_rationale: "test".to_string(),
            is_os_drive: false,
            is_removable: false,
            vendor: None,
            model: None,
            interface: None,
            rotational: None,
            hybrid: None,
            performance_class: PerformanceClass::Slow,
            performance_confidence: 0.7,
            performance_rationale: "test".to_string(),
            eligible_for_local_target: false,
            ineligible_reasons: vec!["Cloud-backed drive is excluded".to_string()],
            metadata_notes: Vec::new(),
            role_hint: Default::default(),
            target_role_eligibility: Vec::new(),
        };

        let report = Report {
            report_version: "1.2.0".to_string(),
            generated_at: "2026-02-11T00:00:00Z".to_string(),
            scan_id: "test-scan".to_string(),
            scan: ScanMetadata {
                roots: vec!["J:\\".to_string()],
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
            disks: vec![cloud_disk],
            paths: Vec::new(),
            categories: Vec::new(),
            duplicates: Vec::new(),
            recommendations: Vec::new(),
            policy_decisions: Vec::new(),
            rule_traces: Vec::new(),
            warnings: Vec::new(),
        };

        let candidate = Recommendation {
            id: "test-rec".to_string(),
            title: "bad target".to_string(),
            rationale: "test".to_string(),
            confidence: 0.9,
            target_mount: Some("J:\\".to_string()),
            policy_safe: true,
            policy_rules_applied: Vec::new(),
            policy_rules_blocked: Vec::new(),
            evidence: Vec::new(),
            next_steps: Vec::new(),
            estimated_impact: EstimatedImpact {
                space_saving_bytes: None,
                performance: None,
                risk_notes: None,
            },
            risk_level: RiskLevel::Low,
        };

        let outcome = enforce_recommendation_policies(&report, vec![candidate]);
        assert!(outcome.recommendations.is_empty());
        assert_eq!(outcome.decisions.len(), 1);
    }

    #[test]
    fn blocks_active_placement_into_media_role_target() {
        let media_disk = DiskInfo {
            name: "RED (Photos)".to_string(),
            mount_point: "G:\\".to_string(),
            total_space_bytes: 1,
            free_space_bytes: 1,
            disk_kind: DiskKind::Hdd,
            file_system: Some("ntfs".to_string()),
            storage_type: DiskStorageType::Hdd,
            locality_class: LocalityClass::LocalPhysical,
            locality_confidence: 0.9,
            locality_rationale: "test".to_string(),
            is_os_drive: false,
            is_removable: false,
            vendor: None,
            model: None,
            interface: None,
            rotational: Some(true),
            hybrid: Some(false),
            performance_class: PerformanceClass::Slow,
            performance_confidence: 0.7,
            performance_rationale: "test".to_string(),
            eligible_for_local_target: true,
            ineligible_reasons: Vec::new(),
            metadata_notes: Vec::new(),
            role_hint: crate::model::DiskRoleHint {
                role: crate::model::DiskRole::MediaLibrary,
                confidence: 0.9,
                evidence: vec!["photos".to_string()],
            },
            target_role_eligibility: vec!["media_library".to_string()],
        };

        let report = Report {
            report_version: "1.2.0".to_string(),
            generated_at: "2026-02-11T00:00:00Z".to_string(),
            scan_id: "test-scan".to_string(),
            scan: ScanMetadata {
                roots: vec!["G:\\".to_string()],
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
            disks: vec![media_disk],
            paths: Vec::new(),
            categories: Vec::new(),
            duplicates: Vec::new(),
            recommendations: Vec::new(),
            policy_decisions: Vec::new(),
            rule_traces: Vec::new(),
            warnings: Vec::new(),
        };

        let candidate = Recommendation {
            id: "active-workload-placement".to_string(),
            title: "test".to_string(),
            rationale: "test".to_string(),
            confidence: 0.8,
            target_mount: Some("G:\\".to_string()),
            policy_safe: true,
            policy_rules_applied: Vec::new(),
            policy_rules_blocked: Vec::new(),
            evidence: Vec::new(),
            next_steps: Vec::new(),
            estimated_impact: EstimatedImpact {
                space_saving_bytes: None,
                performance: None,
                risk_notes: None,
            },
            risk_level: RiskLevel::Low,
        };

        let outcome = enforce_recommendation_policies(&report, vec![candidate]);
        assert!(outcome.recommendations.is_empty());
        assert!(outcome
            .decisions
            .iter()
            .any(|d| d.policy_id == "role_aware_target_policy"));
    }
}
