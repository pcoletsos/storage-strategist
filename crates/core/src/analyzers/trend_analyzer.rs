use crate::analyzers::{Analyzer, AnalyzerContext, AnalyzerResult};
use crate::history;
use crate::model::{
    EstimatedImpact, Recommendation, Report, RiskLevel, RuleTrace, RuleTraceStatus,
};
use chrono::{DateTime, Utc};
use std::collections::HashMap;

pub struct TrendAnalyzer;

const MIN_PCT_CHANGE: f64 = 0.10; // 10%
const MIN_ABS_CHANGE_BYTES: u64 = 1_073_741_824; // 1 GB

impl Analyzer for TrendAnalyzer {
    fn id(&self) -> &'static str {
        "trend_analyzer"
    }

    fn analyze(&self, _report: &Report, context: &AnalyzerContext) -> AnalyzerResult {
        let mut result = AnalyzerResult::default();
        let history = match history::load_history(context.report_store_dir.as_deref()) {
            Ok(h) => h,
            Err(e) => {
                result.traces.push(RuleTrace {
                    rule_id: self.id().to_string(),
                    status: RuleTraceStatus::Skipped,
                    detail: format!("Failed to load scan history: {}", e),
                    recommendation_id: None,
                    confidence: None,
                });
                return result;
            }
        };

        if history.snapshots.len() < 2 {
            result.traces.push(RuleTrace {
                rule_id: self.id().to_string(),
                status: RuleTraceStatus::Skipped,
                detail: "Not enough historical data to analyze trends.".to_string(),
                recommendation_id: None,
                confidence: None,
            });
            return result;
        }

        let latest = &history.snapshots[history.snapshots.len() - 1];
        let previous = &history.snapshots[history.snapshots.len() - 2];

        let latest_ts = latest.generated_at.parse::<DateTime<Utc>>().ok();
        let previous_ts = previous.generated_at.parse::<DateTime<Utc>>().ok();
        let duration_days = if let (Some(l), Some(p)) = (latest_ts, previous_ts) {
            (l - p).num_days()
        } else {
            0
        };

        analyze_disk_trends(latest, previous, duration_days, &mut result.recommendations);
        analyze_path_trends(latest, previous, duration_days, &mut result.recommendations);

        if result.recommendations.is_empty() {
            result.traces.push(RuleTrace {
                rule_id: self.id().to_string(),
                status: RuleTraceStatus::Skipped,
                detail: "No significant storage trends detected.".to_string(),
                recommendation_id: None,
                confidence: None,
            });
        } else {
            for rec in &result.recommendations {
                result.traces.push(RuleTrace {
                    rule_id: self.id().to_string(),
                    status: RuleTraceStatus::Emitted,
                    detail: format!("Emitted trend recommendation '{}'", rec.id),
                    recommendation_id: Some(rec.id.clone()),
                    confidence: Some(rec.confidence),
                });
            }
        }

        result
    }
}

fn analyze_disk_trends(
    latest: &crate::model::ScanSnapshot,
    previous: &crate::model::ScanSnapshot,
    duration_days: i64,
    recommendations: &mut Vec<Recommendation>,
) {
    let prev_disks: HashMap<_, _> = previous
        .disks
        .iter()
        .map(|d| (d.mount_point.clone(), d))
        .collect();

    for disk in &latest.disks {
        if let Some(prev_disk) = prev_disks.get(&disk.mount_point) {
            let change = prev_disk.free_space_bytes as i64 - disk.free_space_bytes as i64;
            let pct_change = change as f64 / disk.total_space_bytes.max(1) as f64;

            if change.unsigned_abs() > MIN_ABS_CHANGE_BYTES && pct_change > MIN_PCT_CHANGE {
                recommendations.push(Recommendation {
                    id: format!("disk-growth-{}", sanitize_id(&disk.mount_point)),
                    title: format!("Review storage growth on disk {}", disk.mount_point),
                    rationale: format!(
                        "Disk {} has lost {} of free space in the last {}. Review recent files and application caches.",
                        disk.mount_point,
                        human_bytes(change as u64),
                        human_duration(duration_days)
                    ),
                    confidence: 0.75,
                    target_mount: Some(disk.mount_point.clone()),
                    policy_safe: true,
                    policy_rules_applied: vec![],
                    policy_rules_blocked: vec![],
                    evidence: Vec::new(),
                    next_steps: Vec::new(),
                    estimated_impact: EstimatedImpact {
                        space_saving_bytes: None,
                        performance: None,
                        risk_notes: Some("Unmanaged growth can lead to performance issues or data loss if the disk becomes full.".to_string()),
                    },
                    risk_level: RiskLevel::Medium,
                });
            }
        }
    }
}

fn analyze_path_trends(
    latest: &crate::model::ScanSnapshot,
    previous: &crate::model::ScanSnapshot,
    duration_days: i64,
    recommendations: &mut Vec<Recommendation>,
) {
    let prev_paths: HashMap<_, _> = previous
        .paths
        .iter()
        .map(|p| (p.root_path.clone(), p))
        .collect();

    for path in &latest.paths {
        if let Some(prev_path) = prev_paths.get(&path.root_path) {
            if path.total_size_bytes > prev_path.total_size_bytes {
                let change = path.total_size_bytes - prev_path.total_size_bytes;
                let pct_change = change as f64 / prev_path.total_size_bytes.max(1) as f64;

                if change > MIN_ABS_CHANGE_BYTES && pct_change > MIN_PCT_CHANGE {
                    recommendations.push(Recommendation {
                        id: format!("path-growth-{}", sanitize_id(&path.root_path)),
                        title: format!("Review storage growth in {}", path.root_path),
                        rationale: format!(
                            "Path {} has grown by {} in the last {}. Consider reviewing the largest files and subdirectories.",
                            path.root_path,
                            human_bytes(change),
                            human_duration(duration_days)
                        ),
                        confidence: 0.78,
                        target_mount: None,
                        policy_safe: true,
                        policy_rules_applied: vec![],
                        policy_rules_blocked: vec![],
                        evidence: Vec::new(),
                        next_steps: Vec::new(),
                        estimated_impact: EstimatedImpact {
                            space_saving_bytes: None,
                            performance: None,
                            risk_notes: Some("Identifying the source of growth can help manage storage proactively.".to_string()),
                        },
                        risk_level: RiskLevel::Low,
                    });
                }
            }
        }
    }
}

fn sanitize_id(value: &str) -> String {
    value
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect()
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
    format!("{:.1} {}", size, UNITS[unit])
}

fn human_duration(days: i64) -> String {
    if days <= 1 {
        "day".to_string()
    } else {
        format!("{} days", days)
    }
}
