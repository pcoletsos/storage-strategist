use std::collections::HashMap;

use crate::analyzers::{Analyzer, AnalyzerContext, AnalyzerResult};
use crate::model::{
    EstimatedImpact, Recommendation, Report, RiskLevel, RuleTrace, RuleTraceStatus,
};

pub struct DevArtifactsAnalyzer;

const NODE_MODULES_MIN_SIZE_BYTES: u64 = 1_000_000_000; // 1 GB
const TARGET_DIR_MIN_SIZE_BYTES: u64 = 2_000_000_000; // 2 GB

impl Analyzer for DevArtifactsAnalyzer {
    fn id(&self) -> &'static str {
        "dev_artifacts"
    }

    fn analyze(&self, report: &Report, _context: &AnalyzerContext) -> AnalyzerResult {
        let mut findings: HashMap<&str, (u64, Vec<String>)> = HashMap::new();
        let mut traces = Vec::new();

        for path_stats in &report.paths {
            for dir_usage in &path_stats.largest_directories {
                let path = &dir_usage.path;
                let size = dir_usage.size_bytes;

                if is_node_modules(path) {
                    let entry = findings.entry("node_modules").or_default();
                    entry.0 += size;
                    entry.1.push(path.clone());
                } else if is_target_dir(path) {
                    let entry = findings.entry("target").or_default();
                    entry.0 += size;
                    entry.1.push(path.clone());
                }
            }
        }

        let mut recommendations = Vec::new();

        if let Some((total_size, paths)) = findings.get("node_modules") {
            if *total_size > NODE_MODULES_MIN_SIZE_BYTES {
                let rec = Recommendation {
                    id: "cleanup-node-modules".to_string(),
                    title: "Review large `node_modules` directories".to_string(),
                    rationale: format!(
                        "Found {} `node_modules` director(y/ies) totaling {}. These can often be pruned or deleted in inactive projects to reclaim space.",
                        paths.len(),
                        human_bytes(*total_size)
                    ),
                    confidence: 0.8,
                    target_mount: None,
                    policy_safe: true,
                    policy_rules_applied: vec![],
                    policy_rules_blocked: vec![],
                    evidence: Vec::new(),
                    next_steps: Vec::new(),
                    estimated_impact: EstimatedImpact {
                        space_saving_bytes: Some(*total_size),
                        performance: None,
                        risk_notes: Some("Deleting `node_modules` requires reinstalling dependencies with `npm install` or similar before resuming development.".to_string()),
                    },
                    risk_level: RiskLevel::Low,
                };
                recommendations.push(rec);
            }
        }

        if let Some((total_size, paths)) = findings.get("target") {
            if *total_size > TARGET_DIR_MIN_SIZE_BYTES {
                let rec = Recommendation {
                    id: "cleanup-target-dirs".to_string(),
                    title: "Review large Rust `target` directories".to_string(),
                    rationale: format!(
                        "Found {} Rust `target` director(y/ies) totaling {}. These directories contain build artifacts and can be cleaned with `cargo clean` to reclaim significant space.",
                        paths.len(),
                        human_bytes(*total_size)
                    ),
                    confidence: 0.8,
                    target_mount: None,
                    policy_safe: true,
                    policy_rules_applied: vec![],
                    policy_rules_blocked: vec![],
                    evidence: Vec::new(),
                    next_steps: Vec::new(),
                    estimated_impact: EstimatedImpact {
                        space_saving_bytes: Some(*total_size),
                        performance: None,
                        risk_notes: Some("`cargo clean` will remove all build artifacts, requiring a full recompile of the project.".to_string()),
                    },
                    risk_level: RiskLevel::Low,
                };
                recommendations.push(rec);
            }
        }

        if recommendations.is_empty() {
            traces.push(RuleTrace {
                rule_id: self.id().to_string(),
                status: RuleTraceStatus::Skipped,
                detail: "No significant development artifacts found.".to_string(),
                recommendation_id: None,
                confidence: None,
            });
        } else {
            for rec in &recommendations {
                traces.push(RuleTrace {
                    rule_id: self.id().to_string(),
                    status: RuleTraceStatus::Emitted,
                    detail: format!("Emitted recommendation '{}'", rec.id),
                    recommendation_id: Some(rec.id.clone()),
                    confidence: Some(rec.confidence),
                });
            }
        }

        AnalyzerResult {
            recommendations,
            traces,
        }
    }
}

fn is_node_modules(path: &str) -> bool {
    path.ends_with("/node_modules") || path.ends_with("\\node_modules")
}

fn is_target_dir(path: &str) -> bool {
    path.ends_with("/target") || path.ends_with("\\target")
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
