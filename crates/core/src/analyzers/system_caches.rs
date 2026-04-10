use crate::analyzers::{Analyzer, AnalyzerContext, AnalyzerResult};
use crate::model::{
    EstimatedImpact, Recommendation, Report, RiskLevel, RuleTrace, RuleTraceStatus,
};
use std::collections::HashMap;
use std::path::Path;

pub struct SystemCachesAnalyzer;

const MIN_CACHE_SIZE_BYTES: u64 = 500_000_000; // 500 MB

struct CacheTarget {
    id: &'static str,
    name: &'static str,
    paths: Vec<String>,
    cleanup_command: &'static str,
}

impl Analyzer for SystemCachesAnalyzer {
    fn id(&self) -> &'static str {
        "system_caches"
    }

    fn analyze(&self, report: &Report, _context: &AnalyzerContext) -> AnalyzerResult {
        let mut recommendations = Vec::new();
        let mut traces = Vec::new();
        let cache_targets = get_os_cache_targets();

        if cache_targets.is_empty() {
            traces.push(RuleTrace {
                rule_id: self.id().to_string(),
                status: RuleTraceStatus::Skipped,
                detail: "No system cache targets defined for this OS.".to_string(),
                recommendation_id: None,
                confidence: None,
            });
            return AnalyzerResult {
                recommendations,
                traces,
            };
        }

        let mut findings: HashMap<&str, (u64, Vec<String>)> = HashMap::new();

        for target in &cache_targets {
            for path_stats in &report.paths {
                for dir_usage in &path_stats.largest_directories {
                    for cache_path in &target.paths {
                        if Path::new(&dir_usage.path) == Path::new(cache_path) {
                            let entry = findings.entry(target.id).or_default();
                            entry.0 += dir_usage.size_bytes;
                            entry.1.push(dir_usage.path.clone());
                        }
                    }
                }
            }
        }

        for target in &cache_targets {
            if let Some((total_size, paths)) = findings.get(target.id) {
                if *total_size > MIN_CACHE_SIZE_BYTES {
                    let rec = Recommendation {
                        id: format!("cleanup-{}", target.id),
                        title: format!("Review {} cache", target.name),
                        rationale: format!(
                            "Found {} cache director(y/ies) totaling {}. This can be cleaned to reclaim space. Cleanup command: `{}`",
                            paths.len(),
                            human_bytes(*total_size),
                            target.cleanup_command
                        ),
                        confidence: 0.7,
                        target_mount: None,
                        policy_safe: true,
                        policy_rules_applied: vec![],
                        policy_rules_blocked: vec![],
                        evidence: Vec::new(),
                        next_steps: Vec::new(),
                        estimated_impact: EstimatedImpact {
                            space_saving_bytes: Some(*total_size),
                            performance: None,
                            risk_notes: Some(
                                "Running the cleanup command will remove cached data, which may be redownloaded later."
                                    .to_string(),
                            ),
                        },
                        risk_level: RiskLevel::Low,
                    };
                    recommendations.push(rec);
                }
            }
        }

        if recommendations.is_empty() {
            traces.push(RuleTrace {
                rule_id: self.id().to_string(),
                status: RuleTraceStatus::Skipped,
                detail: "No significant system caches found in scanned paths.".to_string(),
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

#[cfg(target_os = "windows")]
fn get_os_cache_targets() -> Vec<CacheTarget> {
    let mut targets = Vec::new();
    if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
        targets.push(CacheTarget {
            id: "docker-wsl",
            name: "Docker WSL data",
            paths: vec![format!("{}\\Docker\\wsl", local_app_data)],
            cleanup_command: "docker system prune -a",
        });
        targets.push(CacheTarget {
            id: "pip-cache",
            name: "pip cache",
            paths: vec![format!("{}\\pip\\Cache", local_app_data)],
            cleanup_command: "pip cache purge",
        });
        targets.push(CacheTarget {
            id: "nvidia-glcache",
            name: "NVIDIA GL Cache",
            paths: vec![format!("{}\\NVIDIA\\GLCache", local_app_data)],
            cleanup_command: "Manually delete files",
        });
    }
    targets
}

#[cfg(not(target_os = "windows"))]
fn get_os_cache_targets() -> Vec<CacheTarget> {
    // TODO: Add paths for Linux and macOS
    Vec::new()
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
