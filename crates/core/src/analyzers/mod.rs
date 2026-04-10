use std::path::PathBuf;

use crate::model::{Recommendation, Report, RuleTrace};

pub mod dev_artifacts;
pub mod system_caches;
pub mod trend_analyzer;

#[derive(Debug, Clone, Default)]
pub struct AnalyzerContext {
    pub report_store_dir: Option<PathBuf>,
}

/// A trait for application-specific or pattern-specific analysis.
pub trait Analyzer {
    fn id(&self) -> &'static str;
    fn analyze(&self, report: &Report, context: &AnalyzerContext) -> AnalyzerResult;
}

/// The output of a single analyzer.
#[derive(Default)]
pub struct AnalyzerResult {
    pub recommendations: Vec<Recommendation>,
    pub traces: Vec<RuleTrace>,
}

/// Runs all registered analyzers and returns their combined results.
pub fn run_analyzers(report: &Report, context: &AnalyzerContext) -> Vec<AnalyzerResult> {
    let analyzers: Vec<Box<dyn Analyzer>> = vec![
        Box::new(dev_artifacts::DevArtifactsAnalyzer),
        Box::new(system_caches::SystemCachesAnalyzer),
        Box::new(trend_analyzer::TrendAnalyzer),
    ];

    analyzers
        .iter()
        .map(|analyzer| analyzer.analyze(report, context))
        .collect()
}
