pub mod analyzers;
pub mod categorize;
pub mod dedupe;
pub mod device;
pub mod diagnostics;
pub mod doctor;
pub mod eval;
pub mod history;
pub mod markdown;
pub mod model;
pub mod planner;
pub mod policy;
pub mod recommend;
pub mod reports;
pub mod role;
pub mod scan;

pub use device::{detect_os_mount, enrich_disks, DiskProbe};
pub use diagnostics::{
    build_diagnostics_bundle, write_diagnostics_bundle, DiagnosticsBundle, DiagnosticsEnvironment,
};
pub use doctor::{collect_doctor_info, DoctorInfo};
pub use eval::{
    evaluate_suite, evaluate_suite_file, EvaluationCase, EvaluationResult, EvaluationSuite,
};
pub use markdown::render_markdown_summary;
pub use model::{
    BackendParity, Category, CategorySuggestion, DiskDiff, DiskInfo, DiskKind, DiskRole,
    DiskRoleHint, DiskStorageType, DuplicateGroup, DuplicateIntent, DuplicateIntentLabel,
    EstimatedImpact, FileEntry, FileTypeSummary, LocalityClass, PathDiff, PathStats,
    PerformanceClass, PolicyAction, PolicyDecision, Recommendation, RecommendationChange,
    RecommendationChangeKind, RecommendationEvidence, RecommendationEvidenceKind, Report,
    ReportDiff, ReportImportResult, ReportSummary, RiskLevel, RuleTrace, RuleTraceStatus,
    ScanBackendKind, ScanMetadata, ScanMetrics, ScanPhase, ScanPhaseCount, ScanProgressEvent,
    ScanProgressSummary, REPORT_VERSION,
};
pub use planner::{
    build_scenario_plan, ScenarioPlan, ScenarioProjection, ScenarioRiskMix, ScenarioStrategy,
};
pub use recommend::{
    generate_recommendation_bundle, generate_recommendations, RecommendationBundle,
};
pub use reports::{
    build_report_diff, compare_reports, default_report_store_dir, get_report, history_file_path,
    import_report, list_reports, report_path_for_scan, resolve_report_store_dir, store_report,
};
pub use role::infer_disk_roles;
pub use scan::{
    compare_backends, run_scan, run_scan_with_callback, run_scan_with_events, ScanOptions,
    ScanRunOutput,
};
