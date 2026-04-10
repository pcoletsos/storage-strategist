use serde::{Deserialize, Serialize};

pub const REPORT_VERSION: &str = "1.3.0";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Report {
    pub report_version: String,
    pub generated_at: String,
    #[serde(default = "default_scan_id")]
    pub scan_id: String,
    pub scan: ScanMetadata,
    #[serde(default)]
    pub scan_metrics: ScanMetrics,
    #[serde(default)]
    pub scan_progress_summary: ScanProgressSummary,
    #[serde(default)]
    pub backend_parity: Option<BackendParity>,
    pub disks: Vec<DiskInfo>,
    pub paths: Vec<PathStats>,
    pub categories: Vec<CategorySuggestion>,
    pub duplicates: Vec<DuplicateGroup>,
    pub recommendations: Vec<Recommendation>,
    #[serde(default)]
    pub policy_decisions: Vec<PolicyDecision>,
    #[serde(default)]
    pub rule_traces: Vec<RuleTrace>,
    pub warnings: Vec<String>,
}

fn default_scan_id() -> String {
    "unknown".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ScanMetadata {
    pub roots: Vec<String>,
    pub max_depth: Option<usize>,
    pub excludes: Vec<String>,
    pub dedupe: bool,
    pub dedupe_min_size: u64,
    pub dry_run: bool,
    #[serde(default)]
    pub backend: ScanBackendKind,
    #[serde(default)]
    pub progress: bool,
    #[serde(default)]
    pub min_ratio: Option<f32>,
    #[serde(default)]
    pub emit_progress_events: bool,
    #[serde(default = "default_progress_interval_ms")]
    pub progress_interval_ms: u64,
}

fn default_progress_interval_ms() -> u64 {
    250
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ScanBackendKind {
    #[default]
    Native,
    #[serde(alias = "pdu")]
    PduLibrary,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct ScanMetrics {
    #[serde(default)]
    pub backend: ScanBackendKind,
    #[serde(default)]
    pub elapsed_ms: u64,
    #[serde(default)]
    pub scanned_roots: u64,
    #[serde(default)]
    pub scanned_files: u64,
    #[serde(default)]
    pub scanned_directories: u64,
    #[serde(default)]
    pub scanned_bytes: u64,
    #[serde(default)]
    pub permission_denied_warnings: u64,
    #[serde(default)]
    pub contradiction_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct ScanProgressSummary {
    #[serde(default)]
    pub total_events: u64,
    #[serde(default)]
    pub phase_counts: Vec<ScanPhaseCount>,
    #[serde(default)]
    pub completed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ScanPhaseCount {
    pub phase: ScanPhase,
    pub events: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ScanProgressEvent {
    pub seq: u64,
    pub scan_id: String,
    pub phase: ScanPhase,
    pub current_path: Option<String>,
    pub scanned_files: u64,
    pub scanned_bytes: u64,
    pub errors: u64,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ScanPhase {
    EnumeratingDisks,
    WalkingFiles,
    Categorizing,
    Dedupe,
    Analyzing,
    Recommending,
    Done,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct BackendParity {
    #[serde(default)]
    pub native_elapsed_ms: u64,
    #[serde(default)]
    pub pdu_library_elapsed_ms: u64,
    #[serde(default)]
    pub scanned_files_delta: i64,
    #[serde(default)]
    pub scanned_bytes_delta: i64,
    #[serde(default)]
    pub tolerance_ratio: f32,
    #[serde(default)]
    pub within_tolerance: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DiskInfo {
    pub name: String,
    pub mount_point: String,
    pub total_space_bytes: u64,
    pub free_space_bytes: u64,
    pub disk_kind: DiskKind,
    pub file_system: Option<String>,
    #[serde(default)]
    pub storage_type: DiskStorageType,
    #[serde(default)]
    pub locality_class: LocalityClass,
    #[serde(default)]
    pub locality_confidence: f32,
    #[serde(default)]
    pub locality_rationale: String,
    #[serde(default)]
    pub is_os_drive: bool,
    #[serde(default)]
    pub is_removable: bool,
    #[serde(default)]
    pub vendor: Option<String>,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub interface: Option<String>,
    #[serde(default)]
    pub rotational: Option<bool>,
    #[serde(default)]
    pub hybrid: Option<bool>,
    #[serde(default)]
    pub performance_class: PerformanceClass,
    #[serde(default)]
    pub performance_confidence: f32,
    #[serde(default)]
    pub performance_rationale: String,
    #[serde(default)]
    pub eligible_for_local_target: bool,
    #[serde(default)]
    pub ineligible_reasons: Vec<String>,
    #[serde(default)]
    pub metadata_notes: Vec<String>,
    #[serde(default)]
    pub role_hint: DiskRoleHint,
    #[serde(default)]
    pub target_role_eligibility: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DiskKind {
    Ssd,
    Hdd,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum DiskStorageType {
    Hdd,
    Ssd,
    Nvme,
    Usb,
    Network,
    Virtual,
    CloudBacked,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum LocalityClass {
    LocalPhysical,
    LocalVirtual,
    Network,
    CloudBacked,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum PerformanceClass {
    Fast,
    Balanced,
    Slow,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum DiskRole {
    ActiveWorkload,
    GamesLibrary,
    MediaLibrary,
    BackupTarget,
    Archive,
    Mixed,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DiskRoleHint {
    #[serde(default)]
    pub role: DiskRole,
    #[serde(default)]
    pub confidence: f32,
    #[serde(default)]
    pub evidence: Vec<String>,
}

impl Default for DiskRoleHint {
    fn default() -> Self {
        Self {
            role: DiskRole::Unknown,
            confidence: 0.0,
            evidence: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PathStats {
    pub root_path: String,
    pub disk_mount: Option<String>,
    pub total_size_bytes: u64,
    pub file_count: u64,
    pub directory_count: u64,
    pub largest_files: LargestFiles,
    pub largest_directories: Vec<DirectoryUsage>,
    pub file_type_summary: FileTypeSummary,
    pub activity: ActivitySignals,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LargestFiles {
    pub entries: Vec<FileEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FileEntry {
    pub path: String,
    pub size_bytes: u64,
    pub modified: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DirectoryUsage {
    pub path: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FileTypeSummary {
    pub top_extensions: Vec<ExtensionUsage>,
    pub other_files: u64,
    pub other_bytes: u64,
    pub total_files: u64,
    pub total_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExtensionUsage {
    pub extension: String,
    pub files: u64,
    pub bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ActivitySignals {
    pub recent_files: u64,
    pub stale_files: u64,
    pub unknown_modified_files: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DuplicateGroup {
    pub size_bytes: u64,
    pub hash: String,
    pub files: Vec<DuplicateFile>,
    pub total_wasted_bytes: u64,
    pub intent: DuplicateIntent,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DuplicateFile {
    pub path: String,
    pub disk_mount: Option<String>,
    pub modified: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DuplicateIntent {
    pub label: DuplicateIntentLabel,
    pub rationale: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DuplicateIntentLabel {
    LikelyIntentional,
    LikelyRedundant,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CategorySuggestion {
    pub target: String,
    pub disk_mount: Option<String>,
    pub category: Category,
    pub confidence: f32,
    pub rationale: String,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    Backup,
    Games,
    Work,
    Media,
    Archive,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Recommendation {
    pub id: String,
    pub title: String,
    pub rationale: String,
    #[serde(default = "default_recommendation_confidence")]
    pub confidence: f32,
    #[serde(default)]
    pub target_mount: Option<String>,
    #[serde(default = "default_policy_safe")]
    pub policy_safe: bool,
    #[serde(default)]
    pub policy_rules_applied: Vec<String>,
    #[serde(default)]
    pub policy_rules_blocked: Vec<String>,
    #[serde(default)]
    pub evidence: Vec<RecommendationEvidence>,
    #[serde(default)]
    pub next_steps: Vec<String>,
    pub estimated_impact: EstimatedImpact,
    pub risk_level: RiskLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RecommendationEvidence {
    #[serde(default)]
    pub kind: RecommendationEvidenceKind,
    pub label: String,
    pub detail: String,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub mount_point: Option<String>,
    #[serde(default)]
    pub duplicate_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum RecommendationEvidenceKind {
    Disk,
    Directory,
    DuplicateGroup,
    HistoryDelta,
    Warning,
    #[default]
    Other,
}

fn default_recommendation_confidence() -> f32 {
    0.5
}

fn default_policy_safe() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EstimatedImpact {
    pub space_saving_bytes: Option<u64>,
    pub performance: Option<String>,
    pub risk_notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PolicyDecision {
    pub policy_id: String,
    pub recommendation_id: String,
    pub action: PolicyAction,
    pub rationale: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum PolicyAction {
    #[default]
    Allowed,
    Blocked,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuleTrace {
    pub rule_id: String,
    pub status: RuleTraceStatus,
    pub detail: String,
    pub recommendation_id: Option<String>,
    pub confidence: Option<f32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum RuleTraceStatus {
    Emitted,
    #[default]
    Skipped,
    Rejected,
}

// A collection of historical snapshots.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct ScanHistory {
    pub snapshots: Vec<ScanSnapshot>,
}

// A summary of a scan at a point in time, for historical trend analysis.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ScanSnapshot {
    pub scan_id: String,
    pub generated_at: String,
    pub disks: Vec<DiskSnapshot>,
    pub paths: Vec<PathSnapshot>,
}

// A snapshot of a disk's state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DiskSnapshot {
    pub mount_point: String,
    pub total_space_bytes: u64,
    pub free_space_bytes: u64,
}

// A snapshot of a scanned path's state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PathSnapshot {
    pub root_path: String,
    pub total_size_bytes: u64,
    pub file_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReportSummary {
    pub scan_id: String,
    pub generated_at: String,
    pub report_version: String,
    #[serde(default)]
    pub roots: Vec<String>,
    #[serde(default)]
    pub backend: ScanBackendKind,
    #[serde(default)]
    pub warnings_count: u64,
    #[serde(default)]
    pub recommendation_count: u64,
    pub stored_report_path: String,
    #[serde(default)]
    pub source_path: Option<String>,
    #[serde(default)]
    pub imported: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReportImportResult {
    pub summary: ReportSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReportDiff {
    pub left_scan_id: String,
    pub right_scan_id: String,
    pub left_generated_at: String,
    pub right_generated_at: String,
    #[serde(default)]
    pub duplicate_wasted_bytes_delta: i64,
    #[serde(default)]
    pub disk_diffs: Vec<DiskDiff>,
    #[serde(default)]
    pub path_diffs: Vec<PathDiff>,
    #[serde(default)]
    pub recommendation_changes: Vec<RecommendationChange>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DiskDiff {
    pub mount_point: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub left_free_space_bytes: Option<u64>,
    #[serde(default)]
    pub right_free_space_bytes: Option<u64>,
    pub free_space_delta_bytes: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PathDiff {
    pub root_path: String,
    #[serde(default)]
    pub left_total_size_bytes: Option<u64>,
    #[serde(default)]
    pub right_total_size_bytes: Option<u64>,
    pub total_size_delta_bytes: i64,
    #[serde(default)]
    pub left_file_count: Option<u64>,
    #[serde(default)]
    pub right_file_count: Option<u64>,
    pub file_count_delta: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RecommendationChangeKind {
    Added,
    Removed,
    ConfidenceChanged,
    TargetChanged,
    RiskChanged,
    RationaleChanged,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RecommendationChange {
    pub id: String,
    pub change: RecommendationChangeKind,
    #[serde(default)]
    pub left_confidence: Option<f32>,
    #[serde(default)]
    pub right_confidence: Option<f32>,
    #[serde(default)]
    pub left_target_mount: Option<String>,
    #[serde(default)]
    pub right_target_mount: Option<String>,
    #[serde(default)]
    pub left_risk_level: Option<RiskLevel>,
    #[serde(default)]
    pub right_risk_level: Option<RiskLevel>,
}
