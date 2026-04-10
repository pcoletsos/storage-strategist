use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Instant, UNIX_EPOCH};

use anyhow::{anyhow, Result};
use chrono::{DateTime, Duration, SecondsFormat, Utc};
use globset::{Glob, GlobSet, GlobSetBuilder};
use serde::{Deserialize, Serialize};
use sysinfo::{DiskKind as SysDiskKind, Disks};
use tracing::info;
use uuid::Uuid;
use walkdir::WalkDir;

use crate::analyzers::AnalyzerContext;
use crate::categorize::{aggregate_categories_by_disk, categorize_disks, categorize_paths};
use crate::dedupe::{find_duplicates, FileRecord};
use crate::device::{enrich_disks, DiskProbe};
use crate::history;
use crate::model::{
    ActivitySignals, BackendParity, DirectoryUsage, DiskInfo, DiskKind, ExtensionUsage, FileEntry,
    FileTypeSummary, LargestFiles, PathStats, Report, ScanBackendKind, ScanMetadata, ScanMetrics,
    ScanPhase, ScanPhaseCount, ScanProgressEvent, ScanProgressSummary, REPORT_VERSION,
};
use crate::recommend::generate_recommendation_bundle_with_context;
use crate::role::infer_disk_roles;

#[cfg(feature = "pdu-backend")]
use parallel_disk_usage::{
    fs_tree_builder::FsTreeBuilder,
    get_size::GetApparentSize,
    hardlink::HardlinkIgnorant,
    os_string_display::OsStringDisplay,
    reporter::{ErrorOnlyReporter, ErrorReport},
    size::Bytes,
};

const PDU_INSPIRED_BANNED_AUTO_ROOTS: &[&str] = &[
    "/dev", "/proc", "/sys", "/run", "/mnt", "/media", "/cdrom", "/Volumes", "/System",
];
const CACHE_SCHEMA_VERSION: u32 = 1;
const CACHE_DIR_NAME: &str = "storage-strategist-cache";
const DEFAULT_CACHE_TTL_SECONDS: u64 = 900;

#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub paths: Vec<PathBuf>,
    pub max_depth: Option<usize>,
    pub excludes: Vec<String>,
    pub dedupe: bool,
    pub dedupe_min_size: u64,
    pub dry_run: bool,
    pub largest_files_limit: usize,
    pub largest_directories_limit: usize,
    pub top_extensions_limit: usize,
    pub backend: ScanBackendKind,
    pub progress: bool,
    pub min_ratio: Option<f32>,
    pub scan_id: Option<String>,
    pub emit_progress_events: bool,
    pub progress_interval_ms: u64,
    pub incremental_cache: bool,
    pub cache_dir: Option<PathBuf>,
    pub cache_ttl_seconds: u64,
    pub record_history: bool,
    pub report_store_dir: Option<PathBuf>,
    pub cancel_flag: Option<Arc<AtomicBool>>,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            paths: Vec::new(),
            max_depth: None,
            excludes: Vec::new(),
            dedupe: false,
            dedupe_min_size: 1_048_576,
            dry_run: true,
            largest_files_limit: 20,
            largest_directories_limit: 10,
            top_extensions_limit: 12,
            backend: ScanBackendKind::Native,
            progress: false,
            min_ratio: None,
            scan_id: None,
            emit_progress_events: false,
            progress_interval_ms: 250,
            incremental_cache: false,
            cache_dir: None,
            cache_ttl_seconds: DEFAULT_CACHE_TTL_SECONDS,
            record_history: true,
            report_store_dir: None,
            cancel_flag: None,
        }
    }
}

#[derive(Debug, Serialize)]
struct ScanCacheKey {
    roots: Vec<String>,
    max_depth: Option<usize>,
    excludes: Vec<String>,
    dedupe: bool,
    dedupe_min_size: u64,
    backend: ScanBackendKind,
    min_ratio: Option<f32>,
    largest_files_limit: usize,
    largest_directories_limit: usize,
    top_extensions_limit: usize,
    report_version: String,
    cache_schema_version: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ScanCacheEntry {
    schema_version: u32,
    key: String,
    created_at: String,
    root_signatures: Vec<CacheRootSignature>,
    report: Report,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct CacheRootSignature {
    path: String,
    exists: bool,
    modified_unix_secs: Option<i64>,
}

#[derive(Debug, Clone)]
struct BackendProgress {
    current_path: String,
    scanned_files: u64,
    scanned_bytes: u64,
    errors: u64,
}

trait ScanBackend {
    fn kind(&self) -> ScanBackendKind;

    fn scan(
        &self,
        roots: &[PathBuf],
        disks: &[DiskInfo],
        excludes: &ExcludeMatcher,
        options: &ScanOptions,
        warnings: &mut Vec<String>,
        on_progress: &mut dyn FnMut(BackendProgress),
    ) -> Result<BackendScanOutput>;
}

#[derive(Default, Debug, Clone)]
struct BackendCounters {
    scanned_files: u64,
    scanned_directories: u64,
    scanned_bytes: u64,
}

struct BackendScanOutput {
    paths: Vec<PathStats>,
    files: Vec<FileRecord>,
    counters: BackendCounters,
}

struct NativeBackend;

impl ScanBackend for NativeBackend {
    fn kind(&self) -> ScanBackendKind {
        ScanBackendKind::Native
    }

    fn scan(
        &self,
        roots: &[PathBuf],
        disks: &[DiskInfo],
        excludes: &ExcludeMatcher,
        options: &ScanOptions,
        warnings: &mut Vec<String>,
        on_progress: &mut dyn FnMut(BackendProgress),
    ) -> Result<BackendScanOutput> {
        let mut output = BackendScanOutput {
            paths: Vec::new(),
            files: Vec::new(),
            counters: BackendCounters::default(),
        };

        for (index, root) in roots.iter().enumerate() {
            if is_cancelled(options) {
                warnings.push("scan canceled by caller".to_string());
                break;
            }

            match scan_root(root, disks, excludes, options, warnings, None, None) {
                Ok(result) => {
                    output.counters.scanned_files = output
                        .counters
                        .scanned_files
                        .saturating_add(result.scanned_files);
                    output.counters.scanned_directories = output
                        .counters
                        .scanned_directories
                        .saturating_add(result.scanned_directories);
                    output.counters.scanned_bytes = output
                        .counters
                        .scanned_bytes
                        .saturating_add(result.scanned_bytes);
                    output.files.extend(result.files);
                    output.paths.push(result.stats);

                    on_progress(BackendProgress {
                        current_path: root.to_string_lossy().to_string(),
                        scanned_files: output.counters.scanned_files,
                        scanned_bytes: output.counters.scanned_bytes,
                        errors: warnings.len() as u64,
                    });

                    if options.progress {
                        info!(
                            "scan progress: root {}/{} complete ({})",
                            index + 1,
                            roots.len(),
                            root.display()
                        );
                    }
                }
                Err(err) => warnings.push(format!("scan failed for {}: {}", root.display(), err)),
            }
        }

        Ok(output)
    }
}

struct PduLibraryBackend;
impl ScanBackend for PduLibraryBackend {
    fn kind(&self) -> ScanBackendKind {
        ScanBackendKind::PduLibrary
    }

    fn scan(
        &self,
        roots: &[PathBuf],
        disks: &[DiskInfo],
        excludes: &ExcludeMatcher,
        options: &ScanOptions,
        warnings: &mut Vec<String>,
        on_progress: &mut dyn FnMut(BackendProgress),
    ) -> Result<BackendScanOutput> {
        if !options.excludes.is_empty() {
            warnings.push(
                "pdu_library backend does not currently apply exclude patterns; falling back to native backend for correctness."
                    .to_string(),
            );
            let native = NativeBackend;
            return native.scan(roots, disks, excludes, options, warnings, on_progress);
        }

        #[cfg(not(feature = "pdu-backend"))]
        {
            warnings.push(
                "pdu_library backend unavailable in this build; falling back to native backend."
                    .to_string(),
            );
            let native = NativeBackend;
            return native.scan(roots, disks, excludes, options, warnings, on_progress);
        }

        #[cfg(feature = "pdu-backend")]
        {
            let mut output = BackendScanOutput {
                paths: Vec::new(),
                files: Vec::new(),
                counters: BackendCounters::default(),
            };

            for root in roots {
                if is_cancelled(options) {
                    warnings.push("scan canceled by caller".to_string());
                    break;
                }

                let (pdu_total, pdu_largest) = match build_pdu_tree_summary(root, options) {
                    Ok(v) => v,
                    Err(err) => {
                        warnings.push(format!(
                            "pdu_library scan summary failed for {}: {}; using native root summary",
                            root.display(),
                            err
                        ));
                        (None, None)
                    }
                };

                match scan_root(
                    root,
                    disks,
                    excludes,
                    options,
                    warnings,
                    pdu_largest,
                    pdu_total,
                ) {
                    Ok(result) => {
                        output.counters.scanned_files = output
                            .counters
                            .scanned_files
                            .saturating_add(result.scanned_files);
                        output.counters.scanned_directories = output
                            .counters
                            .scanned_directories
                            .saturating_add(result.scanned_directories);
                        output.counters.scanned_bytes = output
                            .counters
                            .scanned_bytes
                            .saturating_add(result.scanned_bytes);
                        output.files.extend(result.files);
                        output.paths.push(result.stats);

                        on_progress(BackendProgress {
                            current_path: root.to_string_lossy().to_string(),
                            scanned_files: output.counters.scanned_files,
                            scanned_bytes: output.counters.scanned_bytes,
                            errors: warnings.len() as u64,
                        });
                    }
                    Err(err) => {
                        warnings.push(format!("scan failed for {}: {}", root.display(), err))
                    }
                }
            }

            Ok(output)
        }
    }
}

struct RootScanResult {
    stats: PathStats,
    files: Vec<FileRecord>,
    scanned_files: u64,
    scanned_directories: u64,
    scanned_bytes: u64,
}

pub struct ScanRunOutput {
    pub report: Report,
    pub events: Vec<ScanProgressEvent>,
}

pub fn run_scan(options: &ScanOptions) -> Result<Report> {
    run_scan_with_callback(options, |_| {})
}

pub fn run_scan_with_events(options: &ScanOptions) -> Result<ScanRunOutput> {
    let mut events = Vec::new();
    let report = run_scan_with_callback(options, |event| events.push(event))?;
    Ok(ScanRunOutput { report, events })
}

pub fn run_scan_with_callback<F>(options: &ScanOptions, mut on_event: F) -> Result<Report>
where
    F: FnMut(ScanProgressEvent),
{
    validate_scan_options(options)?;
    let started = Instant::now();
    let scan_id = options
        .scan_id
        .clone()
        .unwrap_or_else(|| Uuid::new_v4().to_string());

    let mut warnings = Vec::new();
    let mut total_events = 0_u64;
    let mut phase_counts: HashMap<ScanPhase, u64> = HashMap::new();

    emit_scan_event(
        options,
        &mut on_event,
        &scan_id,
        &mut total_events,
        &mut phase_counts,
        ScanPhase::EnumeratingDisks,
        None,
        0,
        0,
        0,
    );

    let mut disks = enumerate_disks();
    let roots = resolve_roots(options, &disks, &mut warnings)?;
    let excludes = ExcludeMatcher::new(&options.excludes, &mut warnings);

    if let Some(mut cached_report) =
        try_load_cached_report(options, &scan_id, &roots, &mut warnings, started.elapsed())
    {
        emit_scan_event(
            options,
            &mut on_event,
            &scan_id,
            &mut total_events,
            &mut phase_counts,
            ScanPhase::Done,
            None,
            cached_report.scan_metrics.scanned_files,
            cached_report.scan_metrics.scanned_bytes,
            cached_report.warnings.len() as u64,
        );

        cached_report.scan_progress_summary = ScanProgressSummary {
            total_events,
            phase_counts: phase_counts
                .iter()
                .map(|(phase, events)| ScanPhaseCount {
                    phase: phase.clone(),
                    events: *events,
                })
                .collect(),
            completed: true,
        };
        return Ok(cached_report);
    }

    emit_scan_event(
        options,
        &mut on_event,
        &scan_id,
        &mut total_events,
        &mut phase_counts,
        ScanPhase::WalkingFiles,
        None,
        0,
        0,
        warnings.len() as u64,
    );

    let backend: Box<dyn ScanBackend> = match options.backend {
        ScanBackendKind::Native => Box::new(NativeBackend),
        ScanBackendKind::PduLibrary => Box::new(PduLibraryBackend),
    };

    let (backend_output, categories, duplicates) = {
        let mut progress_hook = |progress: BackendProgress| {
            emit_scan_event(
                options,
                &mut on_event,
                &scan_id,
                &mut total_events,
                &mut phase_counts,
                ScanPhase::WalkingFiles,
                Some(progress.current_path),
                progress.scanned_files,
                progress.scanned_bytes,
                progress.errors,
            );
        };

        let backend_output = backend.scan(
            &roots,
            &disks,
            &excludes,
            options,
            &mut warnings,
            &mut progress_hook,
        )?;

        emit_scan_event(
            options,
            &mut on_event,
            &scan_id,
            &mut total_events,
            &mut phase_counts,
            ScanPhase::Categorizing,
            None,
            backend_output.counters.scanned_files,
            backend_output.counters.scanned_bytes,
            warnings.len() as u64,
        );

        let mut categories = categorize_paths(&backend_output.paths);
        categories.extend(categorize_disks(&disks));
        categories.extend(aggregate_categories_by_disk(&categories));
        infer_disk_roles(&mut disks, &categories);

        emit_scan_event(
            options,
            &mut on_event,
            &scan_id,
            &mut total_events,
            &mut phase_counts,
            ScanPhase::Dedupe,
            None,
            backend_output.counters.scanned_files,
            backend_output.counters.scanned_bytes,
            warnings.len() as u64,
        );

        let duplicates = if options.dedupe {
            find_duplicates(
                &backend_output.files,
                options.dedupe_min_size,
                &mut warnings,
            )
        } else {
            Vec::new()
        };

        (backend_output, categories, duplicates)
    };

    emit_scan_event(
        options,
        &mut on_event,
        &scan_id,
        &mut total_events,
        &mut phase_counts,
        ScanPhase::Analyzing,
        None,
        backend_output.counters.scanned_files,
        backend_output.counters.scanned_bytes,
        warnings.len() as u64,
    );

    let scan = ScanMetadata {
        roots: roots
            .iter()
            .map(|path| path.to_string_lossy().to_string())
            .collect(),
        max_depth: options.max_depth,
        excludes: options.excludes.clone(),
        dedupe: options.dedupe,
        dedupe_min_size: options.dedupe_min_size,
        dry_run: options.dry_run,
        backend: backend.kind(),
        progress: options.progress,
        min_ratio: options.min_ratio,
        emit_progress_events: options.emit_progress_events,
        progress_interval_ms: options.progress_interval_ms,
    };

    emit_scan_event(
        options,
        &mut on_event,
        &scan_id,
        &mut total_events,
        &mut phase_counts,
        ScanPhase::Recommending,
        None,
        backend_output.counters.scanned_files,
        backend_output.counters.scanned_bytes,
        warnings.len() as u64,
    );

    let mut report = Report {
        report_version: REPORT_VERSION.to_string(),
        generated_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        scan_id: scan_id.clone(),
        scan,
        scan_metrics: ScanMetrics {
            backend: backend.kind(),
            elapsed_ms: started.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
            scanned_roots: roots.len() as u64,
            scanned_files: backend_output.counters.scanned_files,
            scanned_directories: backend_output.counters.scanned_directories,
            scanned_bytes: backend_output.counters.scanned_bytes,
            permission_denied_warnings: 0,
            contradiction_count: 0,
        },
        scan_progress_summary: ScanProgressSummary::default(),
        backend_parity: None,
        disks,
        paths: backend_output.paths,
        categories,
        duplicates,
        recommendations: Vec::new(),
        policy_decisions: Vec::new(),
        rule_traces: Vec::new(),
        warnings,
    };

    // Run general recommendations
    let recommendation_bundle = generate_recommendation_bundle_with_context(
        &report,
        &AnalyzerContext {
            report_store_dir: options.report_store_dir.clone(),
        },
    );
    report.recommendations = recommendation_bundle.recommendations;
    report.policy_decisions = recommendation_bundle.policy_decisions;
    report.rule_traces = recommendation_bundle.rule_traces;
    report.scan_metrics.contradiction_count = recommendation_bundle.contradiction_count;

    report.scan_metrics.permission_denied_warnings = report
        .warnings
        .iter()
        .filter(|warning| warning.to_lowercase().contains("permission"))
        .count() as u64;

    emit_scan_event(
        options,
        &mut on_event,
        &scan_id,
        &mut total_events,
        &mut phase_counts,
        ScanPhase::Done,
        None,
        report.scan_metrics.scanned_files,
        report.scan_metrics.scanned_bytes,
        report.warnings.len() as u64,
    );

    report.scan_progress_summary = ScanProgressSummary {
        total_events,
        phase_counts: phase_counts
            .iter()
            .map(|(phase, events)| ScanPhaseCount {
                phase: phase.clone(),
                events: *events,
            })
            .collect(),
        completed: true,
    };

    persist_cached_report(options, &roots, &mut report);

    if options.record_history {
        if let Err(err) = append_scan_to_history(&report, options.report_store_dir.as_deref()) {
            append_warning_once(
                &mut report.warnings,
                format!("Failed to append scan to history: {}", err),
            );
        }
    }

    Ok(report)
}

fn append_scan_to_history(report: &Report, report_store_dir: Option<&Path>) -> Result<()> {
    let mut history = history::load_history(report_store_dir)?;

    let snapshot = crate::model::ScanSnapshot {
        scan_id: report.scan_id.clone(),
        generated_at: report.generated_at.clone(),
        disks: report
            .disks
            .iter()
            .map(|d| crate::model::DiskSnapshot {
                mount_point: d.mount_point.clone(),
                total_space_bytes: d.total_space_bytes,
                free_space_bytes: d.free_space_bytes,
            })
            .collect(),
        paths: report
            .paths
            .iter()
            .map(|p| crate::model::PathSnapshot {
                root_path: p.root_path.clone(),
                total_size_bytes: p.total_size_bytes,
                file_count: p.file_count,
            })
            .collect(),
    };

    history.snapshots.push(snapshot);
    history::save_history(&history, report_store_dir)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn emit_scan_event<F>(
    options: &ScanOptions,
    on_event: &mut F,
    scan_id: &str,
    total_events: &mut u64,
    phase_counts: &mut HashMap<ScanPhase, u64>,
    phase: ScanPhase,
    current_path: Option<String>,
    scanned_files: u64,
    scanned_bytes: u64,
    errors: u64,
) where
    F: FnMut(ScanProgressEvent),
{
    *total_events = total_events.saturating_add(1);
    *phase_counts.entry(phase.clone()).or_insert(0) += 1;

    if options.emit_progress_events {
        on_event(ScanProgressEvent {
            seq: *total_events,
            scan_id: scan_id.to_string(),
            phase,
            current_path,
            scanned_files,
            scanned_bytes,
            errors,
            timestamp: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        });
    }
}

pub fn compare_backends(options: &ScanOptions) -> Result<BackendParity> {
    let mut native = options.clone();
    native.backend = ScanBackendKind::Native;
    native.emit_progress_events = false;
    native.record_history = false;

    let mut pdu = options.clone();
    pdu.backend = ScanBackendKind::PduLibrary;
    pdu.emit_progress_events = false;
    pdu.record_history = false;

    let native_report = run_scan(&native)?;
    let pdu_report = run_scan(&pdu)?;

    let scanned_files_delta = pdu_report.scan_metrics.scanned_files as i64
        - native_report.scan_metrics.scanned_files as i64;
    let scanned_bytes_delta = pdu_report.scan_metrics.scanned_bytes as i64
        - native_report.scan_metrics.scanned_bytes as i64;

    let denom = native_report.scan_metrics.scanned_bytes.max(1) as f64;
    let ratio = (scanned_bytes_delta.unsigned_abs() as f64 / denom) as f32;
    let tolerance_ratio = 0.05;

    Ok(BackendParity {
        native_elapsed_ms: native_report.scan_metrics.elapsed_ms,
        pdu_library_elapsed_ms: pdu_report.scan_metrics.elapsed_ms,
        scanned_files_delta,
        scanned_bytes_delta,
        tolerance_ratio,
        within_tolerance: ratio <= tolerance_ratio,
    })
}

fn resolve_roots(
    options: &ScanOptions,
    disks: &[DiskInfo],
    warnings: &mut Vec<String>,
) -> Result<Vec<PathBuf>> {
    let raw_roots = if options.paths.is_empty() {
        disks
            .iter()
            .map(|disk| PathBuf::from(&disk.mount_point))
            .collect::<Vec<_>>()
    } else {
        options.paths.clone()
    };

    let mut roots = Vec::new();
    let mut seen = HashSet::new();
    for root in raw_roots {
        let key = root.to_string_lossy().to_lowercase();
        if !seen.insert(key) {
            continue;
        }

        if options.paths.is_empty() && should_skip_auto_root(&root) {
            warnings.push(format!(
                "auto-root skipped by pseudo/system mount filter: {}",
                root.display()
            ));
            continue;
        }
        if !root.exists() {
            warnings.push(format!("scan root not found: {}", root.display()));
            continue;
        }
        roots.push(root);
    }

    if roots.is_empty() {
        return Err(anyhow!(
            "no valid scan roots were resolved. Provide --paths or ensure disks are mounted."
        ));
    }
    Ok(roots)
}

fn should_skip_auto_root(path: &Path) -> bool {
    let normalized = path.to_string_lossy().replace('\\', "/");
    PDU_INSPIRED_BANNED_AUTO_ROOTS
        .iter()
        .any(|prefix| normalized == *prefix || normalized.starts_with(&format!("{prefix}/")))
}

fn scan_root(
    root: &Path,
    disks: &[DiskInfo],
    excludes: &ExcludeMatcher,
    options: &ScanOptions,
    warnings: &mut Vec<String>,
    largest_directories_override: Option<Vec<DirectoryUsage>>,
    total_size_override: Option<u64>,
) -> Result<RootScanResult> {
    let mut file_count = 0_u64;
    let mut directory_count = 0_u64;
    let mut total_size_bytes = 0_u64;
    let mut top_file_types: HashMap<String, (u64, u64)> = HashMap::new();
    let mut top_directory_sizes: HashMap<String, u64> = HashMap::new();
    let mut largest_files: Vec<FileEntry> = Vec::new();
    let mut files: Vec<FileRecord> = Vec::new();
    let disk_mount = match_disk_mount(root, disks);

    let now = Utc::now();
    let recent_cutoff = now - Duration::days(90);
    let stale_cutoff = now - Duration::days(365 * 2);
    let mut activity = ActivitySignals {
        recent_files: 0,
        stale_files: 0,
        unknown_modified_files: 0,
    };

    let mut walker = WalkDir::new(root).follow_links(false);
    if let Some(depth) = options.max_depth {
        walker = walker.max_depth(depth);
    }
    let iter = walker.into_iter().filter_entry(|entry| {
        if entry.depth() == 0 {
            return true;
        }
        !excludes.is_excluded(entry.path())
    });

    for item in iter {
        if is_cancelled(options) {
            warnings.push(format!(
                "scan canceled while walking {}; report contains partial data",
                root.display()
            ));
            break;
        }

        let entry = match item {
            Ok(entry) => entry,
            Err(err) => {
                warnings.push(format!("walk error under {}: {}", root.display(), err));
                continue;
            }
        };
        if entry.depth() == 0 {
            continue;
        }
        if entry.file_type().is_dir() {
            directory_count += 1;
            continue;
        }
        if !entry.file_type().is_file() {
            continue;
        }

        let metadata = match entry.metadata() {
            Ok(metadata) => metadata,
            Err(err) => {
                warnings.push(format!(
                    "metadata read failed for {}: {}",
                    entry.path().display(),
                    err
                ));
                continue;
            }
        };

        let size_bytes = metadata.len();
        let path = entry.path();
        file_count += 1;
        total_size_bytes = total_size_bytes.saturating_add(size_bytes);

        let modified_dt = metadata.modified().ok().map(DateTime::<Utc>::from);
        let modified_text = modified_dt.map(|time| time.to_rfc3339_opts(SecondsFormat::Secs, true));
        match modified_dt {
            Some(time) if time >= recent_cutoff => activity.recent_files += 1,
            Some(time) if time <= stale_cutoff => activity.stale_files += 1,
            Some(_) => {}
            None => activity.unknown_modified_files += 1,
        }

        let extension = path
            .extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| ext.to_lowercase())
            .unwrap_or_else(|| "none".to_string());
        let type_entry = top_file_types.entry(extension).or_insert((0, 0));
        type_entry.0 += 1;
        type_entry.1 = type_entry.1.saturating_add(size_bytes);

        update_largest_files(
            &mut largest_files,
            options.largest_files_limit,
            FileEntry {
                path: path.to_string_lossy().to_string(),
                size_bytes,
                modified: modified_text.clone(),
            },
        );

        if let Ok(relative) = path.strip_prefix(root) {
            let mut components = relative.components();
            if let Some(first) = components.next() {
                if components.next().is_some() {
                    let bucket = root.join(first.as_os_str()).to_string_lossy().to_string();
                    let current = top_directory_sizes.entry(bucket).or_insert(0);
                    *current = current.saturating_add(size_bytes);
                }
            }
        }

        files.push(FileRecord {
            path: path.to_path_buf(),
            size_bytes,
            disk_mount: disk_mount.clone(),
            modified: modified_text,
        });
    }

    let file_type_summary = finalize_type_summary(
        top_file_types,
        options.top_extensions_limit,
        file_count,
        total_size_bytes,
    );
    let largest_directories = largest_directories_override.unwrap_or_else(|| {
        finalize_largest_directories(top_directory_sizes, options.largest_directories_limit)
    });

    if let Some(override_total) = total_size_override {
        total_size_bytes = override_total;
    }

    Ok(RootScanResult {
        stats: PathStats {
            root_path: root.to_string_lossy().to_string(),
            disk_mount,
            total_size_bytes,
            file_count,
            directory_count,
            largest_files: LargestFiles {
                entries: largest_files,
            },
            largest_directories,
            file_type_summary,
            activity,
        },
        files,
        scanned_files: file_count,
        scanned_directories: directory_count,
        scanned_bytes: total_size_bytes,
    })
}

#[cfg(feature = "pdu-backend")]
fn build_pdu_tree_summary(
    root: &Path,
    options: &ScanOptions,
) -> Result<(Option<u64>, Option<Vec<DirectoryUsage>>)> {
    let reporter = ErrorOnlyReporter::new(ErrorReport::SILENT);
    let tree: parallel_disk_usage::data_tree::DataTree<OsStringDisplay, Bytes> = FsTreeBuilder {
        root: root.to_path_buf(),
        size_getter: GetApparentSize,
        hardlinks_recorder: &HardlinkIgnorant,
        reporter: &reporter,
        max_depth: options
            .max_depth
            .map(|depth| depth as u64)
            .unwrap_or(u64::MAX),
    }
    .into();

    let mut largest_directories = tree
        .children()
        .iter()
        .map(|child| DirectoryUsage {
            path: root
                .join(child.name().as_os_str())
                .to_string_lossy()
                .to_string(),
            size_bytes: child.size().into(),
        })
        .collect::<Vec<_>>();
    largest_directories.sort_by(|a, b| {
        b.size_bytes
            .cmp(&a.size_bytes)
            .then_with(|| a.path.cmp(&b.path))
    });
    largest_directories.truncate(options.largest_directories_limit);

    // The native walker reports the sum of file sizes only. The PDU tree summary
    // includes the root directory entry size on some platforms, which creates a
    // stable one-directory delta (commonly 4096 bytes on Linux) in parity checks.
    let root_directory_size = fs::metadata(root)
        .ok()
        .filter(|metadata| metadata.is_dir())
        .map(|metadata| metadata.len())
        .unwrap_or(0);
    let total_size: u64 = tree.size().into();
    let normalized_total_size = total_size.saturating_sub(root_directory_size);

    Ok((Some(normalized_total_size), Some(largest_directories)))
}

#[cfg(not(feature = "pdu-backend"))]
fn build_pdu_tree_summary(
    _root: &Path,
    _options: &ScanOptions,
) -> Result<(Option<u64>, Option<Vec<DirectoryUsage>>)> {
    Err(anyhow!("pdu-backend feature not enabled"))
}

fn update_largest_files(current: &mut Vec<FileEntry>, limit: usize, candidate: FileEntry) {
    if limit == 0 {
        return;
    }
    current.push(candidate);
    current.sort_by(|a, b| {
        b.size_bytes
            .cmp(&a.size_bytes)
            .then_with(|| a.path.cmp(&b.path))
    });
    current.truncate(limit);
}

fn finalize_largest_directories(map: HashMap<String, u64>, limit: usize) -> Vec<DirectoryUsage> {
    let mut values = map
        .into_iter()
        .map(|(path, size_bytes)| DirectoryUsage { path, size_bytes })
        .collect::<Vec<_>>();
    values.sort_by(|a, b| {
        b.size_bytes
            .cmp(&a.size_bytes)
            .then_with(|| a.path.cmp(&b.path))
    });
    values.truncate(limit);
    values
}

fn finalize_type_summary(
    map: HashMap<String, (u64, u64)>,
    limit: usize,
    total_files: u64,
    total_bytes: u64,
) -> FileTypeSummary {
    let mut extensions = map
        .into_iter()
        .map(|(extension, (files, bytes))| ExtensionUsage {
            extension,
            files,
            bytes,
        })
        .collect::<Vec<_>>();
    extensions.sort_by(|a, b| {
        b.bytes
            .cmp(&a.bytes)
            .then_with(|| a.extension.cmp(&b.extension))
    });
    let mut top_extensions = extensions;
    top_extensions.truncate(limit);

    let top_files = top_extensions.iter().map(|item| item.files).sum::<u64>();
    let top_bytes = top_extensions.iter().map(|item| item.bytes).sum::<u64>();

    FileTypeSummary {
        top_extensions,
        other_files: total_files.saturating_sub(top_files),
        other_bytes: total_bytes.saturating_sub(top_bytes),
        total_files,
        total_bytes,
    }
}

fn match_disk_mount(path: &Path, disks: &[DiskInfo]) -> Option<String> {
    let mut best: Option<(&DiskInfo, usize)> = None;
    for disk in disks {
        let mount = Path::new(&disk.mount_point);
        if !path.starts_with(mount) {
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

fn enumerate_disks() -> Vec<DiskInfo> {
    let disks = Disks::new_with_refreshed_list();
    let probes = disks
        .list()
        .iter()
        .map(|disk| {
            let disk_kind = match disk.kind() {
                SysDiskKind::HDD => DiskKind::Hdd,
                SysDiskKind::SSD => DiskKind::Ssd,
                _ => DiskKind::Unknown,
            };

            DiskProbe {
                name: disk.name().to_string_lossy().to_string(),
                mount_point: disk.mount_point().to_string_lossy().to_string(),
                total_space_bytes: disk.total_space(),
                free_space_bytes: disk.available_space(),
                disk_kind,
                file_system: Some(disk.file_system().to_string_lossy().to_string()),
                is_removable: disk.is_removable(),
            }
        })
        .collect::<Vec<_>>();
    enrich_disks(probes)
}

struct ExcludeMatcher {
    globset: Option<GlobSet>,
    substrings: Vec<String>,
}

impl ExcludeMatcher {
    fn new(patterns: &[String], warnings: &mut Vec<String>) -> Self {
        if patterns.is_empty() {
            return Self {
                globset: None,
                substrings: Vec::new(),
            };
        }

        let mut builder = GlobSetBuilder::new();
        let mut substrings = Vec::new();
        for pattern in patterns {
            let pattern = pattern.trim();
            if pattern.is_empty() {
                continue;
            }

            if is_plain_substring_pattern(pattern) {
                substrings.push(pattern.to_lowercase());
                continue;
            }

            match Glob::new(pattern) {
                Ok(glob) => {
                    builder.add(glob);
                }
                Err(err) => {
                    warnings.push(format!(
                        "invalid exclude glob '{pattern}': {err}; using substring fallback."
                    ));
                    substrings.push(pattern.to_lowercase());
                }
            }
        }

        let globset = match builder.build() {
            Ok(set) => Some(set),
            Err(err) => {
                warnings.push(format!(
                    "failed to compile exclude glob set: {err}; glob excludes disabled."
                ));
                None
            }
        };

        Self {
            globset,
            substrings,
        }
    }

    fn is_excluded(&self, path: &Path) -> bool {
        if let Some(globset) = &self.globset {
            if globset.is_match(path) {
                return true;
            }
        }

        if self.substrings.is_empty() {
            return false;
        }

        let lowered = path.to_string_lossy().to_lowercase();
        self.substrings
            .iter()
            .any(|pattern| lowered.contains(pattern))
    }
}

fn is_plain_substring_pattern(pattern: &str) -> bool {
    !pattern
        .chars()
        .any(|ch| matches!(ch, '*' | '?' | '[' | ']' | '{' | '}'))
}

fn validate_scan_options(options: &ScanOptions) -> Result<()> {
    if let Some(min_ratio) = options.min_ratio {
        if !(0.0..=1.0).contains(&min_ratio) {
            return Err(anyhow!("min_ratio must be between 0.0 and 1.0"));
        }
    }
    if options.progress_interval_ms == 0 {
        return Err(anyhow!("progress_interval_ms must be greater than zero"));
    }
    if options.incremental_cache && options.cache_ttl_seconds == 0 {
        return Err(anyhow!(
            "cache_ttl_seconds must be greater than zero when incremental_cache is enabled"
        ));
    }
    Ok(())
}

fn is_cancelled(options: &ScanOptions) -> bool {
    options
        .cancel_flag
        .as_ref()
        .is_some_and(|flag| flag.load(Ordering::Relaxed))
}

fn try_load_cached_report(
    options: &ScanOptions,
    scan_id: &str,
    roots: &[PathBuf],
    pending_warnings: &mut Vec<String>,
    elapsed: std::time::Duration,
) -> Option<Report> {
    if !options.incremental_cache {
        return None;
    }

    let cache_key = match build_scan_cache_key(roots, options) {
        Ok(value) => value,
        Err(err) => {
            pending_warnings.push(format!("cache key generation failed: {err}"));
            return None;
        }
    };
    let cache_path = scan_cache_path(options, &cache_key);

    let payload = match fs::read_to_string(&cache_path) {
        Ok(value) => value,
        Err(err) => {
            if err.kind() != std::io::ErrorKind::NotFound {
                pending_warnings.push(format!(
                    "incremental cache read failed for {}: {}",
                    cache_path.display(),
                    err
                ));
            }
            return None;
        }
    };

    let entry: ScanCacheEntry = match serde_json::from_str(&payload) {
        Ok(value) => value,
        Err(err) => {
            pending_warnings.push(format!(
                "incremental cache payload invalid for {}: {}",
                cache_path.display(),
                err
            ));
            return None;
        }
    };

    if entry.schema_version != CACHE_SCHEMA_VERSION || entry.key != cache_key {
        return None;
    }

    let created_at = match DateTime::parse_from_rfc3339(&entry.created_at) {
        Ok(value) => value.with_timezone(&Utc),
        Err(err) => {
            pending_warnings.push(format!(
                "incremental cache timestamp parse failed for {}: {}",
                cache_path.display(),
                err
            ));
            return None;
        }
    };
    let age_seconds = Utc::now()
        .signed_duration_since(created_at)
        .num_seconds()
        .max(0) as u64;
    if age_seconds > options.cache_ttl_seconds {
        return None;
    }

    let current_signatures = collect_root_signatures(roots, pending_warnings);
    if current_signatures != entry.root_signatures {
        return None;
    }

    let mut report = entry.report;
    report.scan_id = scan_id.to_string();
    report.generated_at = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
    report.scan.roots = roots
        .iter()
        .map(|path| path.to_string_lossy().to_string())
        .collect();
    report.scan.max_depth = options.max_depth;
    report.scan.excludes = options.excludes.clone();
    report.scan.dedupe = options.dedupe;
    report.scan.dedupe_min_size = options.dedupe_min_size;
    report.scan.dry_run = options.dry_run;
    report.scan.backend = options.backend.clone();
    report.scan.progress = options.progress;
    report.scan.min_ratio = options.min_ratio;
    report.scan.emit_progress_events = options.emit_progress_events;
    report.scan.progress_interval_ms = options.progress_interval_ms;
    report.scan_metrics.backend = options.backend.clone();
    report.scan_metrics.elapsed_ms = elapsed.as_millis().try_into().unwrap_or(u64::MAX);
    report.scan_metrics.scanned_roots = roots.len() as u64;
    merge_warnings(&mut report.warnings, pending_warnings);
    append_warning_once(
        &mut report.warnings,
        format!(
            "scan result loaded from incremental cache: {}",
            cache_path.display()
        ),
    );

    Some(report)
}

fn persist_cached_report(options: &ScanOptions, roots: &[PathBuf], report: &mut Report) {
    if !options.incremental_cache {
        return;
    }
    if report
        .warnings
        .iter()
        .any(|warning| warning.to_lowercase().contains("scan canceled"))
    {
        return;
    }

    let cache_key = match build_scan_cache_key(roots, options) {
        Ok(value) => value,
        Err(err) => {
            append_warning_once(
                &mut report.warnings,
                format!("cache key generation failed: {err}"),
            );
            return;
        }
    };

    let root_signatures = collect_root_signatures(roots, &mut report.warnings);
    let cache_path = scan_cache_path(options, &cache_key);
    let cache_entry = ScanCacheEntry {
        schema_version: CACHE_SCHEMA_VERSION,
        key: cache_key,
        created_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        root_signatures,
        report: report.clone(),
    };

    if let Err(err) = fs::create_dir_all(scan_cache_dir(options)) {
        append_warning_once(
            &mut report.warnings,
            format!(
                "incremental cache directory create failed for {}: {}",
                cache_path.display(),
                err
            ),
        );
        return;
    }

    let payload = match serde_json::to_string(&cache_entry) {
        Ok(value) => value,
        Err(err) => {
            append_warning_once(
                &mut report.warnings,
                format!("incremental cache serialization failed: {err}"),
            );
            return;
        }
    };

    if let Err(err) = fs::write(&cache_path, payload) {
        append_warning_once(
            &mut report.warnings,
            format!(
                "incremental cache write failed for {}: {}",
                cache_path.display(),
                err
            ),
        );
    }
}

fn build_scan_cache_key(roots: &[PathBuf], options: &ScanOptions) -> Result<String> {
    let key = ScanCacheKey {
        roots: roots
            .iter()
            .map(|root| normalize_cache_path(root.as_path()))
            .collect(),
        max_depth: options.max_depth,
        excludes: options.excludes.clone(),
        dedupe: options.dedupe,
        dedupe_min_size: options.dedupe_min_size,
        backend: options.backend.clone(),
        min_ratio: options.min_ratio,
        largest_files_limit: options.largest_files_limit,
        largest_directories_limit: options.largest_directories_limit,
        top_extensions_limit: options.top_extensions_limit,
        report_version: REPORT_VERSION.to_string(),
        cache_schema_version: CACHE_SCHEMA_VERSION,
    };
    let payload = serde_json::to_vec(&key)?;
    Ok(blake3::hash(&payload).to_hex().to_string())
}

fn scan_cache_dir(options: &ScanOptions) -> PathBuf {
    options
        .cache_dir
        .clone()
        .unwrap_or_else(|| std::env::temp_dir().join(CACHE_DIR_NAME))
}

fn scan_cache_path(options: &ScanOptions, cache_key: &str) -> PathBuf {
    scan_cache_dir(options).join(format!("{cache_key}.json"))
}

fn collect_root_signatures(
    roots: &[PathBuf],
    warnings: &mut Vec<String>,
) -> Vec<CacheRootSignature> {
    let mut signatures = Vec::with_capacity(roots.len());
    for root in roots {
        match fs::metadata(root) {
            Ok(metadata) => {
                let modified_unix_secs = metadata
                    .modified()
                    .ok()
                    .and_then(|value| value.duration_since(UNIX_EPOCH).ok())
                    .and_then(|duration| i64::try_from(duration.as_secs()).ok());
                signatures.push(CacheRootSignature {
                    path: normalize_cache_path(root.as_path()),
                    exists: true,
                    modified_unix_secs,
                });
            }
            Err(err) => {
                append_warning_once(
                    warnings,
                    format!(
                        "cache signature probe failed for {}: {}",
                        root.display(),
                        err
                    ),
                );
                signatures.push(CacheRootSignature {
                    path: normalize_cache_path(root.as_path()),
                    exists: false,
                    modified_unix_secs: None,
                });
            }
        }
    }
    signatures
}

fn merge_warnings(target: &mut Vec<String>, source: &[String]) {
    for warning in source {
        append_warning_once(target, warning.clone());
    }
}

fn append_warning_once(target: &mut Vec<String>, warning: String) {
    if !target.iter().any(|value| value == &warning) {
        target.push(warning);
    }
}

fn normalize_cache_path(path: &Path) -> String {
    #[cfg(windows)]
    {
        path.to_string_lossy().replace('\\', "/").to_lowercase()
    }
    #[cfg(not(windows))]
    {
        path.to_string_lossy().replace('\\', "/")
    }
}

#[cfg(test)]
mod tests {
    use super::{
        run_scan, should_skip_auto_root, validate_scan_options, ExcludeMatcher, ScanOptions,
    };
    use std::fs;
    use std::path::Path;
    use std::thread;
    use std::time::Duration;
    use tempfile::tempdir;

    #[test]
    fn exclude_matcher_matches_glob_and_substring() {
        let mut warnings = Vec::new();
        let matcher = ExcludeMatcher::new(
            &[
                "**/*.tmp".to_string(),
                "[".to_string(),
                "node_modules".to_string(),
            ],
            &mut warnings,
        );

        assert!(matcher.is_excluded(Path::new("C:/repo/a.tmp")));
        assert!(matcher.is_excluded(Path::new("C:/repo/node_modules/pkg/index.js")));
        assert!(!matcher.is_excluded(Path::new("C:/repo/src/main.rs")));
        assert!(!warnings.is_empty());
    }

    #[test]
    fn auto_root_filter_skips_pseudo_mounts() {
        assert!(should_skip_auto_root(Path::new("/proc")));
        assert!(should_skip_auto_root(Path::new("/sys/kernel")));
        assert!(!should_skip_auto_root(Path::new("C:/Users")));
    }

    #[test]
    fn validates_min_ratio_bounds() {
        let options = ScanOptions {
            min_ratio: Some(1.2),
            record_history: false,
            ..ScanOptions::default()
        };
        assert!(validate_scan_options(&options).is_err());
    }

    #[test]
    fn validates_cache_ttl_when_incremental_cache_enabled() {
        let options = ScanOptions {
            incremental_cache: true,
            cache_ttl_seconds: 0,
            record_history: false,
            ..ScanOptions::default()
        };
        assert!(validate_scan_options(&options).is_err());
    }

    #[test]
    fn incremental_cache_hits_on_second_run() {
        let root = tempdir().expect("temp root");
        let cache_dir = tempdir().expect("cache root");
        fs::write(root.path().join("a.bin"), vec![42_u8; 1024]).expect("seed file");

        let options = ScanOptions {
            paths: vec![root.path().to_path_buf()],
            max_depth: Some(4),
            incremental_cache: true,
            cache_dir: Some(cache_dir.path().to_path_buf()),
            cache_ttl_seconds: 900,
            record_history: false,
            ..ScanOptions::default()
        };

        let first = run_scan(&options).expect("first scan succeeds");
        assert!(!first
            .warnings
            .iter()
            .any(|warning| warning.contains("incremental cache")));

        let second = run_scan(&options).expect("second scan succeeds");
        assert!(second
            .warnings
            .iter()
            .any(|warning| warning.contains("scan result loaded from incremental cache")));
        assert_eq!(
            first.scan_metrics.scanned_files,
            second.scan_metrics.scanned_files
        );
    }

    #[test]
    fn incremental_cache_misses_when_root_signature_changes() {
        let root = tempdir().expect("temp root");
        let cache_dir = tempdir().expect("cache root");
        fs::write(root.path().join("a.bin"), vec![7_u8; 512]).expect("seed file");

        let options = ScanOptions {
            paths: vec![root.path().to_path_buf()],
            max_depth: Some(4),
            incremental_cache: true,
            cache_dir: Some(cache_dir.path().to_path_buf()),
            cache_ttl_seconds: 900,
            record_history: false,
            ..ScanOptions::default()
        };

        let first = run_scan(&options).expect("first scan succeeds");
        thread::sleep(Duration::from_secs(1));
        fs::write(root.path().join("b.bin"), vec![9_u8; 256]).expect("change root");

        let second = run_scan(&options).expect("second scan succeeds");
        assert!(!second
            .warnings
            .iter()
            .any(|warning| warning.contains("scan result loaded from incremental cache")));
        assert!(second.scan_metrics.scanned_files > first.scan_metrics.scanned_files);
    }
}
