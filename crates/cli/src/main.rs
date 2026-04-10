use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::ArgAction;
use clap::{Args, Parser, Subcommand, ValueEnum};
use serde::Serialize;
use storage_strategist_core::{
    build_diagnostics_bundle, build_scenario_plan, collect_doctor_info, compare_backends,
    compare_reports as compare_saved_reports, evaluate_suite_file, generate_recommendation_bundle,
    get_report as load_saved_report, import_report as import_saved_report,
    list_reports as list_saved_reports, render_markdown_summary, run_scan, store_report, Report,
    ScanBackendKind, ScanOptions,
};
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(
    name = "storage-strategist",
    version,
    about = "Analyze storage usage and produce non-destructive organization recommendations."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Scan paths/disks and emit a JSON report.
    Scan(ScanArgs),
    /// Re-run recommendation rules from an existing report.
    Recommend(RecommendArgs),
    /// Show environment and detected disk information.
    Doctor,
    /// Evaluate recommendation quality against fixture suite.
    Eval(EvalArgs),
    /// Run scan benchmark loop and emit throughput metrics.
    Benchmark(BenchmarkArgs),
    /// Compare native and pdu_library backend outputs for parity checks.
    Parity(ParityArgs),
    /// Build read-only what-if scenario projections from a report.
    Plan(PlanArgs),
    /// Export diagnostics bundle (report + doctor + environment metadata).
    Diagnostics(DiagnosticsArgs),
    /// Work with saved reports in the local report store.
    Reports(ReportsArgs),
}

#[derive(Debug, Copy, Clone, ValueEnum)]
enum CliBackendKind {
    Native,
    #[value(name = "pdu_library", alias = "pdu-library", alias = "pdu")]
    PduLibrary,
}

impl From<CliBackendKind> for ScanBackendKind {
    fn from(value: CliBackendKind) -> Self {
        match value {
            CliBackendKind::Native => ScanBackendKind::Native,
            CliBackendKind::PduLibrary => ScanBackendKind::PduLibrary,
        }
    }
}

#[derive(Debug, Args)]
struct ScanArgs {
    /// One or more root paths to scan. If omitted, all detected mount points are used.
    #[arg(long = "paths", value_name = "PATH", num_args = 1.., action = ArgAction::Append)]
    paths: Vec<PathBuf>,

    /// Output report path.
    #[arg(
        long,
        default_value = "storage-strategist-report.json",
        value_name = "FILE"
    )]
    output: PathBuf,

    /// Maximum traversal depth (root is depth 0).
    #[arg(long)]
    max_depth: Option<usize>,

    /// Exclude glob patterns (repeatable).
    #[arg(long = "exclude", value_name = "GLOB", num_args = 1.., action = ArgAction::Append)]
    exclude: Vec<String>,

    /// Enable duplicate detection.
    #[arg(long)]
    dedupe: bool,

    /// Ignore files smaller than this during dedupe.
    #[arg(long, default_value_t = 1_048_576, value_name = "BYTES")]
    dedupe_min_size: u64,

    /// Scanner backend (`native` or `pdu-library`).
    #[arg(long, default_value = "native")]
    backend: CliBackendKind,

    /// Emit progress log events while scanning.
    #[arg(long)]
    progress: bool,

    /// Optional minimum ratio filter for directory summaries (pdu-compatible behavior).
    #[arg(long)]
    min_ratio: Option<f32>,

    /// Enable incremental scan cache lookups and writes.
    #[arg(long)]
    incremental_cache: bool,

    /// Optional cache directory for incremental scan state.
    #[arg(long, value_name = "DIR")]
    cache_dir: Option<PathBuf>,

    /// Cache time-to-live in seconds when incremental cache is enabled.
    #[arg(long, default_value_t = 900, value_name = "SECONDS")]
    cache_ttl_seconds: u64,

    /// Persist scan history metadata for trend analysis.
    #[arg(long, action = ArgAction::Set, default_value_t = true)]
    record_history: bool,

    /// Optional local report store root directory.
    #[arg(long, value_name = "DIR")]
    report_store_dir: Option<PathBuf>,

    /// Forward-compatible no-op in v1 (read-only is always active).
    #[arg(long)]
    dry_run: bool,
}

#[derive(Debug, Args)]
struct RecommendArgs {
    /// Input report file.
    #[arg(long, value_name = "FILE")]
    report: PathBuf,

    /// Optional markdown summary output file.
    #[arg(long, value_name = "FILE")]
    md: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct EvalArgs {
    /// Evaluation suite JSON file.
    #[arg(long, value_name = "FILE", default_value = "fixtures/eval-suite.json")]
    suite: PathBuf,

    /// Optional JSON output file for evaluation result.
    #[arg(long, value_name = "FILE")]
    output: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct BenchmarkArgs {
    /// Paths to benchmark. If omitted, uses auto-detected mount points.
    #[arg(long = "paths", value_name = "PATH", num_args = 1.., action = ArgAction::Append)]
    paths: Vec<PathBuf>,

    /// Maximum traversal depth (root is depth 0).
    #[arg(long)]
    max_depth: Option<usize>,

    /// Iteration count.
    #[arg(long, default_value_t = 1)]
    iterations: usize,

    /// Scanner backend (`native` or `pdu-library`).
    #[arg(long, default_value = "native")]
    backend: CliBackendKind,

    /// Optional benchmark output JSON file.
    #[arg(long, value_name = "FILE")]
    output: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct ParityArgs {
    /// Paths to compare across backends. If omitted, uses auto-detected mount points.
    #[arg(long = "paths", value_name = "PATH", num_args = 1.., action = ArgAction::Append)]
    paths: Vec<PathBuf>,

    /// Maximum traversal depth (root is depth 0).
    #[arg(long)]
    max_depth: Option<usize>,

    /// Optional JSON output file for parity result.
    #[arg(long, value_name = "FILE")]
    output: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct PlanArgs {
    /// Input report file.
    #[arg(long, value_name = "FILE")]
    report: PathBuf,

    /// Optional JSON output file for scenario plan.
    #[arg(long, value_name = "FILE")]
    output: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct DiagnosticsArgs {
    /// Input report file.
    #[arg(long, value_name = "FILE")]
    report: PathBuf,

    /// Diagnostics bundle output file.
    #[arg(
        long,
        value_name = "FILE",
        default_value = "storage-strategist-diagnostics.json"
    )]
    output: PathBuf,
}

#[derive(Debug, Args)]
struct ReportsArgs {
    /// Optional local report store root directory.
    #[arg(long, value_name = "DIR")]
    store_dir: Option<PathBuf>,

    #[command(subcommand)]
    command: ReportsCommand,
}

#[derive(Debug, Subcommand)]
enum ReportsCommand {
    /// List indexed reports from the local report store.
    List,
    /// Import an existing report JSON into the local report store.
    Import(ReportsImportArgs),
    /// Show a stored report by scan id.
    Show(ReportsShowArgs),
    /// Compare two stored reports by scan id.
    Diff(ReportsDiffArgs),
}

#[derive(Debug, Args)]
struct ReportsImportArgs {
    #[arg(long, value_name = "FILE")]
    path: PathBuf,
}

#[derive(Debug, Args)]
struct ReportsShowArgs {
    #[arg(long, value_name = "SCAN_ID")]
    scan_id: String,
}

#[derive(Debug, Args)]
struct ReportsDiffArgs {
    #[arg(long, value_name = "LEFT_SCAN_ID")]
    left: String,
    #[arg(long, value_name = "RIGHT_SCAN_ID")]
    right: String,
    #[arg(long, value_name = "FILE")]
    output: Option<PathBuf>,
}

#[derive(Debug, Serialize)]
struct BenchmarkResult {
    iterations: usize,
    backend: ScanBackendKind,
    avg_elapsed_ms: f64,
    avg_files: f64,
    avg_bytes: f64,
    avg_throughput_mb_s: f64,
}

fn main() -> Result<()> {
    init_tracing();
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan(args) => run_scan_command(args),
        Commands::Recommend(args) => run_recommend_command(args),
        Commands::Doctor => {
            run_doctor_command();
            Ok(())
        }
        Commands::Eval(args) => run_eval_command(args),
        Commands::Benchmark(args) => run_benchmark_command(args),
        Commands::Parity(args) => run_parity_command(args),
        Commands::Plan(args) => run_plan_command(args),
        Commands::Diagnostics(args) => run_diagnostics_command(args),
        Commands::Reports(args) => run_reports_command(args),
    }
}

fn run_scan_command(args: ScanArgs) -> Result<()> {
    let ScanArgs {
        paths,
        output,
        max_depth,
        exclude,
        dedupe,
        dedupe_min_size,
        backend,
        progress,
        min_ratio,
        incremental_cache,
        cache_dir,
        cache_ttl_seconds,
        record_history,
        report_store_dir,
        dry_run,
    } = args;

    let options = ScanOptions {
        paths,
        max_depth,
        excludes: exclude,
        dedupe,
        dedupe_min_size,
        backend: backend.into(),
        progress,
        min_ratio,
        incremental_cache,
        cache_dir,
        cache_ttl_seconds,
        record_history,
        report_store_dir: report_store_dir.clone(),
        dry_run: true,
        ..ScanOptions::default()
    };

    let report = run_scan(&options)?;
    let payload = serde_json::to_string_pretty(&report).context("failed to serialize report")?;
    fs::write(&output, payload)
        .with_context(|| format!("failed to write report to {}", output.display()))?;
    let stored_summary = store_report(&report, report_store_dir.as_deref(), Some(&output), false)?;

    println!("Report written to {}", output.display());
    println!(
        "Stored report indexed at {}",
        stored_summary.stored_report_path
    );
    println!(
        "Scanned {} root(s), {} disk(s), {} file(s), {} warning(s).",
        report.scan.roots.len(),
        report.disks.len(),
        report.scan_metrics.scanned_files,
        report.warnings.len()
    );
    println!(
        "Backend: {:?}, elapsed: {} ms, contradictions blocked: {}.",
        report.scan_metrics.backend,
        report.scan_metrics.elapsed_ms,
        report.scan_metrics.contradiction_count
    );
    println!("v1 read-only mode active; --dry-run is implicit.");

    if dry_run {
        println!("--dry-run acknowledged.");
    }

    Ok(())
}

fn run_recommend_command(args: RecommendArgs) -> Result<()> {
    let data = fs::read_to_string(&args.report)
        .with_context(|| format!("failed to read {}", args.report.display()))?;
    let mut report: Report = serde_json::from_str(&data)
        .with_context(|| format!("failed to parse {}", args.report.display()))?;

    let bundle = generate_recommendation_bundle(&report);
    report.recommendations = bundle.recommendations.clone();
    report.rule_traces = bundle.rule_traces.clone();
    report.policy_decisions = bundle.policy_decisions.clone();

    if report.recommendations.is_empty() {
        println!(
            "No recommendations generated from {}",
            args.report.display()
        );
    } else {
        println!(
            "Generated {} recommendation(s) from {}:",
            report.recommendations.len(),
            args.report.display()
        );
        for item in &report.recommendations {
            println!(
                "- [{:?} | conf {:.2} | safe {}] {}: {}",
                item.risk_level, item.confidence, item.policy_safe, item.title, item.rationale
            );
        }
    }

    if let Some(md_path) = args.md {
        let markdown = render_markdown_summary(&report, &report.recommendations);
        fs::write(&md_path, markdown).with_context(|| {
            format!("failed to write markdown summary to {}", md_path.display())
        })?;
        println!("Markdown summary written to {}", md_path.display());
    }

    Ok(())
}

fn run_eval_command(args: EvalArgs) -> Result<()> {
    let result = evaluate_suite_file(&args.suite)?;
    println!(
        "Eval: {}/{} cases passed | precision@3 {:.3} | contradiction_rate {:.3} | unsafe {}",
        result.passed_cases,
        result.total_cases,
        result.precision_at_3,
        result.contradiction_rate,
        result.unsafe_recommendations
    );

    for case in &result.case_results {
        println!(
            "- [{}] {} | p@3 {:.3} | forbidden hits: {}",
            if case.passed { "PASS" } else { "FAIL" },
            case.name,
            case.precision_at_3,
            if case.forbidden_hits.is_empty() {
                "none".to_string()
            } else {
                case.forbidden_hits.join(", ")
            }
        );
    }

    if let Some(output) = args.output {
        let payload = serde_json::to_string_pretty(&result).context("failed to serialize eval")?;
        fs::write(&output, payload)
            .with_context(|| format!("failed to write eval output {}", output.display()))?;
        println!("Evaluation JSON written to {}", output.display());
    }

    Ok(())
}

fn run_benchmark_command(args: BenchmarkArgs) -> Result<()> {
    if args.iterations == 0 {
        anyhow::bail!("iterations must be > 0");
    }

    let mut total_elapsed = 0_u128;
    let mut total_files = 0_u128;
    let mut total_bytes = 0_u128;

    for _ in 0..args.iterations {
        let options = ScanOptions {
            paths: args.paths.clone(),
            max_depth: args.max_depth,
            excludes: Vec::new(),
            dedupe: false,
            dedupe_min_size: 1_048_576,
            backend: args.backend.into(),
            progress: false,
            min_ratio: None,
            dry_run: true,
            record_history: false,
            ..ScanOptions::default()
        };
        let report = run_scan(&options)?;
        total_elapsed = total_elapsed.saturating_add(report.scan_metrics.elapsed_ms as u128);
        total_files = total_files.saturating_add(report.scan_metrics.scanned_files as u128);
        total_bytes = total_bytes.saturating_add(report.scan_metrics.scanned_bytes as u128);
    }

    let avg_elapsed_ms = total_elapsed as f64 / args.iterations as f64;
    let avg_files = total_files as f64 / args.iterations as f64;
    let avg_bytes = total_bytes as f64 / args.iterations as f64;
    let avg_throughput_mb_s = if avg_elapsed_ms <= 0.0 {
        0.0
    } else {
        (avg_bytes / (1024.0 * 1024.0)) / (avg_elapsed_ms / 1000.0)
    };

    let result = BenchmarkResult {
        iterations: args.iterations,
        backend: args.backend.into(),
        avg_elapsed_ms,
        avg_files,
        avg_bytes,
        avg_throughput_mb_s,
    };

    println!(
        "Benchmark complete: iter={} backend={:?} avg_elapsed={:.2}ms avg_files={:.2} avg_throughput={:.2}MB/s",
        result.iterations,
        result.backend,
        result.avg_elapsed_ms,
        result.avg_files,
        result.avg_throughput_mb_s
    );

    if let Some(output) = args.output {
        let payload = serde_json::to_string_pretty(&result)
            .context("failed to serialize benchmark result")?;
        fs::write(&output, payload)
            .with_context(|| format!("failed to write benchmark output {}", output.display()))?;
        println!("Benchmark JSON written to {}", output.display());
    }

    Ok(())
}

fn run_parity_command(args: ParityArgs) -> Result<()> {
    let options = ScanOptions {
        paths: args.paths,
        max_depth: args.max_depth,
        excludes: Vec::new(),
        dedupe: false,
        dedupe_min_size: 1_048_576,
        backend: ScanBackendKind::Native,
        progress: false,
        min_ratio: None,
        dry_run: true,
        record_history: false,
        ..ScanOptions::default()
    };

    let parity = compare_backends(&options)?;
    println!(
        "Parity: within_tolerance={} tolerance={:.3} scanned_files_delta={} scanned_bytes_delta={}",
        parity.within_tolerance,
        parity.tolerance_ratio,
        parity.scanned_files_delta,
        parity.scanned_bytes_delta
    );
    println!(
        "Elapsed native={}ms pdu_library={}ms",
        parity.native_elapsed_ms, parity.pdu_library_elapsed_ms
    );

    if let Some(output) = args.output {
        let payload =
            serde_json::to_string_pretty(&parity).context("failed to serialize parity result")?;
        fs::write(&output, payload)
            .with_context(|| format!("failed to write parity output {}", output.display()))?;
        println!("Parity JSON written to {}", output.display());
    }

    Ok(())
}

fn run_plan_command(args: PlanArgs) -> Result<()> {
    let data = fs::read_to_string(&args.report)
        .with_context(|| format!("failed to read {}", args.report.display()))?;
    let mut report: Report = serde_json::from_str(&data)
        .with_context(|| format!("failed to parse {}", args.report.display()))?;

    // Keep planner output aligned with current rule engine behavior.
    let bundle = generate_recommendation_bundle(&report);
    report.recommendations = bundle.recommendations;
    report.rule_traces = bundle.rule_traces;
    report.policy_decisions = bundle.policy_decisions;

    let plan = build_scenario_plan(&report);
    println!(
        "Scenario plan generated for scan {} with {} scenario(s).",
        plan.scan_id,
        plan.scenarios.len()
    );
    for scenario in &plan.scenarios {
        println!(
            "- {} [{}] recs={} projected_space={} blocked={}",
            scenario.title,
            format!("{:?}", scenario.strategy).to_lowercase(),
            scenario.recommendation_count,
            scenario.projected_space_saving_bytes,
            scenario.blocked_recommendation_count
        );
    }

    if let Some(output) = args.output {
        let payload =
            serde_json::to_string_pretty(&plan).context("failed to serialize scenario plan")?;
        fs::write(&output, payload)
            .with_context(|| format!("failed to write plan output {}", output.display()))?;
        println!("Scenario plan JSON written to {}", output.display());
    }

    Ok(())
}

fn run_diagnostics_command(args: DiagnosticsArgs) -> Result<()> {
    let data = fs::read_to_string(&args.report)
        .with_context(|| format!("failed to read {}", args.report.display()))?;
    let report: Report = serde_json::from_str(&data)
        .with_context(|| format!("failed to parse {}", args.report.display()))?;

    let bundle = build_diagnostics_bundle(&report, Some(&args.report));
    let payload =
        serde_json::to_string_pretty(&bundle).context("failed to serialize diagnostics bundle")?;
    fs::write(&args.output, payload).with_context(|| {
        format!(
            "failed to write diagnostics bundle {}",
            args.output.display()
        )
    })?;

    println!(
        "Diagnostics bundle written to {} (scan_id={}, warnings={})",
        args.output.display(),
        bundle.report.scan_id,
        bundle.report.warnings.len()
    );

    Ok(())
}

fn run_reports_command(args: ReportsArgs) -> Result<()> {
    match args.command {
        ReportsCommand::List => {
            let reports = list_saved_reports(args.store_dir.as_deref())?;
            if reports.is_empty() {
                println!("No stored reports found.");
                return Ok(());
            }

            for report in reports {
                println!(
                    "- {} | {} | roots={} | backend={:?} | warnings={} | recommendations={} | imported={} | path={}",
                    report.scan_id,
                    report.generated_at,
                    report.roots.join(", "),
                    report.backend,
                    report.warnings_count,
                    report.recommendation_count,
                    report.imported,
                    report.stored_report_path
                );
            }
            Ok(())
        }
        ReportsCommand::Import(import_args) => {
            let result = import_saved_report(&import_args.path, args.store_dir.as_deref())?;
            println!(
                "Imported report {} into {}",
                result.summary.scan_id, result.summary.stored_report_path
            );
            Ok(())
        }
        ReportsCommand::Show(show_args) => {
            let report = load_saved_report(&show_args.scan_id, args.store_dir.as_deref())?;
            let payload =
                serde_json::to_string_pretty(&report).context("failed to serialize report")?;
            println!("{payload}");
            Ok(())
        }
        ReportsCommand::Diff(diff_args) => {
            let diff = compare_saved_reports(
                &diff_args.left,
                &diff_args.right,
                args.store_dir.as_deref(),
            )?;
            println!(
                "Diff {} -> {} | disk_changes={} path_changes={} duplicate_waste_delta={} recommendation_changes={}",
                diff.left_scan_id,
                diff.right_scan_id,
                diff.disk_diffs.len(),
                diff.path_diffs.len(),
                diff.duplicate_wasted_bytes_delta,
                diff.recommendation_changes.len()
            );
            if let Some(output) = diff_args.output {
                let payload = serde_json::to_string_pretty(&diff)
                    .context("failed to serialize report diff")?;
                fs::write(&output, payload)
                    .with_context(|| format!("failed to write diff output {}", output.display()))?;
                println!("Diff JSON written to {}", output.display());
            }
            Ok(())
        }
    }
}

fn run_doctor_command() {
    let info = collect_doctor_info();
    println!("OS: {} ({})", info.os, info.arch);
    if let Some(current_dir) = info.current_dir {
        println!("Current directory: {}", current_dir);
    }
    if let Some(os_mount) = info.os_mount {
        println!("Detected OS mount: {}", os_mount);
    }
    println!("Read-only mode: {}", info.read_only_mode);
    println!("Detected disks: {}", info.disks.len());
    for disk in info.disks {
        println!(
            "- {} [{}] total={} free={} kind={:?} type={:?} locality={:?} os={} eligible={}",
            disk.name,
            disk.mount_point,
            human_bytes(disk.total_space_bytes),
            human_bytes(disk.free_space_bytes),
            disk.disk_kind,
            disk.storage_type,
            disk.locality_class,
            disk.is_os_drive,
            disk.eligible_for_local_target
        );
        if !disk.ineligible_reasons.is_empty() {
            println!(
                "  ineligible reasons: {}",
                disk.ineligible_reasons.join(" | ")
            );
        }
    }
    for note in info.notes {
        println!("Note: {}", note);
    }
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();
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
