# storage-strategist

`storage-strategist` is a local-first, read-only storage analysis toolchain:
- CLI (`crates/cli`)
- core analysis engine (`crates/core`)
- app/service facade (`crates/service`)
- desktop review UI scaffold (`apps/desktop`, Tauri + React)

## License

This project is licensed under **AGPL-3.0-or-later**.
See `LICENSE`, `THIRD_PARTY_NOTICES.md`, and `CODE_IMPORT_POLICY.md`.

## Contribution Workflow

Use `CONTRIBUTING.md` for the canonical issue-first, branch, PR, and merge
workflow. `DEVELOPMENT.md` has the local setup and validation commands.

## v1 Safety Model

- Read-only scanning and analysis only.
- No delete/move/rename/modify operations on user files.
- No runtime network calls from the scanning/recommendation engine.
- Permission/metadata errors are recorded as warnings; scan continues best-effort.
- Cloud/network/virtual mounts are analyzed but excluded as local optimization targets.

## Workspace Layout

- `crates/core`: scanning, device intelligence, categorization, dedupe, recommendations, policy, schema.
- `crates/cli`: `storage-strategist` binary.
- `crates/service`: scan sessions/events/report/recommend facade for GUI consumers.
- `apps/desktop`: Tauri + React read-only review UI scaffold.
- `fixtures`: synthetic report/eval/benchmark fixtures.

## Build and Quality

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
python scripts/check_compliance.py
```

## CLI Usage

```bash
cargo run -p storage-strategist -- scan --paths "D:\\" "G:\\" --output storage-strategist-report.json --backend native --dedupe --incremental-cache --cache-ttl-seconds 900
cargo run -p storage-strategist -- recommend --report storage-strategist-report.json --md summary.md
cargo run -p storage-strategist -- doctor
cargo run -p storage-strategist -- eval --suite fixtures/eval-suite.json --output eval-result.json
cargo run -p storage-strategist -- benchmark --paths fixtures --max-depth 3 --iterations 2 --output benchmark-result.json
cargo run -p storage-strategist -- parity --paths fixtures --max-depth 3
cargo run -p storage-strategist -- plan --report storage-strategist-report.json --output scenario-plan.json
cargo run -p storage-strategist -- diagnostics --report storage-strategist-report.json --output storage-strategist-diagnostics.json
cargo run -p storage-strategist -- reports list
cargo run -p storage-strategist -- reports import --path storage-strategist-report.json
cargo run -p storage-strategist -- reports show --scan-id <scan-id>
cargo run -p storage-strategist -- reports diff --left <scan-id> --right <scan-id> --output report-diff.json
```

Backend values:
- `native`
- `pdu_library` (also accepts `pdu` alias)

## Report Highlights

Report schema version: `1.3.0`

Includes:
- disk inventory and enrichment (storage/locality/performance/OS flags)
- disk role hints (`active_workload`, `games_library`, `media_library`, etc.)
- per-root usage summaries
- duplicate groups (`size -> hash -> files`) with intent guess
- recommendations with policy decisions and rule traces
- scan progress summary + backend parity metadata

## Desktop UI (Read-Only)

Scaffold lives in `apps/desktop`.

Key screens:
- Setup (guided path selection first)
- Scanning (phase/counters/event feed)
- Results tabs (`Disks`, `Usage`, `Categories`, `Duplicates`, `Scenarios`, `Recommendations`, `Rule Trace`)
- Doctor diagnostics
- Diagnostics bundle export action from Results

Run locally:

```bash
cd apps/desktop
npm install
npm run tauri dev
```

## CI

- `.github/workflows/ci.yml`
  - `Contribution guardrails`
  - `fmt`
  - `clippy`
  - `test`
  - compliance checks
  - desktop smoke tests (`apps/desktop`, Playwright)
- evaluation KPI gate (`precision@3`, contradiction rate, unsafe recommendations)
- `.github/workflows/bench.yml`
  - benchmark run
  - regression gate via `scripts/check_benchmark_regression.py` (15% threshold)
- `.github/workflows/desktop-package.yml`
  - manual desktop packaging build job (Windows/macOS/Linux matrix)
  - optional signing when `TAURI_SIGNING_PRIVATE_KEY` secrets are configured

## Parity and KPI Gate Definitions

- Backend parity gate (tracked for CI hardening):
  - source: `compare_backends(...)` parity metadata (`scanned_files_delta`, `scanned_bytes_delta`, `tolerance_ratio`, `within_tolerance`)
  - intent: fail when backend output drift exceeds configured tolerance on fixture scans
- Evaluation KPI gates (tracked for CI hardening):
  - `precision_at_3`: per-case hit ratio among top 3 recommendation IDs against `expected_top_ids`, averaged across suite cases
  - `contradiction_rate`: fraction of suite cases where `contradiction_count > 0`
  - `unsafe_recommendations`: count of emitted recommendations with `policy_safe == false`
  - source: `storage-strategist eval` / `crates/core/src/eval.rs`
  - CI gate script: `scripts/check_eval_kpi_thresholds.py`

## Incremental Cache and Planning

- Incremental cache:
  - enable with `scan --incremental-cache`
  - cache key covers roots/options/backend and is validated by root signatures + TTL
  - IO failures are warning-only and never abort scans
- Scenario planner:
  - `plan` command emits conservative/balanced/aggressive read-only what-if projections
  - projections sum `estimated_impact.space_saving_bytes` for included policy-safe recommendations
- Diagnostics bundle:
  - `diagnostics` command exports report + doctor snapshot + environment metadata for support workflows
- Local report store:
  - completed scans are also indexed into a local report library keyed by `scan_id`
  - `reports list|import|show|diff` expose saved-report and compare workflows for CLI users
  - desktop uses the same store for reopen/import/compare flows

## Notes on `parallel-disk-usage` Inspiration

This project now directly uses `parallel-disk-usage` as an optional backend dependency for tree summary integration and backend parity work. Additional parity/performance validation is tracked in `ROADMAP.md` before defaulting to this backend.
