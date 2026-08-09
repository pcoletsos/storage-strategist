# Architecture Notes (v1.3)

## Goals

- Local-first storage analysis with strict read-only guarantees.
- Explainable recommendations with explicit policy allow/block traces.
- Stable report schema for CLI, service, and desktop UI consumers.
- Cross-platform best-effort scanning with graceful error continuation.

## Workspace Topology

- `crates/core`
  - scanner backends (`native`, `pdu_library`)
  - incremental scan cache (key/signature/TTL best-effort path)
  - device/disk enrichment
  - categorization + disk role inference
  - duplicate detection
  - recommendation rules + policy invariants
  - scenario planner (read-only what-if projections)
  - diagnostics bundle generator
  - report schema (`report_version` currently `1.3.0`)
  - evaluator + markdown rendering + doctor diagnostics
- `crates/cli`
  - user-facing commands: `scan`, `recommend`, `doctor`, `eval`, `benchmark`, `parity`
- `crates/service`
  - application facade for UI/API-style usage
  - scan sessions + event polling + cancellation hooks
- `apps/desktop`
  - Tauri 2 + React read-only review UI
  - guided setup, progress view, results workbench, doctor view

## Scanner and Backend Design

`ScanBackend` abstraction in `crates/core/src/scan.rs`:
- `NativeBackend`: walkdir-based traversal and aggregation.
- `PduLibraryBackend`: integrates `parallel-disk-usage` tree summaries via `FsTreeBuilder`, while retaining detailed native file-level stats for category/dedupe/recommendation pipeline.
- Incremental cache (optional via `ScanOptions.incremental_cache`):
  - cache key hashes roots + scan-shaping options + backend/report version
  - cache hit requires matching root signatures and TTL window
  - cache IO failures are downgraded to warnings and never fail the scan

Backend parity support:
- `compare_backends(options)` returns timing, absolute counters, and delta metrics in `BackendParity`.
- `crates/core/src/parity.rs` materializes a fixed catalogue of synthetic tree shapes into a caller-supplied scratch workspace and compares both backends on each shape.
- Used by CLI `parity` / `parity --suite`, the `parity_test` integration test, and the `backend parity` CI job.

Known accounting differences between the backends:
- `parallel-disk-usage` totals every entry it visits; the native sum counts regular files only.
- `directory_entry_bytes`: apparent size of non-root directory entries (the root is already subtracted in `build_pdu_tree_summary`).
- `symlink_entry_bytes`: apparent size of symlink entries, which the native walker skips.
- Both are measured explicitly so a known difference cannot masquerade as a traversal regression.

Parity gate definition (enforced in CI):
- primary signal: `normalized_scanned_bytes_delta`, the residual after removing both accounting terms
- hard limits: `scanned_files_delta == 0`, `normalized_scanned_bytes_delta == 0`, residual ratio at most `0.005`
- `pdu_summary_applied` must be true, so a silent fallback to the native walker fails instead of passing
- gate script: `scripts/check_parity_thresholds.py`; artifact uploads on failure
- promotion criteria: `docs/backend-promotion-checkpoint.md`

## Event and Session Model

Schema types:
- `ScanProgressEvent`
- `ScanPhase`
- `ScanProgressSummary`

Flow:
1. scan emits phase/counter events
2. service stores events per `scan_id`
3. UI/clients poll events (`from_seq`) and session state

Service session states:
- `running`, `completed`, `cancelled`, `failed`

## Recommendation Safety Stack

Rule engine (`recommend.rs`) produces candidate recommendations.
Policy engine (`policy.rs`) enforces non-negotiable constraints:
- target eligibility constraints (cloud/network/virtual/OS exclusions)
- contradiction filtering
- role-aware target policy (blocks active placement onto media/archive/backup role targets)

Recommendation objects include:
- `policy_rules_applied`
- `policy_rules_blocked`
- `policy_safe`

## Disk Intelligence and Role Inference

`DiskInfo` contains:
- locality classification (`local_physical`, `local_virtual`, `network`, `cloud_backed`, `unknown`)
- storage/performance hints + confidence/rationale
- destination eligibility and ineligible reasons
- inferred role hint (`DiskRoleHint`) and target role eligibility

Role inference combines:
- disk label/model signals
- aggregated category scores

OS-specific enrichment providers:
- Windows: best-effort WMI (`Win32_DiskDrive` + partition/logical mapping) hints for model/vendor/interface/rotational signals
- Linux: best-effort `lsblk -J` hints for mount-linked model/vendor/transport/rotational signals
- When provider data is unavailable, heuristics remain the fallback and scan continues without failure

## Report Schema Evolution Strategy

- `report_version` is semantic and additive by default.
- New fields are serde-defaulted where possible to preserve backwards loading.
- v1.3 additive fields include:
  - `scan_id`
  - `scan_progress_summary`
  - `backend_parity`
  - disk role fields
  - recommendation policy rule fields
- `BackendParity` additive fields for the parity gate (all serde-defaulted):
  - `native_scanned_files`, `native_scanned_bytes`
  - `pdu_library_scanned_files`, `pdu_library_scanned_bytes`
  - `pdu_summary_applied`
  - `directory_entry_bytes`, `symlink_entry_bytes`
  - `normalized_scanned_bytes_delta`

## UI Architecture (Read-Only)

`apps/desktop` stages:
- setup (guided path selection first)
- scanning (events/counters/warnings)
- results tabs
- doctor diagnostics

UI constraints:
- no move/delete/rename actions
- advisory wording only
- unsafe destination classes visually represented and excluded by policy
- scenario planner and diagnostics export remain read-only support tooling

## Reliability and Error Handling

- traversal errors are converted to warnings and scanning continues.
- permission-denied events are counted in scan metrics.
- symlink traversal disabled by default to avoid loops.
- cancellation is best-effort and cooperative via shared atomic flag.

## CI and Governance

- `CONTRIBUTING.md`: canonical issue-first branch/PR/merge contract
- `.github/workflows/contribution-guardrails.yml`: PR guardrail check for branch naming, Conventional Commit titles, linked issues, and milestone-backed issues
- `.github/workflows/ci.yml`: `Contribution guardrails` + fmt + clippy (`-D warnings`) + tests + compliance checks + desktop smoke tests
- `.github/workflows/bench.yml`: benchmark run + regression threshold check (15%)
- `.github/workflows/desktop-package.yml`: manual desktop packaging matrix (Windows/macOS/Linux) with optional signing env support
- Evaluation KPI definitions (`crates/core/src/eval.rs`):
  - `precision_at_3`: top-3 recommendation hit ratio against case `expected_top_ids`, averaged over suite cases
  - `contradiction_rate`: fraction of cases with `contradiction_count > 0`
  - `unsafe_recommendations`: emitted recommendation count where `policy_safe == false`
- KPI threshold enforcement script: `scripts/check_eval_kpi_thresholds.py`
- AGPL/provenance governance:
  - `THIRD_PARTY_NOTICES.md`
  - `CODE_IMPORT_POLICY.md`
  - `provenance/imported_code.json`
