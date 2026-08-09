# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, and this project adheres to Semantic Versioning.

## [Unreleased]

### Added
- AGPL compliance framework:
  - `THIRD_PARTY_NOTICES.md`
  - `CODE_IMPORT_POLICY.md`
  - `provenance/imported_code.json`
  - `scripts/check_compliance.py`
- CI workflow with quality and compliance gates.
- Scanner backend abstraction with `native` and `pdu`-compatible modes.
- Pseudo/system mount filtering for auto-discovered roots.
- Report schema additions:
  - scan backend/progress/min_ratio
  - `scan_metrics`
  - recommendation `target_mount` and `policy_safe`
  - `policy_decisions`
  - `rule_traces`
- Policy invariant module to block unsafe recommendation targets.
- Fixture evaluator command (`eval`) and benchmark command (`benchmark`).
- Service crate (`crates/service`) with scan session/event APIs.
- `scan_id`, `scan_progress_summary`, and backend parity metadata in report schema.
- Disk role inference (`DiskRole`, `DiskRoleHint`) and role-based target eligibility fields.
- Recommendation policy rule tracking fields:
  - `policy_rules_applied`
  - `policy_rules_blocked`
- Role-aware recommendation safety policy (blocks active-placement into media/archive/backup roles).
- CLI backend parity command (`parity`).
- Desktop UI scaffold (`apps/desktop`) using Tauri + React (read-only).
- Benchmark regression workflow (`.github/workflows/bench.yml`) and threshold script (`scripts/check_benchmark_regression.py`).
- Benchmark baseline fixture (`fixtures/benchmark-baseline.json`).
- Evaluation KPI threshold gate script (`scripts/check_eval_kpi_thresholds.py`) and CI job.
- Expanded evaluation suite fixtures for active workload and OS-headroom/cloud scenarios.
- OS-specific device metadata enrichers:
  - Windows WMI bridge for model/vendor/interface/rotational hints.
  - Linux `lsblk` bridge for model/vendor/transport/rotational hints.
- Incremental scan cache with key/signature/TTL checks and warning-safe persistence.
- Scenario planner module with conservative/balanced/aggressive read-only projections.
- Diagnostics bundle generator/export path (report + doctor + environment metadata).
- Service and Tauri APIs:
  - `plan_scenarios_from_report`
  - `export_diagnostics_bundle`
- CLI commands:
  - `plan`
  - `diagnostics`
- Desktop UI updates:
  - `Scenarios` results tab
  - diagnostics bundle export action
- Backend parity suite (`crates/core/src/parity.rs`) covering flat, deep, wide, empty,
  mixed-size, unicode, hidden, and symlink tree shapes.
- `parity --suite` CLI mode with declared tolerances and a JSON artifact.
- Backend parity CI gate (`scripts/check_parity_thresholds.py`) that fails on
  file-count or residual byte drift and uploads `parity-result.json` on failure.
- Default backend promotion checkpoint (`docs/backend-promotion-checkpoint.md`).
- `BackendParity` additive fields: absolute per-backend counters,
  `pdu_summary_applied`, `directory_entry_bytes`, `symlink_entry_bytes`, and
  `normalized_scanned_bytes_delta`.

### Changed
- Repository license migrated to `AGPL-3.0-or-later`.
- Report schema version bumped to `1.2.0` with additive fields.
- Report schema version bumped to `1.3.0` with additive fields for scan sessions, parity, and role metadata.
- Recommendation engine now returns traceable bundle output before policy enforcement.
- README/ARCHITECTURE/ROADMAP updated for AGPL workflow and new commands.
- CLI backend naming standardized to `pdu_library` (`pdu` alias supported).
- Desktop packaging workflow expanded to Windows/macOS/Linux matrix with optional signing env wiring.
- Tauri bundle config enabled for packaging builds.

### Fixed
- Recommendation dedup/contradiction handling now blocks duplicate recommendation IDs.
- Cloud-backed target safety enforcement is now explicit in policy decisions.
