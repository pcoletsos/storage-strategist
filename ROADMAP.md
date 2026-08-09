# Roadmap Update Plan: PDU-Informed Core + Tauri Review UI (Read-Only)

## Summary

This roadmap track updates `storage-strategist` with concrete patterns from `F:\repos\oss\parallel-disk-usage` and adds a full desktop UI path.

Chosen defaults:
- UI shell: **Tauri + React**
- First UI release: **read-only review UI**
- Scan UX: **guided path selection first**

Key external findings from `parallel-disk-usage`:
- Mature parallel traversal and event/reporting abstractions.
- Strict JSON/schema-oriented design and compatibility handling.
- Strong quality baseline (about **98 tests**) and benchmark workflows.
- Apache-2.0 license compatible with this AGPL project.

## 90-Day Focus (UI + Core)

### P0 (Weeks 1-4)

1. [x] **PDU library backend integration (real library usage)**
   - Added `ScanBackendKind::PduLibrary`.
   - Uses `parallel-disk-usage` tree summarization APIs (`FsTreeBuilder`) with native detailed traversal fallback.
2. [x] **Scan progress/event system**
   - Added structured `ScanProgressEvent`, `ScanPhase`, `ScanProgressSummary`, and `scan_id`.
   - Added service-layer event polling with session IDs.
3. [x] **Recommendation safety hardening**
   - Added role-aware policy checks blocking active-placement recommendations into media/archive/backup targets.
4. [x] **Benchmark regression gate**
   - Added `.github/workflows/bench.yml`.
   - Added `scripts/check_benchmark_regression.py` (initial threshold 15%).
5. [x] **UI foundation (Tauri + React)**
   - Added `apps/desktop` scaffold with setup, scanning, results, and doctor screens.
6. [x] **Quality uplift (first tranche)**
   - Expanded tests around scan excludes/progress, role inference, and policy safety.

### P1 (Weeks 5-8)

7. [x] **UI results workbench depth**
   - richer recommendation inspector and policy trace views
   - duplicate/group drill-down interactions
8. [x] **Rule calibration loop**
   - fixture expansion + KPI thresholds in CI (`precision@3`, contradiction rate, unsafe target count)
9. [x] **Device intelligence providers**
   - OS-specific enrichers for model/interface/rotational confidence

### P2 (Weeks 9-12)

10. [x] **Incremental scan cache**
    - best-effort cache key/signature/TTL checks with warning-only IO failures
    - CLI/service/UI scan request support for cache controls
11. [x] **Scenario planner (read-only what-if simulation)**
    - conservative/balanced/aggressive what-if projections from policy-safe recommendations
    - CLI/service/Tauri + desktop results-tab integration
12. [x] **Release hardening**
    - installer/signing, diagnostics bundle, desktop packaging
    - diagnostics bundle export across core/service/CLI/UI
    - desktop packaging workflow expanded to Windows/macOS/Linux artifact builds

## Known Limitations

- `pdu_library` currently powers tree/summary integration and backend parity checks; full parity/perf validation still required before making it default. Promotion criteria live in `docs/backend-promotion-checkpoint.md`.
- Two known backend accounting differences remain open: `parallel-disk-usage` counts directory and symlink entry sizes that the native file-size sum omits. The parity gate measures both explicitly; they must be fixed at the source before promotion.
- UI scaffold is intentionally read-only and focuses on review/explainability.
- Hardware metadata remains best-effort on platform APIs that do not expose low-level fields.

## Important Public API / Type Changes

### Core (`crates/core`)

- `ScanOptions` additions:
  - `scan_id`, `emit_progress_events`, `progress_interval_ms`, `backend: ScanBackendKind`
  - `incremental_cache`, `cache_dir`, `cache_ttl_seconds`
- New event model:
  - `ScanProgressEvent`, `ScanPhase`, `ScanProgressSummary`
- `DiskInfo` additions:
  - `role_hint`, `target_role_eligibility`
- New role model:
  - `DiskRole`, `DiskRoleHint`
- `Report` additions:
  - `scan_id`, `scan_progress_summary`, `backend_parity`
- `Recommendation` additions:
  - `policy_rules_applied`, `policy_rules_blocked`

### Service layer (`crates/service`)

Implemented APIs:
- `start_scan(request) -> scan_id`
- `poll_scan_events(scan_id, from_seq) -> Vec<ScanProgressEvent>`
- `get_scan_session(scan_id) -> ScanSessionSnapshot`
- `cancel_scan(scan_id) -> CancelScanResponse`
- `load_report(path) -> Report`
- `generate_recommendations_from_report(report) -> RecommendationBundle`
- `plan_scenarios_from_report(report) -> ScenarioPlan`
- `export_diagnostics_bundle(report, output, source_report_path) -> DiagnosticsBundle`
- `doctor() -> DoctorInfo`

### Desktop UI (`apps/desktop`)

- Tauri command bridge wired to `crates/service`.
- React state machine:
  - `setup -> scanning -> results -> doctor`

## UI Plan (Decision Complete)

Information architecture:
1. Setup screen (guided path selection first)
2. Scanning screen (phase/events/counters + cancel)
3. Results screen tabs (`Disks`, `Usage`, `Categories`, `Duplicates`, `Recommendations`, `Rule Trace`)
   - includes `Scenarios` what-if planner tab
4. Doctor screen (diagnostics + eligibility context)

UX constraints:
- No destructive controls.
- Advisory recommendation wording only.
- Cloud/virtual/network/OS destination constraints preserved in policy/UI messaging.

## Implementation Sequence (Current)

1. [x] Add PDU dependency and implement `PduLibraryBackend`
2. [x] Add backend parity function (`compare_backends`)
3. [x] Add progress event bus + session IDs
4. [x] Add `DiskRole` inference module
5. [x] Add role-aware recommendation policy constraints
6. [x] Add benchmark CI regression gate (15% initial threshold)
7. [x] Add `crates/service`
8. [x] Scaffold Tauri + React app and connect setup/scan flow
9. [x] Expand UI recommendation inspector and trace drilldowns
10. [x] Add UI e2e smoke tests and packaging jobs
11. [x] Add incremental cache flow (`scan` cache key/signature/TTL + warning-safe persistence)
12. [x] Add scenario planner APIs and desktop `Scenarios` tab
13. [x] Add diagnostics bundle export path and multi-OS packaging workflow hardening

## Test Scenarios (Implemented + Planned)

Implemented:
- disk role classification heuristics
- policy blocking for cloud targets
- policy blocking for active-placement into media-role targets
- scan exclude matching (glob + substring fallback)
- fixture-based recommendation evaluation
- expanded evaluation fixture suite with KPI threshold gate script
- CI evaluation KPI gate (`precision@3`, contradiction rate, unsafe recommendations)
- OS-specific disk metadata hints (Windows WMI and Linux `lsblk`)
- desktop UI smoke tests for `setup -> scanning -> results -> doctor` flow (Playwright)
- incremental cache hit/miss tests for root-signature change detection
- scenario planner projection tests (risk-filtered conservative/balanced/aggressive sets)
- diagnostics bundle generation test (report + source-path embedding)

- backend parity fixture assertions (`native` vs `pdu_library`) across flat, deep, wide, empty, mixed-size, unicode, hidden, and symlink tree shapes

Planned next:
- permission continuation stress fixtures
- parity suite execution on the full OS matrix (currently Linux only in CI)

## Assumptions and Defaults

- Strictly read-only behavior across CLI/service/UI.
- Guided path selection is default UI entrypoint.
- `native` remains default scanner until parity/perf criteria are tightened.
- Performance regression threshold starts at 15% and can be tightened later.
- First UI release prioritizes trust/explainability over automation.

## Roadmap Continuation (Post-90-Day)

### P3 (Weeks 13-16)

13. [x] **Backend parity CI gate**
    - fixture-based parity suite over representative tree shapes (`parity --suite`)
    - CI fails when file-count or residual byte deltas exceed the agreed tolerances
    - `parity-result.json` uploads on failure for triage
14. [ ] **Performance promotion criteria**
    - collect multi-run baseline for `native` and `pdu_library`
    - tighten regression threshold from 15% to 10% after variance stabilizes
15. [ ] **Default backend decision checkpoint**
    - criteria documented in `docs/backend-promotion-checkpoint.md`
    - switch default to `pdu_library` only after parity + perf criteria pass on supported OS matrix
    - keep explicit `native` override as fallback through the next minor release

### P4 (Weeks 17-20)

16. [ ] **Recommendation calibration expansion**
    - add fixtures for media-heavy, game-library, mixed SSD/HDD, and cloud-backed profiles
    - persist KPI baselines for regression comparison
17. [ ] **Quality gates in CI**
    - enforce `precision@3`, contradiction rate, and unsafe-target count thresholds
    - publish evaluation artifacts on failure for quick triage
18. [ ] **UI explainability depth**
    - add recommendation inspector panels (evidence, blocked rules, target eligibility reasons)
    - add rule trace filtering by status (`Emitted`, `Rejected`, `Skipped`)

### P5 (Weeks 21-24)

19. [ ] **Desktop release hardening**
    - signed installers for Windows/macOS/Linux
    - reproducible build metadata and release notes automation
20. [ ] **Diagnostics bundle workflow**
    - export report, warnings, doctor output, and environment metadata bundle
    - add UI affordance for support-friendly bundle discovery
21. [ ] **Docs and support matrix**
    - publish filesystem/platform support matrix and known constraints
    - document report schema compatibility and upgrade guidance

## Exit Criteria for Upcoming Milestones

- `v1.4` candidate:
  - parity fixture gate enabled in CI
  - evaluation KPI thresholds enforced
  - recommendation inspector + trace drilldowns shipped
- `v1.5` candidate:
  - signed desktop installers on primary platforms
  - diagnostics bundle workflow shipped
  - default backend decision documented (`native` vs `pdu_library`)

## Immediate Next Sprint (Weeks 13-14)

1. [x] Add parity fixture assertions for `native` vs `pdu_library`.
2. [x] Add CI parity/eval artifact jobs with fail thresholds.
3. [x] Implement results-tab recommendation inspector detail panes.
4. [x] Add desktop e2e smoke tests for `setup -> scanning -> results -> doctor`.
5. [x] Update `README.md` and `ARCHITECTURE.md` with parity gate/KPI definitions.
