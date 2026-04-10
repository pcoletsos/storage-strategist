# Desktop UI (Tauri + React)

This app is the read-only review UI track for `storage-strategist`.

## Scope

- Guided path selection before scan start.
- Home/library workflow for reopening imported or previously saved reports.
- Live scan progress (events + session polling).
- Results workbench:
  - Disks
  - Usage
  - Categories
  - Duplicates
  - Scenarios (read-only what-if planner)
  - Recommendations
  - Rule Trace
- Doctor diagnostics panel.
- Diagnostics bundle export action from Results.
- No destructive operations.

## Local run

```bash
cd apps/desktop
npm install
npm run tauri dev
```

## Smoke tests

```bash
cd apps/desktop
npm install
npx playwright install chromium
npm run test:e2e
```

## Notes

- Uses `crates/service` for scan/recommend/report APIs.
- UI is intentionally advisory and read-only in all current phases.
- Saved reports are indexed into the shared local report store and can be reopened or compared without rescanning.
- E2E smoke tests mock the Tauri command bridge to validate setup/scanning/results/doctor flows in CI.
