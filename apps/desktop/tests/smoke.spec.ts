import { expect, test } from "@playwright/test";

const mockReport = {
  scan_id: "scan-e2e-1",
  report_version: "1.3.0",
  generated_at: "2026-02-12T00:00:00Z",
  disks: [
    {
      name: "Data Disk",
      mount_point: "D:\\",
      locality_class: "local_physical",
      performance_class: "balanced",
      is_os_drive: false,
      eligible_for_local_target: true,
      ineligible_reasons: [],
      role_hint: {
        role: "active_workload",
        confidence: 0.8,
        evidence: ["fixture"],
      },
    },
  ],
  paths: [
    {
      root_path: "D:\\Demo",
      file_count: 12,
      directory_count: 4,
      total_size_bytes: 104857600,
    },
  ],
  categories: [],
  duplicates: [],
  recommendations: [
    {
      id: "cloud-backed-target-exclusion",
      title: "Cloud-backed drives excluded from local placement targets",
      rationale:
        "Cloud-backed destinations are analyzed for visibility but excluded for local placement recommendations.",
      confidence: 0.95,
      target_mount: "D:\\",
      policy_safe: true,
      policy_rules_applied: ["safe_target_policy"],
      policy_rules_blocked: [],
      estimated_impact: {
        space_saving_bytes: null,
        performance: null,
        risk_notes: "Avoids non-local target suggestions.",
      },
      risk_level: "low",
      evidence: [
        {
          kind: "disk",
          label: "Excluded destination",
          detail: "Fixture evidence",
          mount_point: "D:\\",
        },
      ],
      next_steps: ["Review the linked evidence before taking action."],
    },
  ],
  policy_decisions: [
    {
      policy_id: "safe_target_policy",
      recommendation_id: "cloud-backed-target-exclusion",
      action: "allowed",
      rationale: "Target mount passed local placement eligibility checks.",
    },
  ],
  rule_traces: [
    {
      rule_id: "cloud_exclusion_notice",
      status: "emitted",
      detail: "Rule produced one recommendation.",
      recommendation_id: "cloud-backed-target-exclusion",
      confidence: 0.95,
    },
  ],
  warnings: [],
};

const mockDoctor = {
  os: "windows",
  arch: "x86_64",
  read_only_mode: true,
  disks: mockReport.disks,
  notes: [],
};

const mockScenarioPlan = {
  generated_at: "2026-02-12T00:00:03Z",
  scan_id: "scan-e2e-1",
  assumptions: ["Read-only simulation"],
  scenarios: [
    {
      scenario_id: "conservative",
      title: "Conservative",
      strategy: "conservative",
      recommendation_ids: ["cloud-backed-target-exclusion"],
      recommendation_count: 1,
      projected_space_saving_bytes: 0,
      risk_mix: { low: 1, medium: 0, high: 0 },
      blocked_recommendation_count: 0,
      notes: [],
    },
  ],
};

const mockEvents = [
  {
    seq: 1,
    scan_id: "scan-e2e-1",
    phase: "walking_files",
    current_path: "D:\\Demo",
    scanned_files: 10,
    scanned_bytes: 2097152,
    errors: 0,
    timestamp: "2026-02-12T00:00:01Z",
  },
  {
    seq: 2,
    scan_id: "scan-e2e-1",
    phase: "done",
    current_path: null,
    scanned_files: 12,
    scanned_bytes: 3145728,
    errors: 0,
    timestamp: "2026-02-12T00:00:02Z",
  },
];

const mockReportSummary = {
  scan_id: mockReport.scan_id,
  generated_at: mockReport.generated_at,
  report_version: mockReport.report_version,
  roots: ["D:\\Demo"],
  backend: "native",
  warnings_count: 0,
  recommendation_count: mockReport.recommendations.length,
  stored_report_path: "mock-report.json",
  source_path: "mock-report.json",
  imported: false,
};

const mockReportDiff = {
  left_scan_id: "scan-left",
  right_scan_id: "scan-right",
  left_generated_at: "2026-02-11T00:00:00Z",
  right_generated_at: "2026-02-12T00:00:00Z",
  duplicate_wasted_bytes_delta: 1024,
  disk_diffs: [],
  path_diffs: [],
  recommendation_changes: [],
};

test.beforeEach(async ({ page }) => {
  await page.addInitScript(
    ({ report, doctor, events, scenarioPlan, reportSummary, reportDiff }) => {
      let sessionCalls = 0;
      let eventCalls = 0;
      const scanId = report.scan_id;

      (
        window as unknown as {
          __TAURI_INTERNALS__: { invoke: (...args: unknown[]) => Promise<unknown> };
        }
      ).__TAURI_INTERNALS__ = {
        invoke: async (command: string) => {
          switch (command) {
            case "start_scan":
              return scanId;
            case "poll_scan_events":
              eventCalls += 1;
              return eventCalls === 1 ? events : [];
            case "get_scan_session":
              sessionCalls += 1;
              if (sessionCalls < 2) {
                return {
                  scan_id: scanId,
                  status: "running",
                  total_events: 0,
                };
              }
              return {
                scan_id: scanId,
                status: "completed",
                report_path: "mock-report.json",
                total_events: events.length,
              };
            case "load_report":
              return report;
            case "list_reports":
              return [reportSummary];
            case "get_report":
              return report;
            case "import_report":
              return { summary: reportSummary };
            case "compare_reports":
              return reportDiff;
            case "generate_recommendations":
              return {
                recommendations: report.recommendations,
                policy_decisions: report.policy_decisions,
                rule_traces: report.rule_traces,
                contradiction_count: 0,
              };
            case "plan_scenarios":
              return scenarioPlan;
            case "doctor":
              return doctor;
            case "export_diagnostics_bundle":
              return {
                generated_at: "2026-02-12T00:00:04Z",
                source_report_path: "mock-report.json",
                report,
                doctor,
                environment: {
                  os: "windows",
                  arch: "x86_64",
                  read_only_mode: true,
                  app_version: "0.1.0",
                },
              };
            case "cancel_scan":
              return null;
            default:
              throw new Error(`Unexpected Tauri command in smoke test: ${command}`);
          }
        },
      };
    },
    {
      report: mockReport,
      doctor: mockDoctor,
      events: mockEvents,
      scenarioPlan: mockScenarioPlan,
      reportSummary: mockReportSummary,
      reportDiff: mockReportDiff,
    }
  );
});

test("setup to results to doctor smoke flow", async ({ page }) => {
  await page.goto("/");

  await expect(page.getByRole("heading", { name: "Home And Guided Path Selection" })).toBeVisible();

  await page.getByPlaceholder(/Add path/).fill("D:\\Demo");
  await page.getByRole("button", { name: "Add Path" }).click();
  await page.getByRole("button", { name: "Start Read-Only Scan" }).click();

  await expect(page.getByRole("heading", { name: "Scanning" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Results Workbench" })).toBeVisible();

  await expect(page.getByText("Recommendations (1)")).toBeVisible();
  await expect(page.getByText("Policy Decisions (1)")).toBeVisible();
  await page.getByRole("button", { name: "Open in Rule Trace" }).click();

  await expect(page.getByRole("button", { name: "Reset Filters" })).toBeVisible();
  await expect(page.getByText("cloud_exclusion_notice")).toBeVisible();
  await page.getByRole("button", { name: "Open Recommendation Inspector" }).click();

  await expect(
    page.getByRole("heading", {
      name: "Cloud-backed drives excluded from local placement targets",
    })
  ).toBeVisible();

  await page.getByRole("button", { name: "Doctor" }).click();
  await expect(page.getByRole("heading", { name: "Doctor" })).toBeVisible();
  await expect(page.getByText("Detected disks: 1")).toBeVisible();
});
