import { expect, test, type Page } from "@playwright/test";

const storedReport = {
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

const importedReport = {
  ...storedReport,
  scan_id: "../legacy-import",
  generated_at: "2026-02-13T00:00:00Z",
  recommendations: [
    {
      id: "stored-imported-recommendation",
      title: "Stored imported recommendation",
      rationale: "Imported reports should reopen exactly as stored.",
      confidence: 0.33,
      target_mount: "D:\\",
      policy_safe: false,
      policy_rules_applied: ["imported_policy"],
      policy_rules_blocked: ["blocked_for_review"],
      estimated_impact: {
        space_saving_bytes: 1024,
        performance: "Stored planner note",
        risk_notes: "Stored imported risk note.",
      },
      risk_level: "high",
      evidence: [
        {
          kind: "warning",
          label: "Stored imported evidence",
          detail: "This value should survive reopen without recomputation.",
          mount_point: "D:\\",
        },
      ],
      next_steps: ["Review the stored imported evidence."],
    },
  ],
  policy_decisions: [
    {
      policy_id: "imported_policy",
      recommendation_id: "stored-imported-recommendation",
      action: "blocked",
      rationale: "Imported policy decisions must stay intact.",
    },
  ],
  rule_traces: [
    {
      rule_id: "imported_rule_trace",
      status: "rejected",
      detail: "Stored imported trace detail.",
      recommendation_id: "stored-imported-recommendation",
      confidence: 0.21,
    },
  ],
};

const mockDoctor = {
  os: "windows",
  arch: "x86_64",
  read_only_mode: true,
  disks: storedReport.disks,
  notes: [],
};

const mockEvents = [
  {
    seq: 1,
    scan_id: storedReport.scan_id,
    phase: "walking_files",
    current_path: "D:\\Demo",
    scanned_files: 10,
    scanned_bytes: 2097152,
    errors: 0,
    timestamp: "2026-02-12T00:00:01Z",
  },
  {
    seq: 2,
    scan_id: storedReport.scan_id,
    phase: "done",
    current_path: null,
    scanned_files: 12,
    scanned_bytes: 3145728,
    errors: 0,
    timestamp: "2026-02-12T00:00:02Z",
  },
];

const storedSummary = {
  scan_id: storedReport.scan_id,
  generated_at: storedReport.generated_at,
  report_version: storedReport.report_version,
  roots: ["D:\\Demo"],
  backend: "native",
  warnings_count: 0,
  recommendation_count: storedReport.recommendations.length,
  stored_report_path: "D:\\Library\\stored-report.json",
  source_path: "D:\\Library\\stored-report.json",
  imported: false,
};

const importedSummary = {
  scan_id: importedReport.scan_id,
  generated_at: importedReport.generated_at,
  report_version: importedReport.report_version,
  roots: ["D:\\Demo"],
  backend: "native",
  warnings_count: 0,
  recommendation_count: importedReport.recommendations.length,
  stored_report_path: "D:\\Library\\imported-legacy-report.json",
  source_path: "D:\\Imports\\legacy-report.json",
  imported: true,
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

async function getTauriCalls(page: Page) {
  return page.evaluate(() => {
    return (
      window as unknown as {
        __mockTauriState__: { calls: Array<{ command: string; payload?: Record<string, unknown> }> };
      }
    ).__mockTauriState__.calls;
  });
}

test.beforeEach(async ({ page }) => {
  await page.addInitScript(
    ({ report, imported, doctor, events, reportSummary, importedReportSummary, reportDiff }) => {
      const state = {
        calls: [] as Array<{ command: string; payload?: Record<string, unknown> }>,
        sessionCalls: 0,
        eventCalls: 0,
      };

      const buildScenarioPlan = (activeReport: typeof report) => ({
        generated_at: "2026-02-12T00:00:03Z",
        scan_id: activeReport.scan_id,
        assumptions: ["Read-only simulation"],
        scenarios: [
          {
            scenario_id: "conservative",
            title: "Conservative",
            strategy: "conservative",
            recommendation_ids: activeReport.recommendations.map((entry) => entry.id),
            recommendation_count: activeReport.recommendations.length,
            projected_space_saving_bytes:
              activeReport.recommendations[0]?.estimated_impact?.space_saving_bytes ?? 0,
            risk_mix: { low: 1, medium: 0, high: 0 },
            blocked_recommendation_count: activeReport.recommendations.filter(
              (entry) => !entry.policy_safe
            ).length,
            notes: [],
          },
        ],
      });

      (
        window as unknown as {
          __TAURI_INTERNALS__: {
            invoke: (command: string, payload?: Record<string, unknown>) => Promise<unknown>;
          };
          __mockTauriState__: typeof state;
        }
      ).__mockTauriState__ = state;

      (
        window as unknown as {
          __TAURI_INTERNALS__: {
            invoke: (command: string, payload?: Record<string, unknown>) => Promise<unknown>;
          };
        }
      ).__TAURI_INTERNALS__ = {
        invoke: async (command: string, payload?: Record<string, unknown>) => {
          state.calls.push({ command, payload });

          switch (command) {
            case "start_scan":
              return report.scan_id;
            case "poll_scan_events":
              state.eventCalls += 1;
              return state.eventCalls === 1 ? events : [];
            case "get_scan_session":
              state.sessionCalls += 1;
              if (state.sessionCalls < 2) {
                return {
                  scan_id: report.scan_id,
                  status: "running",
                  total_events: 0,
                };
              }
              return {
                scan_id: report.scan_id,
                status: "completed",
                report_path: reportSummary.stored_report_path,
                total_events: events.length,
              };
            case "load_report":
              return payload?.path === importedReportSummary.stored_report_path ? imported : report;
            case "list_reports":
              return [reportSummary, importedReportSummary];
            case "get_report":
              return report;
            case "import_report":
              return { summary: importedReportSummary };
            case "compare_reports":
              return reportDiff;
            case "generate_recommendations":
              throw new Error("generate_recommendations should not run during reopen/import flows");
            case "plan_scenarios":
              return buildScenarioPlan((payload?.report as typeof report) ?? report);
            case "doctor":
              return doctor;
            case "export_diagnostics_bundle":
              return {
                generated_at: "2026-02-12T00:00:04Z",
                source_report_path: payload?.sourceReportPath,
                report: payload?.report,
                doctor,
                environment: {
                  os: "windows",
                  arch: "x86_64",
                  read_only_mode: true,
                  app_version: "0.1.0",
                },
              };
            case "export_markdown_summary":
            case "export_report_diff":
            case "cancel_scan":
              return null;
            case "plugin:dialog|open":
              return "D:\\Imports\\legacy-report.json";
            default:
              throw new Error(`Unexpected Tauri command in smoke test: ${command}`);
          }
        },
      };
    },
    {
      report: storedReport,
      imported: importedReport,
      doctor: mockDoctor,
      events: mockEvents,
      reportSummary: storedSummary,
      importedReportSummary: importedSummary,
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

  const commands = (await getTauriCalls(page)).map((entry) => entry.command);
  expect(commands).not.toContain("generate_recommendations");

  await page.getByRole("button", { name: "Doctor" }).click();
  await expect(page.getByRole("heading", { name: "Doctor" })).toBeVisible();
  await expect(page.getByText("Detected disks: 1")).toBeVisible();
});

test("reopening a saved report keeps the stored recommendations and traces", async ({ page }) => {
  await page.goto("/");

  await page.getByRole("button", { name: "Open Report" }).first().click();

  await expect(page.getByRole("heading", { name: "Results Workbench" })).toBeVisible();
  await expect(
    page.getByRole("heading", {
      name: "Cloud-backed drives excluded from local placement targets",
    })
  ).toBeVisible();
  await page.getByRole("button", { name: "Open in Rule Trace" }).click();
  await expect(page.getByText("cloud_exclusion_notice")).toBeVisible();

  const calls = await getTauriCalls(page);
  expect(calls.filter((entry) => entry.command === "generate_recommendations")).toHaveLength(0);
  expect(calls.filter((entry) => entry.command === "load_report")).toContainEqual({
    command: "load_report",
    payload: { path: storedSummary.stored_report_path },
  });
});

test("imported reports reopen from the stored path and exports use stored provenance", async ({
  page,
}) => {
  await page.goto("/");

  await page.getByRole("button", { name: "Import Report..." }).click();

  await expect(page.getByRole("heading", { name: "Results Workbench" })).toBeVisible();
  await expect(
    page.getByRole("heading", {
      name: "Stored imported recommendation",
    })
  ).toBeVisible();
  await expect(page.getByText("Imported ../legacy-import into the local report library.")).toBeVisible();

  let calls = await getTauriCalls(page);
  expect(calls.filter((entry) => entry.command === "generate_recommendations")).toHaveLength(0);
  expect(calls.filter((entry) => entry.command === "load_report")).toContainEqual({
    command: "load_report",
    payload: { path: importedSummary.stored_report_path },
  });

  await page.getByRole("button", { name: "Export Markdown Summary" }).click();
  await expect(
    page.getByText("Markdown review summary written to D:\\Library\\imported-legacy-report.md.")
  ).toBeVisible();

  await page.getByRole("button", { name: "Export Diagnostics Bundle" }).click();
  await expect(
    page.getByText(
      "Diagnostics bundle written to D:\\Library\\imported-legacy-report.diagnostics.json"
    )
  ).toBeVisible();

  calls = await getTauriCalls(page);

  expect(calls).toContainEqual({
    command: "export_markdown_summary",
    payload: {
      report: importedReport,
      outputPath: "D:\\Library\\imported-legacy-report.md",
    },
  });
  expect(calls).toContainEqual({
    command: "export_diagnostics_bundle",
    payload: {
      report: importedReport,
      outputPath: "D:\\Library\\imported-legacy-report.diagnostics.json",
      sourceReportPath: importedSummary.stored_report_path,
    },
  });
});
