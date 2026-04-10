import { useEffect, useMemo, useState } from "react";
import { open } from "@tauri-apps/plugin-dialog";

import {
  cancelScan,
  compareReports,
  doctor,
  exportDiagnosticsBundle,
  exportMarkdownSummary,
  exportReportDiff,
  getReport,
  getScanSession,
  importReport,
  listReports,
  loadReport,
  planScenarios,
  pollScanEvents,
  startScan,
} from "./api";
import type {
  DoctorInfo,
  PolicyDecision,
  Report,
  ReportDiff,
  ReportSummary,
  RuleTrace,
  ScenarioPlan,
  ScanProgressEvent,
  ScanRequest,
  ScanSessionSnapshot,
} from "./types";

type Screen = "setup" | "scanning" | "results" | "compare" | "doctor";
type ResultTab =
  | "disks"
  | "usage"
  | "categories"
  | "duplicates"
  | "scenarios"
  | "recommendations"
  | "rule-trace";

const DEFAULT_OUTPUT = "storage-strategist-report.json";

type RuleTraceFilterStatus = "all" | "emitted" | "rejected" | "skipped";
type RecommendationPolicyFilter = "all" | "safe" | "blocked";
type RecommendationEvidenceFilter =
  | "all"
  | "disk"
  | "directory"
  | "duplicate_group"
  | "history_delta"
  | "warning"
  | "other";

const RULE_TRACE_STATUS_OPTIONS: RuleTraceFilterStatus[] = [
  "all",
  "emitted",
  "rejected",
  "skipped",
];

function formatBytes(bytes: number | null | undefined): string {
  if (bytes === null || bytes === undefined || bytes <= 0) {
    return "n/a";
  }
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = bytes;
  let unitIndex = 0;
  while (value >= 1024 && unitIndex < units.length - 1) {
    value /= 1024;
    unitIndex += 1;
  }
  return `${value.toFixed(value >= 100 || unitIndex === 0 ? 0 : 1)} ${units[unitIndex]}`;
}

function formatConfidence(confidence: number | null | undefined): string {
  if (confidence === null || confidence === undefined) {
    return "n/a";
  }
  return `${(confidence * 100).toFixed(1)}%`;
}

function formatSignedBytes(bytes: number | null | undefined): string {
  if (bytes === null || bytes === undefined) {
    return "n/a";
  }
  const sign = bytes < 0 ? "-" : "+";
  return `${sign}${formatBytes(Math.abs(bytes))}`;
}

function deriveDiagnosticsOutputPath(sourcePath?: string): string {
  const base = sourcePath?.trim() || DEFAULT_OUTPUT;
  if (base.toLowerCase().endsWith(".json")) {
    return `${base.slice(0, -5)}.diagnostics.json`;
  }
  return `${base}.diagnostics.json`;
}

function deriveMarkdownOutputPath(sourcePath?: string): string {
  const base = sourcePath?.trim() || DEFAULT_OUTPUT;
  if (base.toLowerCase().endsWith(".json")) {
    return `${base.slice(0, -5)}.md`;
  }
  return `${base}.md`;
}

function deriveDiffOutputPath(leftScanId?: string, rightScanId?: string): string {
  const left = leftScanId?.trim() || "left";
  const right = rightScanId?.trim() || "right";
  return `${left}-to-${right}.diff.json`;
}

function App() {
  const [screen, setScreen] = useState<Screen>("setup");
  const [tab, setTab] = useState<ResultTab>("recommendations");

  const [paths, setPaths] = useState<string[]>([]);
  const [pathInput, setPathInput] = useState("");
  const [excludeInput, setExcludeInput] = useState("");
  const [excludes, setExcludes] = useState<string[]>([]);
  const [output, setOutput] = useState(DEFAULT_OUTPUT);
  const [maxDepth, setMaxDepth] = useState<number | undefined>(undefined);
  const [backend, setBackend] = useState<"native" | "pdu_library">("native");
  const [dedupe, setDedupe] = useState(true);

  const [scanId, setScanId] = useState<string | null>(null);
  const [session, setSession] = useState<ScanSessionSnapshot | null>(null);
  const [events, setEvents] = useState<ScanProgressEvent[]>([]);
  const [report, setReport] = useState<Report | null>(null);
  const [activeReportPath, setActiveReportPath] = useState<string | null>(null);
  const [reportLibrary, setReportLibrary] = useState<ReportSummary[]>([]);
  const [reportDiff, setReportDiff] = useState<ReportDiff | null>(null);
  const [leftCompareId, setLeftCompareId] = useState<string>("");
  const [rightCompareId, setRightCompareId] = useState<string>("");
  const [scenarioPlan, setScenarioPlan] = useState<ScenarioPlan | null>(null);
  const [doctorInfo, setDoctorInfo] = useState<DoctorInfo | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [selectedRecommendationId, setSelectedRecommendationId] = useState<string | null>(null);
  const [traceStatusFilter, setTraceStatusFilter] = useState<RuleTraceFilterStatus>("all");
  const [traceRecommendationFilter, setTraceRecommendationFilter] = useState<string>("all");
  const [usageFilter, setUsageFilter] = useState("");
  const [duplicateFilter, setDuplicateFilter] = useState("");
  const [recommendationFilter, setRecommendationFilter] = useState("");
  const [recommendationPolicyFilter, setRecommendationPolicyFilter] =
    useState<RecommendationPolicyFilter>("all");
  const [recommendationEvidenceFilter, setRecommendationEvidenceFilter] =
    useState<RecommendationEvidenceFilter>("all");

  const refreshReportLibrary = async () => {
    const reports = await listReports();
    setReportLibrary(reports);
    if (!leftCompareId && reports[0]) {
      setLeftCompareId(reports[0].scan_id);
    }
    if (!rightCompareId && reports[1]) {
      setRightCompareId(reports[1].scan_id);
    }
  };

  useEffect(() => {
    void refreshReportLibrary().catch((libraryError) => {
      setError(String(libraryError));
    });
  }, []);

  useEffect(() => {
    if (screen !== "scanning" || !scanId) {
      return;
    }

    let isActive = true;
    let fromSeq = 0;

    const poll = async () => {
      try {
        const [snapshot, nextEvents] = await Promise.all([
          getScanSession(scanId),
          pollScanEvents(scanId, fromSeq),
        ]);

        if (!isActive) {
          return;
        }

        setSession(snapshot);

        if (nextEvents.length > 0) {
          fromSeq = nextEvents[nextEvents.length - 1].seq;
          setEvents((prev) => [...prev, ...nextEvents]);
        }

        if (snapshot.status === "completed") {
          const storedReportPath =
            snapshot.report_path !== undefined && snapshot.report_path !== null
              ? snapshot.report_path
              : null;
          const loaded = storedReportPath ? await loadReport(storedReportPath) : await getReport(scanId);

          if (!isActive) {
            return;
          }

          await loadWorkbenchReport(loaded, storedReportPath);
          await refreshReportLibrary();
          setNotice(null);
        }

        if (snapshot.status === "failed") {
          setError(snapshot.error ?? "scan failed");
          setScreen("setup");
        }

        if (snapshot.status === "cancelled") {
          setError("Scan cancelled.");
          setScreen("setup");
        }
      } catch (pollError) {
        setError(String(pollError));
        setScreen("setup");
      }
    };

    const timer = window.setInterval(poll, 500);
    void poll();

    return () => {
      isActive = false;
      window.clearInterval(timer);
    };
  }, [scanId, screen, output]);

  const latestEvent = useMemo(
    () => (events.length > 0 ? events[events.length - 1] : null),
    [events]
  );

  useEffect(() => {
    if (!report) {
      setSelectedRecommendationId(null);
      setTraceRecommendationFilter("all");
      return;
    }

    const hasCurrentSelection =
      selectedRecommendationId !== null &&
      report.recommendations.some((recommendation) => recommendation.id === selectedRecommendationId);

    if (!hasCurrentSelection) {
      setSelectedRecommendationId(report.recommendations[0]?.id ?? null);
    }

    if (
      traceRecommendationFilter !== "all" &&
      !report.recommendations.some((recommendation) => recommendation.id === traceRecommendationFilter)
    ) {
      setTraceRecommendationFilter("all");
    }
  }, [report, selectedRecommendationId, traceRecommendationFilter]);

  const policyDecisions = useMemo(
    () => (report?.policy_decisions ?? []) as PolicyDecision[],
    [report]
  );

  const selectedRecommendation = useMemo(() => {
    if (!report || !selectedRecommendationId) {
      return null;
    }
    return (
      report.recommendations.find((recommendation) => recommendation.id === selectedRecommendationId) ?? null
    );
  }, [report, selectedRecommendationId]);

  const selectedRecommendationPolicyDecisions = useMemo(() => {
    if (!selectedRecommendation) {
      return [];
    }
    return policyDecisions.filter(
      (decision) => decision.recommendation_id === selectedRecommendation.id
    );
  }, [policyDecisions, selectedRecommendation]);

  const selectedRecommendationRuleTraces = useMemo(() => {
    if (!selectedRecommendation) {
      return [];
    }
    return (report?.rule_traces ?? []).filter(
      (trace) => trace.recommendation_id === selectedRecommendation.id
    );
  }, [report, selectedRecommendation]);

  const selectedTargetDisk = useMemo(() => {
    if (!report || !selectedRecommendation?.target_mount) {
      return null;
    }
    return (
      report.disks.find((disk) => disk.mount_point === selectedRecommendation.target_mount) ?? null
    );
  }, [report, selectedRecommendation]);

  const ruleTraceCounts = useMemo(() => {
    const traces = report?.rule_traces ?? [];
    return {
      all: traces.length,
      emitted: traces.filter((trace) => trace.status === "emitted").length,
      rejected: traces.filter((trace) => trace.status === "rejected").length,
      skipped: traces.filter((trace) => trace.status === "skipped").length,
    };
  }, [report]);

  const filteredRuleTraces = useMemo(() => {
    const traces = (report?.rule_traces ?? []) as RuleTrace[];
    return traces.filter((trace) => {
      const statusMatches = traceStatusFilter === "all" || trace.status === traceStatusFilter;
      const recommendationMatches =
        traceRecommendationFilter === "all" || trace.recommendation_id === traceRecommendationFilter;
      return statusMatches && recommendationMatches;
    });
  }, [report, traceStatusFilter, traceRecommendationFilter]);

  const filteredUsage = useMemo(() => {
    const query = usageFilter.trim().toLowerCase();
    const paths = report?.paths ?? [];
    if (!query) {
      return paths;
    }
    return paths.filter((path) => path.root_path.toLowerCase().includes(query));
  }, [report, usageFilter]);

  const filteredDuplicates = useMemo(() => {
    const query = duplicateFilter.trim().toLowerCase();
    const duplicates = report?.duplicates ?? [];
    if (!query) {
      return duplicates;
    }
    return duplicates.filter((duplicate) => {
      const label = duplicate.intent?.label?.toLowerCase() ?? "";
      return (
        label.includes(query) ||
        duplicate.hash.toLowerCase().includes(query) ||
        duplicate.files.some((file) => file.path.toLowerCase().includes(query))
      );
    });
  }, [report, duplicateFilter]);

  const filteredRecommendations = useMemo(() => {
    const query = recommendationFilter.trim().toLowerCase();
    const recommendations = report?.recommendations ?? [];
    return recommendations.filter((recommendation) => {
      const queryMatches =
        !query ||
        recommendation.title.toLowerCase().includes(query) ||
        recommendation.rationale.toLowerCase().includes(query) ||
        recommendation.id.toLowerCase().includes(query);
      const policyMatches =
        recommendationPolicyFilter === "all" ||
        (recommendationPolicyFilter === "safe" && recommendation.policy_safe) ||
        (recommendationPolicyFilter === "blocked" && !recommendation.policy_safe);
      const evidenceMatches =
        recommendationEvidenceFilter === "all" ||
        recommendation.evidence.some(
          (evidence) => evidence.kind === recommendationEvidenceFilter
        );
      return queryMatches && policyMatches && evidenceMatches;
    });
  }, [report, recommendationEvidenceFilter, recommendationFilter, recommendationPolicyFilter]);

  const loadWorkbenchReport = async (
    loaded: Report,
    reportPath?: string | null
  ) => {
    const nextScenarioPlan = await planScenarios(loaded);

    setReport(loaded);
    setActiveReportPath(reportPath?.trim() || null);
    setScanId(loaded.scan_id);
    setSession(null);
    setScenarioPlan(nextScenarioPlan);
    setSelectedRecommendationId(loaded.recommendations[0]?.id ?? null);
    setTraceStatusFilter("all");
    setTraceRecommendationFilter("all");
    setRecommendationFilter("");
    setRecommendationPolicyFilter("all");
    setRecommendationEvidenceFilter("all");
    setUsageFilter("");
    setDuplicateFilter("");
    setReportDiff(null);
    setTab("recommendations");
    setScreen("results");
  };

  const openStoredReport = async (summary: ReportSummary) => {
    setError(null);
    setNotice(null);
    try {
      const storedReport = await loadReport(summary.stored_report_path);
      await loadWorkbenchReport(storedReport, summary.stored_report_path);
      setNotice(`Opened saved report ${summary.scan_id}.`);
    } catch (storedReportError) {
      setError(String(storedReportError));
    }
  };

  const importExistingReport = async () => {
    setError(null);
    setNotice(null);
    try {
      const selection = await open({
        directory: false,
        multiple: false,
        filters: [{ name: "JSON Reports", extensions: ["json"] }],
      });
      if (!selection || Array.isArray(selection)) {
        return;
      }
      const result = await importReport(selection);
      await refreshReportLibrary();
      await openStoredReport(result.summary);
      setNotice(`Imported ${result.summary.scan_id} into the local report library.`);
    } catch (importError) {
      setError(String(importError));
    }
  };

  const runCompare = async () => {
    if (!leftCompareId || !rightCompareId || leftCompareId === rightCompareId) {
      setError("Select two different stored reports to compare.");
      return;
    }

    setError(null);
    setNotice(null);
    try {
      const diff = await compareReports(leftCompareId, rightCompareId);
      setReportDiff(diff);
      setScreen("compare");
    } catch (compareError) {
      setError(String(compareError));
    }
  };

  const start = async () => {
    setError(null);
    setNotice(null);
    if (paths.length === 0) {
      setError("Select at least one path before starting a scan.");
      return;
    }

    const request: ScanRequest = {
      paths,
      output: output.trim() || undefined,
      max_depth: maxDepth,
      excludes,
      dedupe,
      dedupe_min_size: 1_048_576,
      backend,
      progress: true,
      min_ratio: undefined,
      emit_progress_events: true,
      progress_interval_ms: 250,
      incremental_cache: true,
      cache_ttl_seconds: 900,
      record_history: true,
    };

    try {
      setEvents([]);
      setSession(null);
      setReport(null);
      setActiveReportPath(null);
      setScenarioPlan(null);
      const id = await startScan(request);
      setScanId(id);
      setScreen("scanning");
    } catch (startError) {
      setError(String(startError));
    }
  };

  const cancel = async () => {
    if (!scanId) {
      return;
    }
    await cancelScan(scanId);
  };

  const loadDoctor = async () => {
    setError(null);
    setNotice(null);
    try {
      const info = await doctor();
      setDoctorInfo(info);
      setScreen("doctor");
    } catch (doctorError) {
      setError(String(doctorError));
    }
  };

  const exportDiagnostics = async () => {
    if (!report) {
      return;
    }
    setError(null);
    setNotice(null);
    try {
      const sourcePath = activeReportPath ?? session?.report_path ?? output;
      const outputPath = deriveDiagnosticsOutputPath(sourcePath);
      const bundle = await exportDiagnosticsBundle(report, outputPath, sourcePath);
      setNotice(
        `Diagnostics bundle written to ${outputPath} (scan ${bundle.report.scan_id}, warnings ${bundle.report.warnings.length}).`
      );
    } catch (bundleError) {
      setError(String(bundleError));
    }
  };

  const exportMarkdown = async () => {
    if (!report) {
      return;
    }
    setError(null);
    setNotice(null);
    try {
      const sourcePath = activeReportPath ?? session?.report_path ?? output;
      const outputPath = deriveMarkdownOutputPath(sourcePath);
      await exportMarkdownSummary(report, outputPath);
      setNotice(`Markdown review summary written to ${outputPath}.`);
    } catch (markdownError) {
      setError(String(markdownError));
    }
  };

  const exportCompareJson = async () => {
    if (!reportDiff) {
      return;
    }
    setError(null);
    setNotice(null);
    try {
      const outputPath = deriveDiffOutputPath(
        reportDiff.left_scan_id,
        reportDiff.right_scan_id
      );
      await exportReportDiff(reportDiff, outputPath);
      setNotice(`Compare JSON written to ${outputPath}.`);
    } catch (diffError) {
      setError(String(diffError));
    }
  };

  const addPath = (value: string) => {
    const normalized = value.trim();
    if (!normalized || paths.includes(normalized)) {
      return;
    }
    setPaths((prev) => [...prev, normalized]);
    setPathInput("");
  };

  const browsePaths = async () => {
    try {
      const selection = await open({ directory: true, multiple: true });
      if (!selection) {
        return;
      }
      if (Array.isArray(selection)) {
        selection.forEach((entry) => addPath(entry));
      } else {
        addPath(selection);
      }
    } catch {
      setError(
        "Directory picker unavailable in this environment. Enter paths manually."
      );
    }
  };

  const focusRecommendation = (recommendationId: string) => {
    setSelectedRecommendationId(recommendationId);
    setTab("recommendations");
  };

  return (
    <main className="app-shell">
      <header className="header">
        <div>
          <h1>Storage Strategist Desktop</h1>
          <p className="sub">Read-only review UI. No delete/move/rename actions are available.</p>
        </div>
        <nav className="header-actions">
          <button onClick={() => setScreen("setup")}>Setup</button>
          <button onClick={loadDoctor}>Doctor</button>
        </nav>
      </header>

      {error ? <p className="error">{error}</p> : null}
      {notice ? <p className="notice">{notice}</p> : null}

      {screen === "setup" ? (
        <section className="panel">
          <h2>Home And Guided Path Selection</h2>
          <p>Select local paths first, or reopen/import a stored report from the local library.</p>

          <article className="card">
            <div className="title-row">
              <h3>Report Library</h3>
              <button onClick={importExistingReport}>Import Report...</button>
            </div>
            <p className="muted">
              Reopen saved scans, compare two reports, or import an exported JSON report into the local workbench.
            </p>
            {reportLibrary.length === 0 ? (
              <p className="muted">No saved reports yet.</p>
            ) : (
              <>
                <div className="row two-col">
                  <label>
                    Compare left
                    <select
                      value={leftCompareId}
                      onChange={(event) => setLeftCompareId(event.target.value)}
                    >
                      <option value="">select report</option>
                      {reportLibrary.map((item) => (
                        <option key={`left-${item.scan_id}`} value={item.scan_id}>
                          {item.scan_id} - {item.generated_at}
                        </option>
                      ))}
                    </select>
                  </label>
                  <label>
                    Compare right
                    <select
                      value={rightCompareId}
                      onChange={(event) => setRightCompareId(event.target.value)}
                    >
                      <option value="">select report</option>
                      {reportLibrary.map((item) => (
                        <option key={`right-${item.scan_id}`} value={item.scan_id}>
                          {item.scan_id} - {item.generated_at}
                        </option>
                      ))}
                    </select>
                  </label>
                </div>
                <div className="row end">
                  <button onClick={runCompare} disabled={!leftCompareId || !rightCompareId}>
                    Compare Stored Reports
                  </button>
                </div>
                <div className="scroll-block">
                  {reportLibrary.map((item) => (
                    <article key={item.scan_id} className="card">
                      <div className="title-row">
                        <h3>{item.scan_id}</h3>
                        <span className="badge">{item.backend}</span>
                      </div>
                      <p>{item.generated_at}</p>
                      <p>
                        roots {item.roots.join(", ")} | warnings {item.warnings_count} | recommendations{" "}
                        {item.recommendation_count}
                      </p>
                      <p>stored at {item.stored_report_path}</p>
                      <p>source path {item.source_path ?? "library-generated"}</p>
                      <div className="row end">
                        <button onClick={() => openStoredReport(item)}>Open Report</button>
                      </div>
                    </article>
                  ))}
                </div>
              </>
            )}
          </article>

          <h3>New Scan</h3>
          <p>Select local paths first. Cloud/network/virtual targets are excluded from placement recommendations.</p>

          <div className="row">
            <input
              value={pathInput}
              onChange={(event) => setPathInput(event.target.value)}
              placeholder="Add path (e.g. D:\\Games)"
            />
            <button onClick={() => addPath(pathInput)}>Add Path</button>
            <button onClick={browsePaths}>Browse...</button>
          </div>

          <ul className="list">
            {paths.map((path) => (
              <li key={path}>
                <span>{path}</span>
                <button onClick={() => setPaths(paths.filter((item) => item !== path))}>Remove</button>
              </li>
            ))}
            {paths.length === 0 ? <li className="muted">No paths selected.</li> : null}
          </ul>

          <div className="row two-col">
            <label>
              Output report path
              <input
                value={output}
                onChange={(event) => setOutput(event.target.value)}
                placeholder={DEFAULT_OUTPUT}
              />
            </label>
            <label>
              Max depth (optional)
              <input
                type="number"
                min={1}
                value={maxDepth ?? ""}
                onChange={(event) => {
                  const value = event.target.value;
                  setMaxDepth(value ? Number(value) : undefined);
                }}
              />
            </label>
          </div>

          <div className="row two-col">
            <label>
              Exclude pattern
              <input
                value={excludeInput}
                onChange={(event) => setExcludeInput(event.target.value)}
                placeholder="node_modules or **/*.tmp"
              />
            </label>
            <label>
              Backend
              <select
                value={backend}
                onChange={(event) => setBackend(event.target.value as "native" | "pdu_library")}
              >
                <option value="native">native</option>
                <option value="pdu_library">pdu_library</option>
              </select>
            </label>
          </div>

          <div className="row">
            <button onClick={() => {
              const next = excludeInput.trim();
              if (!next || excludes.includes(next)) {
                return;
              }
              setExcludes((prev) => [...prev, next]);
              setExcludeInput("");
            }}>
              Add Exclude
            </button>
            <label className="inline-toggle">
              <input type="checkbox" checked={dedupe} onChange={(event) => setDedupe(event.target.checked)} />
              Enable dedupe scan
            </label>
          </div>

          <ul className="list compact">
            {excludes.map((item) => (
              <li key={item}>
                <span>{item}</span>
                <button onClick={() => setExcludes(excludes.filter((x) => x !== item))}>Remove</button>
              </li>
            ))}
          </ul>

          <div className="row end">
            <button className="primary" onClick={start} disabled={paths.length === 0}>
              Start Read-Only Scan
            </button>
          </div>
        </section>
      ) : null}

      {screen === "scanning" ? (
        <section className="panel">
          <h2>Scanning</h2>
          <p>
            Scan ID: <code>{scanId}</code>
          </p>
          <p>
            Status: <strong>{session?.status ?? "running"}</strong>
          </p>
          <p>
            Phase: <strong>{latestEvent?.phase ?? "starting"}</strong>
          </p>
          <p>
            Files: {latestEvent?.scanned_files ?? 0} | Bytes: {latestEvent?.scanned_bytes ?? 0} |
            Errors: {latestEvent?.errors ?? 0}
          </p>
          <div className="progress-log">
            {events.slice(-12).map((event) => (
              <p key={event.seq}>
                #{event.seq} {event.phase} {event.current_path ? `(${event.current_path})` : ""}
              </p>
            ))}
          </div>
          <div className="row end">
            <button onClick={cancel}>Cancel</button>
          </div>
        </section>
      ) : null}

      {screen === "results" && report ? (
        <section className="panel">
          <div className="title-row">
            <h2>Results Workbench</h2>
            <div className="row">
              <button onClick={exportMarkdown}>Export Markdown Summary</button>
              <button onClick={exportDiagnostics}>Export Diagnostics Bundle</button>
            </div>
          </div>
          <p>
            Report {report.report_version} generated at {report.generated_at}
          </p>
          <div className="tabs">
            {(
              [
                "disks",
                "usage",
                "categories",
                "duplicates",
                "scenarios",
                "recommendations",
                "rule-trace",
              ] as ResultTab[]
            ).map(
              (item) => (
                <button
                  key={item}
                  className={tab === item ? "active" : ""}
                  onClick={() => setTab(item)}
                >
                  {item}
                </button>
              )
            )}
          </div>

          {tab === "disks" ? (
            <table>
              <thead>
                <tr>
                  <th>Disk</th>
                  <th>Mount</th>
                  <th>Role</th>
                  <th>Locality</th>
                  <th>Perf</th>
                  <th>OS</th>
                  <th>Eligible</th>
                </tr>
              </thead>
              <tbody>
                {report.disks.map((disk) => (
                  <tr key={disk.mount_point}>
                    <td>{disk.name}</td>
                    <td>{disk.mount_point}</td>
                    <td>{disk.role_hint?.role ?? "unknown"}</td>
                    <td>{disk.locality_class}</td>
                    <td>{disk.performance_class}</td>
                    <td>{disk.is_os_drive ? "yes" : "no"}</td>
                    <td>{disk.eligible_for_local_target ? "yes" : "no"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : null}

          {tab === "usage" ? (
            <div className="scroll-block">
              <div className="row">
                <input
                  value={usageFilter}
                  onChange={(event) => setUsageFilter(event.target.value)}
                  placeholder="Filter roots or paths"
                />
              </div>
              {filteredUsage.map((path) => (
                <article key={path.root_path} className="card">
                  <h3>{path.root_path}</h3>
                  <p>
                    files {path.file_count} | directories {path.directory_count} | bytes {path.total_size_bytes}
                  </p>
                </article>
              ))}
            </div>
          ) : null}

          {tab === "categories" ? (
            <div className="scroll-block">
              {(report.categories ?? []).map((category, index) => (
                <article key={`${category.target}-${index}`} className="card">
                  <h3>{category.category}</h3>
                  <p>{category.target}</p>
                  <p>confidence {(category.confidence * 100).toFixed(1)}%</p>
                  <p>{category.rationale}</p>
                </article>
              ))}
            </div>
          ) : null}

          {tab === "duplicates" ? (
            <div className="scroll-block">
              <div className="row">
                <input
                  value={duplicateFilter}
                  onChange={(event) => setDuplicateFilter(event.target.value)}
                  placeholder="Filter by hash, label, or file path"
                />
              </div>
              {filteredDuplicates.map((dup) => (
                <article key={`${dup.hash}-${dup.size_bytes}`} className="card">
                  <h3>{dup.intent?.label ?? "duplicate"}</h3>
                  <p>
                    size {dup.size_bytes} | files {dup.files.length} | wasted {dup.total_wasted_bytes}
                  </p>
                  <p>{dup.intent?.rationale}</p>
                </article>
              ))}
            </div>
          ) : null}

          {tab === "scenarios" ? (
            <div className="scroll-block">
              {!scenarioPlan ? <p className="muted">Scenario plan is unavailable.</p> : null}
              {scenarioPlan ? (
                <>
                  <article className="card">
                    <h3>Planner assumptions</h3>
                    {scenarioPlan.assumptions.map((assumption, index) => (
                      <p key={`${assumption}-${index}`}>{assumption}</p>
                    ))}
                  </article>
                  {scenarioPlan.scenarios.map((scenario) => (
                    <article key={scenario.scenario_id} className="card">
                      <div className="title-row">
                        <h3>{scenario.title}</h3>
                        <span className="badge">{scenario.strategy}</span>
                      </div>
                      <p>
                        recommendations {scenario.recommendation_count} | projected space saving{" "}
                        {formatBytes(scenario.projected_space_saving_bytes)}
                      </p>
                      <p>
                        risk mix low {scenario.risk_mix.low} / medium {scenario.risk_mix.medium} /
                        high {scenario.risk_mix.high}
                      </p>
                      <p>policy blocked recommendations {scenario.blocked_recommendation_count}</p>
                      <p>
                        recommendation ids{" "}
                        {scenario.recommendation_ids.length > 0
                          ? scenario.recommendation_ids.join(", ")
                          : "none"}
                      </p>
                      {scenario.notes.map((note, index) => (
                        <p key={`${scenario.scenario_id}-note-${index}`}>{note}</p>
                      ))}
                    </article>
                  ))}
                </>
              ) : null}
            </div>
          ) : null}

          {tab === "recommendations" ? (
            <div className="split-pane">
              <div className="list-pane">
                <h3>Recommendations ({filteredRecommendations.length})</h3>
                <div className="row">
                  <input
                    value={recommendationFilter}
                    onChange={(event) => setRecommendationFilter(event.target.value)}
                    placeholder="Search recommendation title, id, or rationale"
                  />
                </div>
                <div className="row two-col">
                  <label>
                    Policy
                    <select
                      value={recommendationPolicyFilter}
                      onChange={(event) =>
                        setRecommendationPolicyFilter(
                          event.target.value as RecommendationPolicyFilter
                        )
                      }
                    >
                      <option value="all">all</option>
                      <option value="safe">safe</option>
                      <option value="blocked">blocked</option>
                    </select>
                  </label>
                  <label>
                    Evidence
                    <select
                      value={recommendationEvidenceFilter}
                      onChange={(event) =>
                        setRecommendationEvidenceFilter(
                          event.target.value as RecommendationEvidenceFilter
                        )
                      }
                    >
                      <option value="all">all</option>
                      <option value="disk">disk</option>
                      <option value="directory">directory</option>
                      <option value="duplicate_group">duplicate group</option>
                      <option value="history_delta">history delta</option>
                      <option value="warning">warning</option>
                      <option value="other">other</option>
                    </select>
                  </label>
                </div>
                <div className="scroll-block">
                  {filteredRecommendations.length === 0 ? (
                    <p className="muted">No recommendations were produced for this report.</p>
                  ) : null}
                  {filteredRecommendations.map((recommendation) => {
                    const isActive = recommendation.id === selectedRecommendationId;
                    return (
                      <button
                        key={recommendation.id}
                        className={`select-card ${isActive ? "active" : ""}`}
                        onClick={() => setSelectedRecommendationId(recommendation.id)}
                      >
                        <div className="title-row">
                          <strong>{recommendation.title}</strong>
                          <span className={`badge risk-${recommendation.risk_level}`}>
                            {recommendation.risk_level}
                          </span>
                        </div>
                        <p className="meta-line">
                          confidence {formatConfidence(recommendation.confidence)} | policy{" "}
                          {recommendation.policy_safe ? "safe" : "blocked"}
                        </p>
                        <p className="truncate-2">{recommendation.rationale}</p>
                      </button>
                    );
                  })}
                </div>
              </div>

              <div className="inspector-pane">
                {!selectedRecommendation ? (
                  <article className="card">
                    <h3>Recommendation Inspector</h3>
                    <p className="muted">Select a recommendation to inspect evidence and policy traces.</p>
                  </article>
                ) : (
                  <>
                    <article className="card">
                      <div className="title-row">
                        <h3>{selectedRecommendation.title}</h3>
                        <span className={`badge risk-${selectedRecommendation.risk_level}`}>
                          {selectedRecommendation.risk_level}
                        </span>
                      </div>
                      <p>{selectedRecommendation.rationale}</p>
                      <p>
                        ID <code>{selectedRecommendation.id}</code>
                      </p>
                      <p>
                        confidence {formatConfidence(selectedRecommendation.confidence)} | target{" "}
                        {selectedRecommendation.target_mount ?? "none"}
                      </p>
                      <p>policy safe {selectedRecommendation.policy_safe ? "yes" : "no"}</p>
                      <p>
                        policy applied:{" "}
                        {selectedRecommendation.policy_rules_applied.length > 0
                          ? selectedRecommendation.policy_rules_applied.join(", ")
                          : "none"}
                      </p>
                      <p>
                        policy blocked:{" "}
                        {selectedRecommendation.policy_rules_blocked.length > 0
                          ? selectedRecommendation.policy_rules_blocked.join(", ")
                          : "none"}
                      </p>
                    </article>

                    <article className="card">
                      <h3>Estimated Impact</h3>
                      <p>
                        space saving {formatBytes(selectedRecommendation.estimated_impact.space_saving_bytes)}
                      </p>
                      <p>
                        performance note {selectedRecommendation.estimated_impact.performance ?? "none"}
                      </p>
                      <p>risk notes {selectedRecommendation.estimated_impact.risk_notes ?? "none"}</p>
                    </article>

                    <article className="card">
                      <h3>Evidence ({selectedRecommendation.evidence.length})</h3>
                      {selectedRecommendation.evidence.length === 0 ? (
                        <p className="muted">No structured evidence attached.</p>
                      ) : null}
                      {selectedRecommendation.evidence.map((evidence, index) => (
                        <div key={`${evidence.label}-${index}`} className="detail-block">
                          <p>
                            <strong>{evidence.label}</strong>{" "}
                            <span className="badge">{evidence.kind}</span>
                          </p>
                          <p>{evidence.detail}</p>
                          {evidence.mount_point ? <p>mount {evidence.mount_point}</p> : null}
                          {evidence.path ? <p>path {evidence.path}</p> : null}
                          {evidence.duplicate_hash ? <p>duplicate {evidence.duplicate_hash}</p> : null}
                        </div>
                      ))}
                    </article>

                    <article className="card">
                      <h3>Review Steps</h3>
                      {selectedRecommendation.next_steps.length === 0 ? (
                        <p className="muted">No follow-up guidance recorded.</p>
                      ) : null}
                      {selectedRecommendation.next_steps.map((step, index) => (
                        <p key={`${selectedRecommendation.id}-step-${index}`}>{step}</p>
                      ))}
                    </article>

                    <article className="card">
                      <h3>Policy Decisions ({selectedRecommendationPolicyDecisions.length})</h3>
                      {selectedRecommendationPolicyDecisions.length === 0 ? (
                        <p className="muted">No policy decisions were recorded for this recommendation.</p>
                      ) : null}
                      {selectedRecommendationPolicyDecisions.map((decision, index) => (
                        <div key={`${decision.policy_id}-${index}`} className="detail-block">
                          <p>
                            <strong>{decision.policy_id}</strong>{" "}
                            <span
                              className={`badge ${
                                decision.action === "allowed" ? "status-emitted" : "status-rejected"
                              }`}
                            >
                              {decision.action}
                            </span>
                          </p>
                          <p>{decision.rationale}</p>
                        </div>
                      ))}
                    </article>

                    <article className="card">
                      <h3>Linked Rule Traces ({selectedRecommendationRuleTraces.length})</h3>
                      {selectedRecommendationRuleTraces.length === 0 ? (
                        <p className="muted">No linked traces were found.</p>
                      ) : null}
                      {selectedRecommendationRuleTraces.map((trace, index) => (
                        <div key={`${trace.rule_id}-${index}`} className="detail-block">
                          <p>
                            <strong>{trace.rule_id}</strong>{" "}
                            <span className={`badge status-${trace.status}`}>{trace.status}</span>
                          </p>
                          <p>{trace.detail}</p>
                          <p>confidence {formatConfidence(trace.confidence)}</p>
                        </div>
                      ))}
                      {selectedRecommendationRuleTraces.length > 0 ? (
                        <div className="row end">
                          <button
                            onClick={() => {
                              setTraceRecommendationFilter(selectedRecommendation.id);
                              setTraceStatusFilter("all");
                              setTab("rule-trace");
                            }}
                          >
                            Open in Rule Trace
                          </button>
                        </div>
                      ) : null}
                    </article>

                    {selectedTargetDisk ? (
                      <article className="card">
                        <h3>Target Eligibility Context</h3>
                        <p>
                          {selectedTargetDisk.mount_point} | role {selectedTargetDisk.role_hint.role} | locality{" "}
                          {selectedTargetDisk.locality_class}
                        </p>
                        <p>
                          eligible for local target {selectedTargetDisk.eligible_for_local_target ? "yes" : "no"}
                        </p>
                        <p>
                          ineligible reasons:{" "}
                          {selectedTargetDisk.ineligible_reasons.length > 0
                            ? selectedTargetDisk.ineligible_reasons.join("; ")
                            : "none"}
                        </p>
                      </article>
                    ) : null}
                  </>
                )}
              </div>
            </div>
          ) : null}

          {tab === "rule-trace" ? (
            <>
              <div className="row two-col">
                <label>
                  Status
                  <select
                    value={traceStatusFilter}
                    onChange={(event) =>
                      setTraceStatusFilter(event.target.value as RuleTraceFilterStatus)
                    }
                  >
                    {RULE_TRACE_STATUS_OPTIONS.map((status) => (
                      <option key={status} value={status}>
                        {status} ({ruleTraceCounts[status]})
                      </option>
                    ))}
                  </select>
                </label>
                <label>
                  Recommendation
                  <select
                    value={traceRecommendationFilter}
                    onChange={(event) => setTraceRecommendationFilter(event.target.value)}
                  >
                    <option value="all">all recommendations</option>
                    {report.recommendations.map((recommendation) => (
                      <option key={recommendation.id} value={recommendation.id}>
                        {recommendation.id}
                      </option>
                    ))}
                  </select>
                </label>
              </div>

              <div className="row">
                <button
                  onClick={() => {
                    setTraceStatusFilter("all");
                    setTraceRecommendationFilter("all");
                  }}
                >
                  Reset Filters
                </button>
                {selectedRecommendation ? (
                  <button onClick={() => setTraceRecommendationFilter(selectedRecommendation.id)}>
                    Focus Selected Recommendation
                  </button>
                ) : null}
              </div>

              <div className="scroll-block">
                {filteredRuleTraces.length === 0 ? (
                  <p className="muted">No rule traces match the current filters.</p>
                ) : null}
                {filteredRuleTraces.map((trace, index) => {
                  const linkedRecommendation =
                    trace.recommendation_id === null || trace.recommendation_id === undefined
                      ? null
                      : report.recommendations.find(
                          (recommendation) => recommendation.id === trace.recommendation_id
                        ) ?? null;

                  return (
                    <article key={`${trace.rule_id}-${index}`} className="card">
                      <div className="title-row">
                        <h3>{trace.rule_id}</h3>
                        <span className={`badge status-${trace.status}`}>{trace.status}</span>
                      </div>
                      <p>{trace.detail}</p>
                      <p>confidence {formatConfidence(trace.confidence)}</p>
                      <p>recommendation {trace.recommendation_id ?? "none"}</p>
                      {linkedRecommendation ? (
                        <div className="row end">
                          <button onClick={() => focusRecommendation(linkedRecommendation.id)}>
                            Open Recommendation Inspector
                          </button>
                        </div>
                      ) : null}
                    </article>
                  );
                })}
              </div>
            </>
          ) : null}
        </section>
      ) : null}

      {screen === "doctor" ? (
        <section className="panel">
          <h2>Doctor</h2>
          {!doctorInfo ? <p>Loading doctor data...</p> : null}
          {doctorInfo ? (
            <>
              <p>
                OS {doctorInfo.os} ({doctorInfo.arch}) | read-only {doctorInfo.read_only_mode ? "yes" : "no"}
              </p>
              <p>Detected disks: {doctorInfo.disks.length}</p>
              <ul className="list compact">
                {doctorInfo.disks.map((disk) => (
                  <li key={disk.mount_point}>
                    {disk.mount_point} {disk.name} | locality {disk.locality_class} | role {disk.role_hint.role}
                  </li>
                ))}
              </ul>
            </>
          ) : null}
        </section>
      ) : null}

      {screen === "compare" && reportDiff ? (
        <section className="panel">
          <div className="title-row">
            <h2>Report Compare</h2>
            <div className="row">
              <button onClick={exportCompareJson}>Export Compare JSON</button>
              <button onClick={() => setScreen("setup")}>Back To Library</button>
            </div>
          </div>
          <p>
            {reportDiff.left_scan_id} ({reportDiff.left_generated_at}) {"->"} {reportDiff.right_scan_id} (
            {reportDiff.right_generated_at})
          </p>
          <article className="card">
            <h3>Overview</h3>
            <p>duplicate waste delta {formatSignedBytes(reportDiff.duplicate_wasted_bytes_delta)}</p>
            <p>
              disk changes {reportDiff.disk_diffs.length} | path changes {reportDiff.path_diffs.length} |
              recommendation changes {reportDiff.recommendation_changes.length}
            </p>
          </article>

          <div className="split-pane">
            <div className="list-pane">
              <article className="card">
                <h3>Disk Changes</h3>
                {reportDiff.disk_diffs.length === 0 ? (
                  <p className="muted">No disk free-space changes detected.</p>
                ) : null}
                {reportDiff.disk_diffs.map((disk) => (
                  <div key={disk.mount_point} className="detail-block">
                    <p>
                      <strong>{disk.mount_point}</strong> {disk.name ?? ""}
                    </p>
                    <p>
                      left {formatBytes(disk.left_free_space_bytes)} | right{" "}
                      {formatBytes(disk.right_free_space_bytes)}
                    </p>
                    <p>delta {formatSignedBytes(disk.free_space_delta_bytes)}</p>
                  </div>
                ))}
              </article>
            </div>

            <div className="inspector-pane">
              <article className="card">
                <h3>Path Growth</h3>
                {reportDiff.path_diffs.length === 0 ? (
                  <p className="muted">No path growth or shrinkage detected.</p>
                ) : null}
                {reportDiff.path_diffs.map((path) => (
                  <div key={path.root_path} className="detail-block">
                    <p>
                      <strong>{path.root_path}</strong>
                    </p>
                    <p>
                      left {formatBytes(path.left_total_size_bytes)} | right{" "}
                      {formatBytes(path.right_total_size_bytes)}
                    </p>
                    <p>delta {formatSignedBytes(path.total_size_delta_bytes)}</p>
                  </div>
                ))}
              </article>

              <article className="card">
                <h3>Recommendation Changes</h3>
                {reportDiff.recommendation_changes.length === 0 ? (
                  <p className="muted">No recommendation changes detected.</p>
                ) : null}
                {reportDiff.recommendation_changes.map((change, index) => (
                  <div key={`${change.id}-${change.change}-${index}`} className="detail-block">
                    <p>
                      <strong>{change.id}</strong> <span className="badge">{change.change}</span>
                    </p>
                    <p>
                      confidence {formatConfidence(change.left_confidence)} {"->"}{" "}
                      {formatConfidence(change.right_confidence)}
                    </p>
                    <p>
                      target {change.left_target_mount ?? "none"} {"->"}{" "}
                      {change.right_target_mount ?? "none"}
                    </p>
                  </div>
                ))}
              </article>
            </div>
          </div>
        </section>
      ) : null}
    </main>
  );
}

export default App;
