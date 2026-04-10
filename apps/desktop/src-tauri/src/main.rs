#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::PathBuf;

use storage_strategist_core::{
    DiagnosticsBundle, DoctorInfo, RecommendationBundle, Report, ReportDiff, ReportImportResult,
    ReportSummary, ScanProgressEvent, ScenarioPlan,
};
use storage_strategist_service::{
    cancel_scan as service_cancel_scan, compare_reports as service_compare_reports,
    doctor as service_doctor, export_diagnostics_bundle as service_export_diagnostics_bundle,
    export_markdown_summary as service_export_markdown_summary,
    export_report_diff as service_export_report_diff, generate_recommendations_from_report,
    get_report as service_get_report, get_scan_session as service_get_scan_session,
    import_report as service_import_report, list_reports as service_list_reports,
    load_report as service_load_report, plan_scenarios_from_report as service_plan_scenarios_from_report,
    poll_scan_events as service_poll_scan_events, start_scan as service_start_scan,
    CancelScanResponse, ScanRequest, ScanSessionSnapshot,
};

#[tauri::command]
fn start_scan(request: ScanRequest) -> Result<String, String> {
    service_start_scan(request).map_err(|err| err.to_string())
}

#[tauri::command]
fn poll_scan_events(scan_id: String, from_seq: u64) -> Result<Vec<ScanProgressEvent>, String> {
    service_poll_scan_events(&scan_id, from_seq).map_err(|err| err.to_string())
}

#[tauri::command]
fn get_scan_session(scan_id: String) -> Result<ScanSessionSnapshot, String> {
    service_get_scan_session(&scan_id).map_err(|err| err.to_string())
}

#[tauri::command]
fn cancel_scan(scan_id: String) -> Result<CancelScanResponse, String> {
    service_cancel_scan(&scan_id).map_err(|err| err.to_string())
}

#[tauri::command]
fn load_report(path: String) -> Result<Report, String> {
    service_load_report(path).map_err(|err| err.to_string())
}

#[tauri::command]
fn list_reports() -> Result<Vec<ReportSummary>, String> {
    service_list_reports(None).map_err(|err| err.to_string())
}

#[tauri::command]
fn get_report(scan_id: String) -> Result<Report, String> {
    service_get_report(&scan_id, None).map_err(|err| err.to_string())
}

#[tauri::command]
fn import_report(path: String) -> Result<ReportImportResult, String> {
    service_import_report(path, None).map_err(|err| err.to_string())
}

#[tauri::command]
fn compare_reports(left_scan_id: String, right_scan_id: String) -> Result<ReportDiff, String> {
    service_compare_reports(&left_scan_id, &right_scan_id, None).map_err(|err| err.to_string())
}

#[tauri::command]
fn generate_recommendations(report: Report) -> Result<RecommendationBundle, String> {
    Ok(generate_recommendations_from_report(&report))
}

#[tauri::command]
fn plan_scenarios(report: Report) -> Result<ScenarioPlan, String> {
    Ok(service_plan_scenarios_from_report(&report))
}

#[tauri::command]
fn export_diagnostics_bundle(
    report: Report,
    output_path: String,
    source_report_path: Option<String>,
) -> Result<DiagnosticsBundle, String> {
    service_export_diagnostics_bundle(
        &report,
        output_path,
        source_report_path.map(PathBuf::from),
    )
    .map_err(|err| err.to_string())
}

#[tauri::command]
fn export_markdown_summary(report: Report, output_path: String) -> Result<(), String> {
    service_export_markdown_summary(&report, output_path).map_err(|err| err.to_string())
}

#[tauri::command]
fn export_report_diff(diff: ReportDiff, output_path: String) -> Result<(), String> {
    service_export_report_diff(&diff, output_path).map_err(|err| err.to_string())
}

#[tauri::command]
fn doctor() -> DoctorInfo {
    service_doctor()
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            start_scan,
            poll_scan_events,
            get_scan_session,
            cancel_scan,
            load_report,
            list_reports,
            get_report,
            import_report,
            compare_reports,
            generate_recommendations,
            plan_scenarios,
            export_diagnostics_bundle,
            export_markdown_summary,
            export_report_diff,
            doctor,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
