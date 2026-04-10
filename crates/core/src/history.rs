use crate::model::ScanHistory;
use crate::reports::history_file_path;
use anyhow::Result;
use std::fs;
use std::path::Path;

pub fn load_history(custom_dir: Option<&Path>) -> Result<ScanHistory> {
    let path = history_file_path(custom_dir);
    if !path.exists() {
        return Ok(ScanHistory::default());
    }

    let payload = fs::read_to_string(path)?;
    let history: ScanHistory = serde_json::from_str(&payload)?;
    Ok(history)
}

pub fn save_history(history: &ScanHistory, custom_dir: Option<&Path>) -> Result<()> {
    let path = history_file_path(custom_dir);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let payload = serde_json::to_string_pretty(history)?;
    fs::write(path, payload)?;
    Ok(())
}
