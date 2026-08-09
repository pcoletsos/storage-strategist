//! Backend parity suite.
//!
//! The suite materializes a fixed set of synthetic directory shapes into a
//! scratch workspace, scans each one with both the `native` and `pdu_library`
//! backends, and reports the deltas alongside the tolerances that were applied.
//!
//! The shapes are deliberately small and deterministic so the gate measures
//! backend behavior rather than machine state. Nothing here touches user data:
//! every byte written lives under the caller-provided workspace directory.

use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use chrono::{SecondsFormat, Utc};
use serde::{Deserialize, Serialize};

use crate::model::BackendParity;
use crate::scan::{compare_backends, ScanOptions};

/// Schema version for the emitted parity artifact. Bump when the artifact shape
/// changes in a way that breaks `scripts/check_parity_thresholds.py`.
pub const PARITY_SUITE_SCHEMA_VERSION: u32 = 1;

/// Number of shapes the catalogue is expected to produce on this platform.
///
/// Checked at build time so a shape that silently stops being generated fails
/// here rather than sliding under a minimum-count floor in CI. Update this
/// deliberately when adding or removing a shape.
#[cfg(unix)]
pub const EXPECTED_SHAPE_COUNT: usize = 8;
#[cfg(not(unix))]
pub const EXPECTED_SHAPE_COUNT: usize = 7;

/// Tolerances applied to every shape in the suite.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ParityTolerances {
    /// Maximum allowed absolute difference in scanned file counts.
    pub max_scanned_files_delta: i64,
    /// Maximum allowed absolute byte delta once the known accounting terms
    /// (directory and symlink entries) have been removed.
    pub max_normalized_bytes_delta: i64,
    /// Maximum allowed residual byte delta as a ratio of the native total.
    ///
    /// This is the proportional companion to `max_normalized_bytes_delta`: the
    /// absolute limit protects small fixtures, the ratio protects large real
    /// trees where an exact match is unrealistic. Both measure the residual, so
    /// neither trips on the known accounting terms.
    pub max_residual_bytes_delta_ratio: f32,
    /// Fail a shape when the `pdu_library` run quietly fell back to the native
    /// walker, since agreement would then be meaningless.
    pub require_pdu_summary: bool,
}

impl Default for ParityTolerances {
    fn default() -> Self {
        Self {
            max_scanned_files_delta: 0,
            max_normalized_bytes_delta: 0,
            max_residual_bytes_delta_ratio: 0.005,
            require_pdu_summary: true,
        }
    }
}

/// One synthetic tree shape and the traversal property it exercises.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ParityShapeSpec {
    pub name: String,
    pub description: String,
    pub root: PathBuf,
}

/// Parity outcome for a single shape.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ParityShapeReport {
    pub name: String,
    pub description: String,
    pub passed: bool,
    pub failures: Vec<String>,
    #[serde(flatten)]
    pub parity: BackendParity,
}

/// Full suite result. This is the JSON artifact CI uploads on failure.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ParitySuiteReport {
    pub schema_version: u32,
    pub generated_at: String,
    pub platform: String,
    pub pdu_backend_feature_enabled: bool,
    pub tolerances: ParityTolerances,
    pub total_shapes: usize,
    pub passed_shapes: usize,
    pub failed_shapes: usize,
    pub passed: bool,
    pub shapes: Vec<ParityShapeReport>,
}

/// Materialize the synthetic shapes under `workspace` and compare both backends
/// on each one.
///
/// `workspace` must not already contain entries; the suite refuses to write into
/// a populated directory so it can never disturb existing files.
pub fn run_parity_suite(
    workspace: &Path,
    tolerances: &ParityTolerances,
) -> Result<ParitySuiteReport> {
    let shapes = materialize_parity_shapes(workspace)?;

    let mut reports = Vec::with_capacity(shapes.len());
    for shape in &shapes {
        let options = ScanOptions {
            paths: vec![shape.root.clone()],
            excludes: Vec::new(),
            dedupe: false,
            incremental_cache: false,
            record_history: false,
            emit_progress_events: false,
            progress: false,
            dry_run: true,
            ..ScanOptions::default()
        };

        let parity = compare_backends(&options)
            .with_context(|| format!("parity comparison failed for shape {}", shape.name))?;
        let failures = evaluate_shape(&parity, tolerances);

        reports.push(ParityShapeReport {
            name: shape.name.clone(),
            description: shape.description.clone(),
            passed: failures.is_empty(),
            failures,
            parity,
        });
    }

    let passed_shapes = reports.iter().filter(|shape| shape.passed).count();
    let failed_shapes = reports.len() - passed_shapes;

    Ok(ParitySuiteReport {
        schema_version: PARITY_SUITE_SCHEMA_VERSION,
        generated_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        platform: std::env::consts::OS.to_string(),
        pdu_backend_feature_enabled: cfg!(feature = "pdu-backend"),
        tolerances: tolerances.clone(),
        total_shapes: reports.len(),
        passed_shapes,
        failed_shapes,
        passed: failed_shapes == 0,
        shapes: reports,
    })
}

fn evaluate_shape(parity: &BackendParity, tolerances: &ParityTolerances) -> Vec<String> {
    let mut failures = Vec::new();

    if tolerances.require_pdu_summary && !parity.pdu_summary_applied {
        failures.push(
            "pdu_library run fell back to the native walker, so backend agreement is not meaningful"
                .to_string(),
        );
    }

    let files_delta = parity.scanned_files_delta.abs();
    if files_delta > tolerances.max_scanned_files_delta {
        failures.push(format!(
            "scanned_files_delta {} exceeds maximum {} (native={}, pdu_library={})",
            parity.scanned_files_delta,
            tolerances.max_scanned_files_delta,
            parity.native_scanned_files,
            parity.pdu_library_scanned_files
        ));
    }

    let normalized_delta = parity.normalized_scanned_bytes_delta.abs();
    if normalized_delta > tolerances.max_normalized_bytes_delta {
        failures.push(format!(
            "normalized_scanned_bytes_delta {} exceeds maximum {} \
             (raw delta={}, directory_entry_bytes={}, symlink_entry_bytes={})",
            parity.normalized_scanned_bytes_delta,
            tolerances.max_normalized_bytes_delta,
            parity.scanned_bytes_delta,
            parity.directory_entry_bytes,
            parity.symlink_entry_bytes
        ));
    }

    let denominator = parity.native_scanned_bytes.max(1) as f64;
    let residual_ratio = normalized_delta as f64 / denominator;
    if residual_ratio > tolerances.max_residual_bytes_delta_ratio as f64 {
        failures.push(format!(
            "residual byte delta ratio {residual_ratio:.4} exceeds maximum {:.4}",
            tolerances.max_residual_bytes_delta_ratio
        ));
    }

    failures
}

/// Build every parity shape under `workspace` and return their specs.
pub fn materialize_parity_shapes(workspace: &Path) -> Result<Vec<ParityShapeSpec>> {
    ensure_empty_workspace(workspace)?;

    // `mut` is only used on Unix, where the symlink shape is available.
    #[allow(unused_mut)]
    let mut shapes = vec![
        build_flat_files(workspace)?,
        build_deep_chain(workspace)?,
        build_wide_fanout(workspace)?,
        build_empty_and_zero_byte(workspace)?,
        build_mixed_sizes(workspace)?,
        build_unicode_and_spaces(workspace)?,
        build_hidden_entries(workspace)?,
    ];
    #[cfg(unix)]
    shapes.push(build_symlinks(workspace)?);

    if shapes.len() != EXPECTED_SHAPE_COUNT {
        return Err(anyhow!(
            "parity catalogue produced {} shape(s), expected {}; \
             a shape was added or dropped without updating EXPECTED_SHAPE_COUNT",
            shapes.len(),
            EXPECTED_SHAPE_COUNT
        ));
    }

    Ok(shapes)
}

fn ensure_empty_workspace(workspace: &Path) -> Result<()> {
    if workspace.exists() {
        if !workspace.is_dir() {
            return Err(anyhow!(
                "parity workspace {} exists and is not a directory",
                workspace.display()
            ));
        }
        let mut entries = fs::read_dir(workspace)
            .with_context(|| format!("failed to read {}", workspace.display()))?;
        if entries.next().is_some() {
            return Err(anyhow!(
                "parity workspace {} is not empty; refusing to write fixtures into it",
                workspace.display()
            ));
        }
        return Ok(());
    }

    fs::create_dir_all(workspace)
        .with_context(|| format!("failed to create parity workspace {}", workspace.display()))
}

fn build_flat_files(workspace: &Path) -> Result<ParityShapeSpec> {
    let root = shape_root(workspace, "flat-files")?;
    for index in 0..48 {
        write_file(&root.join(format!("file-{index:03}.bin")), 512 + index * 97)?;
    }
    Ok(ParityShapeSpec {
        name: "flat-files".to_string(),
        description: "single directory holding many small files".to_string(),
        root,
    })
}

fn build_deep_chain(workspace: &Path) -> Result<ParityShapeSpec> {
    let root = shape_root(workspace, "deep-chain")?;
    let mut current = root.clone();
    for level in 0..12 {
        current = current.join(format!("level-{level:02}"));
        fs::create_dir_all(&current)
            .with_context(|| format!("failed to create {}", current.display()))?;
        write_file(&current.join("payload.bin"), 256 + level * 64)?;
    }
    Ok(ParityShapeSpec {
        name: "deep-chain".to_string(),
        description: "single deeply nested chain of directories".to_string(),
        root,
    })
}

fn build_wide_fanout(workspace: &Path) -> Result<ParityShapeSpec> {
    let root = shape_root(workspace, "wide-fanout")?;
    for bucket in 0..24 {
        let dir = root.join(format!("bucket-{bucket:02}"));
        fs::create_dir_all(&dir).with_context(|| format!("failed to create {}", dir.display()))?;
        for index in 0..4 {
            write_file(&dir.join(format!("item-{index}.bin")), 1024 + index * 31)?;
        }
    }
    Ok(ParityShapeSpec {
        name: "wide-fanout".to_string(),
        description: "wide sibling fan-out with uniform child directories".to_string(),
        root,
    })
}

fn build_empty_and_zero_byte(workspace: &Path) -> Result<ParityShapeSpec> {
    let root = shape_root(workspace, "empty-and-zero-byte")?;
    for index in 0..8 {
        let dir = root.join(format!("empty-{index:02}"));
        fs::create_dir_all(&dir).with_context(|| format!("failed to create {}", dir.display()))?;
    }
    for index in 0..4 {
        write_file(&root.join(format!("zero-{index}.bin")), 0)?;
    }
    write_file(&root.join("populated.bin"), 4096)?;
    Ok(ParityShapeSpec {
        name: "empty-and-zero-byte".to_string(),
        description: "empty directories mixed with zero-length files".to_string(),
        root,
    })
}

fn build_mixed_sizes(workspace: &Path) -> Result<ParityShapeSpec> {
    let root = shape_root(workspace, "mixed-sizes")?;
    let large = root.join("large");
    fs::create_dir_all(&large).with_context(|| format!("failed to create {}", large.display()))?;
    write_file(&large.join("bulk.bin"), 4 * 1024 * 1024)?;

    let medium = root.join("medium");
    fs::create_dir_all(&medium)
        .with_context(|| format!("failed to create {}", medium.display()))?;
    for index in 0..2 {
        write_file(&medium.join(format!("chunk-{index}.bin")), 256 * 1024)?;
    }

    for index in 0..20 {
        write_file(&root.join(format!("tiny-{index:02}.bin")), 1024)?;
    }

    Ok(ParityShapeSpec {
        name: "mixed-sizes".to_string(),
        description: "large, medium, and tiny files in one tree".to_string(),
        root,
    })
}

fn build_unicode_and_spaces(workspace: &Path) -> Result<ParityShapeSpec> {
    let root = shape_root(workspace, "unicode-and-spaces")?;
    let nested = root.join("φάκελος με κενά");
    fs::create_dir_all(&nested)
        .with_context(|| format!("failed to create {}", nested.display()))?;
    write_file(&nested.join("αρχείο δοκιμής.bin"), 2048)?;
    write_file(&nested.join("naïve café.bin"), 3072)?;
    write_file(&root.join("file with spaces.bin"), 1536)?;
    write_file(&root.join("日本語.bin"), 777)?;
    Ok(ParityShapeSpec {
        name: "unicode-and-spaces".to_string(),
        description: "non-ASCII and space-bearing file and directory names".to_string(),
        root,
    })
}

fn build_hidden_entries(workspace: &Path) -> Result<ParityShapeSpec> {
    let root = shape_root(workspace, "hidden-entries")?;
    let hidden_dir = root.join(".hidden-dir");
    fs::create_dir_all(&hidden_dir)
        .with_context(|| format!("failed to create {}", hidden_dir.display()))?;
    write_file(&hidden_dir.join("payload.bin"), 2048)?;
    write_file(&hidden_dir.join(".nested-dotfile"), 512)?;
    write_file(&root.join(".dotfile"), 1024)?;
    write_file(&root.join("visible.bin"), 1024)?;
    Ok(ParityShapeSpec {
        name: "hidden-entries".to_string(),
        description: "dot-prefixed files and directories".to_string(),
        root,
    })
}

#[cfg(unix)]
fn build_symlinks(workspace: &Path) -> Result<ParityShapeSpec> {
    let root = shape_root(workspace, "symlinks")?;
    let target_dir = root.join("target-dir");
    fs::create_dir_all(&target_dir)
        .with_context(|| format!("failed to create {}", target_dir.display()))?;
    write_file(&target_dir.join("real.bin"), 4096)?;
    write_file(&root.join("real-file.bin"), 2048)?;

    std::os::unix::fs::symlink("real-file.bin", root.join("link-to-file"))
        .context("failed to create file symlink")?;
    std::os::unix::fs::symlink("target-dir", root.join("link-to-dir"))
        .context("failed to create directory symlink")?;
    std::os::unix::fs::symlink("missing-target.bin", root.join("broken-link"))
        .context("failed to create broken symlink")?;

    Ok(ParityShapeSpec {
        name: "symlinks".to_string(),
        description: "file, directory, and broken symlinks that must not be followed".to_string(),
        root,
    })
}

fn shape_root(workspace: &Path, name: &str) -> Result<PathBuf> {
    let root = workspace.join(name);
    fs::create_dir_all(&root)
        .with_context(|| format!("failed to create shape root {}", root.display()))?;
    Ok(root)
}

/// Write `size` deterministic bytes so repeated runs produce identical trees.
fn write_file(path: &Path, size: usize) -> Result<()> {
    let mut file =
        File::create(path).with_context(|| format!("failed to create {}", path.display()))?;
    if size == 0 {
        return Ok(());
    }

    let block: Vec<u8> = (0..4096u32).map(|index| (index % 251) as u8).collect();
    let mut remaining = size;
    while remaining > 0 {
        let take = remaining.min(block.len());
        file.write_all(&block[..take])
            .with_context(|| format!("failed to write {}", path.display()))?;
        remaining -= take;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn materializes_every_shape_once() {
        let workspace = tempdir().expect("tempdir");
        let shapes = materialize_parity_shapes(workspace.path()).expect("materialize");

        assert!(shapes.len() >= 7, "expected the full shape catalogue");
        for shape in &shapes {
            assert!(shape.root.is_dir(), "shape {} has no root", shape.name);
            assert!(
                !shape.description.trim().is_empty(),
                "shape {} needs a description",
                shape.name
            );
        }
    }

    #[test]
    fn refuses_to_write_into_a_populated_workspace() {
        let workspace = tempdir().expect("tempdir");
        fs::write(workspace.path().join("existing.txt"), b"user data").expect("seed");

        let error = materialize_parity_shapes(workspace.path()).expect_err("must refuse");
        assert!(
            error.to_string().contains("is not empty"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn flags_a_silent_backend_fallback() {
        let parity = BackendParity {
            pdu_summary_applied: false,
            ..BackendParity::default()
        };

        let failures = evaluate_shape(&parity, &ParityTolerances::default());
        assert!(
            failures.iter().any(|entry| entry.contains("fell back")),
            "expected a fallback failure, got {failures:?}"
        );
    }

    #[test]
    fn accepts_a_pure_non_file_entry_difference() {
        let parity = BackendParity {
            pdu_summary_applied: true,
            native_scanned_files: 10,
            pdu_library_scanned_files: 10,
            native_scanned_bytes: 1_000_000,
            pdu_library_scanned_bytes: 1_012_329,
            scanned_bytes_delta: 12_329,
            directory_entry_bytes: 12_288,
            symlink_entry_bytes: 41,
            normalized_scanned_bytes_delta: 0,
            ..BackendParity::default()
        };

        assert!(evaluate_shape(&parity, &ParityTolerances::default()).is_empty());
    }

    #[test]
    fn accepts_a_directory_heavy_tree_with_no_residual() {
        // A deeply nested tree of tiny files makes the directory-entry term a
        // large fraction of the total. That must not read as backend drift.
        let parity = BackendParity {
            pdu_summary_applied: true,
            native_scanned_bytes: 7_296,
            pdu_library_scanned_bytes: 8_800,
            scanned_bytes_delta: 1_504,
            directory_entry_bytes: 1_504,
            normalized_scanned_bytes_delta: 0,
            ..BackendParity::default()
        };

        assert!(evaluate_shape(&parity, &ParityTolerances::default()).is_empty());
    }

    #[test]
    fn rejects_a_residual_byte_divergence() {
        let parity = BackendParity {
            pdu_summary_applied: true,
            native_scanned_bytes: 1_000_000,
            pdu_library_scanned_bytes: 1_016_384,
            scanned_bytes_delta: 16_384,
            directory_entry_bytes: 12_288,
            normalized_scanned_bytes_delta: 4_096,
            ..BackendParity::default()
        };

        let failures = evaluate_shape(&parity, &ParityTolerances::default());
        assert!(
            failures
                .iter()
                .any(|entry| entry.contains("normalized_scanned_bytes_delta")),
            "expected a normalized delta failure, got {failures:?}"
        );
    }

    /// `scripts/check_parity_thresholds.py` reads the per-shape parity fields at
    /// the top level of each shape object, which the `flatten` attribute
    /// provides. Round-tripping keeps that contract from drifting.
    #[test]
    fn artifact_round_trips_with_flattened_parity_fields() {
        let workspace = tempdir().expect("tempdir");
        let report =
            run_parity_suite(workspace.path(), &ParityTolerances::default()).expect("suite");

        let payload = serde_json::to_value(&report).expect("serialize");
        let first = &payload["shapes"][0];
        assert!(
            first.get("normalized_scanned_bytes_delta").is_some(),
            "parity fields must be flattened into the shape object"
        );
        assert!(first.get("pdu_summary_applied").is_some());

        let restored: ParitySuiteReport = serde_json::from_value(payload).expect("deserialize");
        assert_eq!(restored, report);
    }

    #[test]
    fn rejects_a_file_count_divergence() {
        let parity = BackendParity {
            pdu_summary_applied: true,
            native_scanned_files: 100,
            pdu_library_scanned_files: 98,
            scanned_files_delta: -2,
            ..BackendParity::default()
        };

        let failures = evaluate_shape(&parity, &ParityTolerances::default());
        assert!(
            failures
                .iter()
                .any(|entry| entry.contains("scanned_files_delta")),
            "expected a file count failure, got {failures:?}"
        );
    }
}
