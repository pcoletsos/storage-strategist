//! Backend parity gate.
//!
//! `native` and `pdu_library` must agree on what they traversed. The suite runs
//! both backends over a fixed catalogue of synthetic tree shapes and fails when
//! any unexplained delta appears.

use anyhow::Result;
use std::path::PathBuf;
use storage_strategist_core::parity::{run_parity_suite, ParityTolerances};
use storage_strategist_core::scan::{compare_backends, ScanOptions};
use tempfile::tempdir;

#[test]
fn backends_agree_on_every_representative_tree_shape() -> Result<()> {
    let workspace = tempdir()?;
    let report = run_parity_suite(workspace.path(), &ParityTolerances::default())?;

    println!(
        "parity suite: {}/{} shapes passed on {}",
        report.passed_shapes, report.total_shapes, report.platform
    );
    for shape in &report.shapes {
        println!(
            "  [{}] {:<20} files_delta={} bytes_delta={} dirs={} symlinks={} residual={}",
            if shape.passed { "PASS" } else { "FAIL" },
            shape.name,
            shape.parity.scanned_files_delta,
            shape.parity.scanned_bytes_delta,
            shape.parity.directory_entry_bytes,
            shape.parity.symlink_entry_bytes,
            shape.parity.normalized_scanned_bytes_delta
        );
    }

    assert!(
        report.pdu_backend_feature_enabled,
        "the parity gate is meaningless without the pdu-backend feature"
    );
    assert!(
        report.total_shapes >= 7,
        "expected the full shape catalogue, got {}",
        report.total_shapes
    );

    let failed = report
        .shapes
        .iter()
        .filter(|shape| !shape.passed)
        .map(|shape| format!("{}: {}", shape.name, shape.failures.join("; ")))
        .collect::<Vec<_>>();
    assert!(
        failed.is_empty(),
        "backend parity violations:\n  {}",
        failed.join("\n  ")
    );

    Ok(())
}

/// Every difference the suite tolerates must be fully explained by the known
/// directory and symlink accounting terms. If a shape needs slack beyond that,
/// the gate is hiding a divergence instead of measuring it.
#[test]
fn tolerated_deltas_are_fully_explained_by_known_accounting_terms() -> Result<()> {
    let workspace = tempdir()?;
    let report = run_parity_suite(workspace.path(), &ParityTolerances::default())?;

    for shape in &report.shapes {
        let explained =
            shape.parity.directory_entry_bytes as i64 + shape.parity.symlink_entry_bytes as i64;
        assert_eq!(
            shape.parity.scanned_bytes_delta, explained,
            "shape {} has {} unexplained byte(s) of drift",
            shape.name, shape.parity.normalized_scanned_bytes_delta
        );
        assert!(
            shape.parity.pdu_summary_applied,
            "shape {} did not exercise the pdu_library summary path",
            shape.name
        );
    }

    Ok(())
}

/// The checked-in report fixtures are a flat directory of JSON files, so the two
/// backends must match on them byte for byte with no normalization at all.
#[test]
fn backends_match_exactly_on_checked_in_fixtures() -> Result<()> {
    let mut fixtures_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    fixtures_path.pop(); // crates
    fixtures_path.pop(); // workspace root
    fixtures_path.push("fixtures");

    assert!(
        fixtures_path.is_dir(),
        "fixtures directory not found at {}",
        fixtures_path.display()
    );

    let options = ScanOptions {
        paths: vec![fixtures_path],
        max_depth: None,
        incremental_cache: false,
        record_history: false,
        ..Default::default()
    };

    let parity = compare_backends(&options)?;
    println!("fixtures parity: {parity:?}");

    assert!(
        parity.pdu_summary_applied,
        "pdu_library summary was skipped"
    );
    assert_eq!(parity.scanned_files_delta, 0, "file count mismatch");
    assert_eq!(parity.scanned_bytes_delta, 0, "byte count mismatch");
    assert_eq!(parity.directory_entry_bytes, 0, "fixtures should be flat");
    assert!(parity.within_tolerance, "parity outside tolerance");

    Ok(())
}
