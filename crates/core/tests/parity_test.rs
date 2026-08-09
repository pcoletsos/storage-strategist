//! Backend parity gate.
//!
//! `native` and `pdu_library` must agree on what they traversed. The suite runs
//! both backends over a fixed catalogue of synthetic tree shapes and fails when
//! any unexplained delta appears.

use anyhow::Result;
use std::path::PathBuf;
use storage_strategist_core::parity::{run_parity_suite, ParityTolerances, EXPECTED_SHAPE_COUNT};
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
    assert_eq!(
        report.total_shapes, EXPECTED_SHAPE_COUNT,
        "the shape catalogue changed size; a dropped shape must not slide past the gate"
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

/// A directory that stats but cannot be read must not register as backend drift.
///
/// pdu's `get_info` discards the size it computed for such a directory, so the
/// normalization has to discard it too. Counting it would over-subtract and turn
/// a permission error into a gate failure, which contradicts the repo rule that
/// permission and IO failures degrade to warnings.
#[cfg(unix)]
#[test]
fn an_unreadable_directory_is_not_reported_as_drift() -> Result<()> {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    let workspace = tempdir()?;
    let root = workspace.path().join("tree");
    let open = root.join("open");
    let locked = root.join("locked");
    fs::create_dir_all(&open)?;
    fs::create_dir_all(&locked)?;
    fs::write(open.join("a.bin"), vec![0_u8; 4096])?;
    fs::write(locked.join("hidden.bin"), vec![0_u8; 8192])?;
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o000))?;

    // Root can read through mode 000, which would make the assertion vacuous.
    let enforced = fs::read_dir(&locked).is_err();

    let options = ScanOptions {
        paths: vec![root.clone()],
        incremental_cache: false,
        record_history: false,
        ..Default::default()
    };
    let parity = compare_backends(&options);

    // Restore permissions before any early return so cleanup can succeed.
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o755))?;
    let parity = parity?;

    if !enforced {
        eprintln!("skipping: this process can read a mode-000 directory");
        return Ok(());
    }

    println!("unreadable-directory parity: {parity:?}");
    assert_eq!(
        parity.normalized_scanned_bytes_delta, 0,
        "a permission error must not surface as unexplained drift"
    );
    assert_eq!(parity.scanned_files_delta, 0);

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
