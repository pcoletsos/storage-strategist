# Default Backend Promotion Checkpoint

This document is the gate for changing the default scanner backend from `native`
to `pdu_library`. It defines what parity means, what is measured, which
differences are known and accepted, and which criteria must pass before the
default changes.

Promotion is a separate decision from this checkpoint. Adding parity coverage
does not authorize the switch; only the criteria below do.

## Current state

- Default backend: `native`
- `pdu_library` status: available, exercised in CI by the backend parity gate
- Blocking items for promotion: see [Open items](#open-items-before-promotion)

## What the two backends actually do

Both backends walk the tree with `walkdir` in `scan_root`, which is what
produces file-level records for categorization, dedupe, and recommendations.
They differ in how a root's total size and directory rollup are computed:

| Aspect | `native` | `pdu_library` |
|---|---|---|
| File records | walkdir | walkdir (same code path) |
| `total_size_bytes` | sum of regular file sizes | `parallel-disk-usage` tree total, minus the root directory entry |
| `largest_directories` | walkdir rollup by first path component | `parallel-disk-usage` tree children |
| Exclude patterns | applied | not supported, falls back to `native` |

Because `pdu_library` falls back to `native` when excludes are set or when the
`pdu-backend` feature is off, a parity run that silently fell back would show
perfect agreement while proving nothing. `BackendParity.pdu_summary_applied`
records whether the `parallel-disk-usage` path actually ran, and the gate fails
when it did not.

## Measured signals

`compare_backends(options)` runs both backends over the same roots and returns
`BackendParity`:

| Field | Meaning |
|---|---|
| `scanned_files_delta` | `pdu_library` file count minus `native` file count |
| `scanned_bytes_delta` | raw byte total difference |
| `directory_entry_bytes` | apparent size of non-root directory entries |
| `symlink_entry_bytes` | apparent size of symlink entries |
| `normalized_scanned_bytes_delta` | `scanned_bytes_delta` minus both accounting terms |
| `pdu_summary_applied` | whether the `parallel-disk-usage` summary drove the totals |
| `native_elapsed_ms`, `pdu_library_elapsed_ms` | wall-clock per backend |

`normalized_scanned_bytes_delta` is the number that matters. It is the portion
of the difference that no known accounting rule explains.

## Known accounting differences

These are real differences in what each backend counts. They are not traversal
disagreements, and they are normalized out of the gate rather than hidden by a
loose threshold.

1. **Directory entries.** `parallel-disk-usage` totals the apparent size of every
   entry it visits, including directories. The native sum counts regular files
   only. `build_pdu_tree_summary` already subtracts the root directory, so the
   residual is every non-root directory. The size is filesystem dependent:
   4096 bytes per directory on ext4, variable on APFS.
2. **Symlink entries.** `parallel-disk-usage` counts a symlink's own apparent
   size, which is the length of its target string. The native walker skips
   symlinks entirely because it does not follow links and only accumulates
   regular files. Neither backend descends through a symlinked directory.

Both terms make `Report.total_size_bytes` depend on which backend produced the
report. That is acceptable while `native` is the default and `pdu_library` is
opt-in. It is not acceptable after promotion, because the same scan would report
different totals before and after the switch.

## Parity gate

Run locally:

```bash
cargo run -p storage-strategist -- parity --suite --output parity-result.json
```

The suite materializes a fixed catalogue of synthetic tree shapes into a
temporary workspace, compares both backends on each, and writes a JSON artifact.
It never reads or writes user data: every byte it creates lives under the
workspace it made, and that workspace is removed unless `--workspace` named it.

Shapes covered:

| Shape | Property under test |
|---|---|
| `flat-files` | many small files in one directory |
| `deep-chain` | deep nesting, directory-heavy relative to file bytes |
| `wide-fanout` | wide sibling fan-out |
| `empty-and-zero-byte` | empty directories and zero-length files |
| `mixed-sizes` | large, medium, and tiny files together |
| `unicode-and-spaces` | non-ASCII and space-bearing names |
| `hidden-entries` | dot-prefixed files and directories |
| `symlinks` (Unix) | file, directory, and broken symlinks |

Tolerances enforced in CI (`backend parity` job) and by
`scripts/check_parity_thresholds.py`:

| Tolerance | Value | Rationale |
|---|---|---|
| `--max-files-delta` | `0` | Both backends walk the same tree with the same walker. Any file-count difference is a defect. |
| `--max-normalized-bytes-delta` | `0` | On synthetic fixtures every byte must be explained. |
| `--max-residual-bytes-delta-ratio` | `0.005` | Proportional companion for large or live trees where an exact match is unrealistic. |
| `--min-shapes` | `7` | Guards against the catalogue silently shrinking. |
| `--require-pdu-backend` | on | A run without the feature proves nothing. |
| `pdu_summary_applied` | must be true per shape | Catches a silent fallback to `native`. |

The job uploads `parity-result.json` with `if: always()`, so a failing run can be
triaged from the artifact without reproducing the tree locally. The artifact
carries absolute counters, both accounting terms, and per-shape failure text.

### Reading a failure

1. Download the `backend-parity-result` artifact from the failing job.
2. Find the shapes with `passed: false` and read their `failures` list.
3. If `pdu_summary_applied` is `false`, the `pdu_library` path did not run. Check
   for the `pdu-backend` feature and for exclude patterns before looking at
   deltas.
4. If `scanned_files_delta` is non-zero, the two walks disagree on what exists.
   That is a traversal defect, not an accounting one.
5. If `normalized_scanned_bytes_delta` is non-zero, a new accounting difference
   appeared. Identify it and either normalize it explicitly or fix the backend.
   Do not widen the tolerance to make it pass.

Widening a tolerance is a decision for the owner of this checkpoint, recorded
here, not a local fix inside a pull request that hit a red gate.

## Promotion criteria

All of the following must hold before `ScanBackendKind::PduLibrary` becomes the
default.

### Parity

- [ ] The parity suite passes on the supported OS matrix (Linux, macOS, Windows),
      not Linux alone.
- [ ] `normalized_scanned_bytes_delta` is `0` for every shape on every platform.
- [ ] `scanned_files_delta` is `0` for every shape on every platform.
- [ ] Directory and symlink accounting differences are eliminated at the source,
      so `Report.total_size_bytes` is identical under both backends. Normalizing
      inside the parity gate is sufficient for measurement, not for promotion.
- [ ] `pdu_library` supports exclude patterns, or the fallback to `native` is
      documented as intended behavior with its parity implications stated.
- [ ] Permission-denied and IO-error trees produce equivalent warnings and
      equivalent partial results under both backends.

### Performance

- [ ] A multi-run baseline exists for both backends on the supported OS matrix,
      with run-to-run variance recorded.
- [ ] `pdu_library` is at least as fast as `native` on the benchmark fixture, and
      the advantage is larger than the recorded variance.
- [ ] The benchmark regression threshold in `scripts/check_benchmark_regression.py`
      is tightened from `0.15` to `0.10` and stays green across consecutive runs.

### Safety and rollback

- [ ] The read-only posture is unchanged: no deletion, move, rename, or
      modification of scanned user files under either backend.
- [ ] `--backend native` remains an explicit override through at least the next
      minor release.
- [ ] `report_version` impact is assessed. If reported totals change for the same
      tree, that is a breaking change and the version is bumped rather than
      quietly shifted.
- [ ] The rollback is a one-line default change plus a release note, and it is
      tested before promotion ships.

## Open items before promotion

| Item | Status | Notes |
|---|---|---|
| Directory-entry accounting difference | Open | Normalized in the gate; must be fixed at the source before promotion |
| Symlink-entry accounting difference | Open | Same as above |
| Exclude-pattern support in `pdu_library` | Open | Currently falls back to `native` |
| Parity on the full OS matrix | Open | CI runs Linux only today |
| Multi-run performance baseline | Open | Tracked as ROADMAP P3 item 14 |
| Threshold tightening to 10% | Open | Blocked on the variance baseline |

## Recording the decision

When the criteria pass, record the promotion in a single pull request that:

1. links this document and the parity and benchmark artifacts that satisfied each
   criterion;
2. changes the default in `ScanOptions::default()` and the CLI `--backend`
   default together;
3. states the rollback step in the pull request body;
4. updates `ROADMAP.md`, `ARCHITECTURE.md`, `README.md`, and `CHANGELOG.md`.

If any criterion is waived, the waiver and its reason belong in this file before
the promotion pull request is opened.
