#!/usr/bin/env python3
"""Validate backend parity tolerances from a parity-suite JSON artifact.

The artifact is produced by:

    cargo run -p storage-strategist -- parity --suite --output parity-result.json

Thresholds are declared here (and in the workflow that calls this script) so the
agreed tolerances stay visible in CI rather than only inside the Rust defaults.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

SUPPORTED_SCHEMA_VERSION = 1

# Every per-shape metric the gate reads. These are required rather than
# defaulted: a missing field would otherwise read as perfect parity and the gate
# would pass while measuring nothing.
REQUIRED_SHAPE_FIELDS = (
    "name",
    "scanned_files_delta",
    "scanned_bytes_delta",
    "directory_entry_bytes",
    "symlink_entry_bytes",
    "normalized_scanned_bytes_delta",
    "native_scanned_bytes",
    "pdu_summary_applied",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate backend parity tolerances")
    parser.add_argument(
        "--input",
        required=True,
        type=Path,
        help="Parity suite result JSON path",
    )
    parser.add_argument(
        "--max-files-delta",
        type=int,
        default=0,
        help="Maximum allowed absolute scanned-file delta per shape (default: 0)",
    )
    parser.add_argument(
        "--max-normalized-bytes-delta",
        type=int,
        default=0,
        help=(
            "Maximum allowed absolute byte delta per shape after removing the "
            "known directory and symlink entry accounting terms (default: 0)"
        ),
    )
    parser.add_argument(
        "--max-residual-bytes-delta-ratio",
        type=float,
        default=0.005,
        help="Maximum allowed residual byte delta ratio per shape (default: 0.005)",
    )
    parser.add_argument(
        "--min-shapes",
        type=int,
        default=7,
        help="Minimum number of shapes the suite must have run (default: 7)",
    )
    parser.add_argument(
        "--require-pdu-backend",
        action="store_true",
        help="Fail when the artifact was produced without the pdu-backend feature",
    )
    return parser.parse_args()


def load_json(path: Path) -> dict:
    if not path.exists():
        print(
            f"ERROR: parity artifact {path} is missing; the suite did not complete",
            file=sys.stderr,
        )
        raise SystemExit(1)
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        print(f"ERROR: failed to read {path}: {exc}", file=sys.stderr)
        raise


def main() -> int:
    args = parse_args()
    payload = load_json(args.input)

    failures: list[str] = []

    schema_version = int(payload.get("schema_version", 0))
    if schema_version != SUPPORTED_SCHEMA_VERSION:
        print(
            f"ERROR: parity artifact schema_version {schema_version} is not supported "
            f"(expected {SUPPORTED_SCHEMA_VERSION})",
            file=sys.stderr,
        )
        return 1

    shapes = payload.get("shapes")
    if not isinstance(shapes, list):
        print("ERROR: parity artifact has no 'shapes' list", file=sys.stderr)
        return 1

    declared_total = payload.get("total_shapes")
    if declared_total is not None and int(declared_total) != len(shapes):
        print(
            f"ERROR: artifact declares {declared_total} shape(s) but carries "
            f"{len(shapes)}; it is truncated or malformed",
            file=sys.stderr,
        )
        return 1

    platform = payload.get("platform", "unknown")
    pdu_enabled = bool(payload.get("pdu_backend_feature_enabled", False))
    print(
        f"Backend parity: platform={platform} shapes={len(shapes)} "
        f"pdu_backend_feature={'on' if pdu_enabled else 'off'}"
    )

    if args.require_pdu_backend and not pdu_enabled:
        failures.append(
            "artifact was produced without the pdu-backend feature, so the "
            "comparison did not exercise parallel-disk-usage"
        )

    if len(shapes) < args.min_shapes:
        failures.append(
            f"suite ran {len(shapes)} shape(s), below the minimum {args.min_shapes}"
        )

    for index, shape in enumerate(shapes):
        if not isinstance(shape, dict):
            print(f"ERROR: shapes[{index}] is not an object", file=sys.stderr)
            return 1

        missing = [field for field in REQUIRED_SHAPE_FIELDS if field not in shape]
        if missing:
            print(
                f"ERROR: shapes[{index}] is missing required field(s): "
                f"{', '.join(missing)}. The artifact does not match schema version "
                f"{SUPPORTED_SCHEMA_VERSION}; the gate cannot verify parity from it.",
                file=sys.stderr,
            )
            return 1

        name = shape["name"]
        try:
            files_delta = int(shape["scanned_files_delta"])
            bytes_delta = int(shape["scanned_bytes_delta"])
            directory_bytes = int(shape["directory_entry_bytes"])
            symlink_bytes = int(shape["symlink_entry_bytes"])
            residual = int(shape["normalized_scanned_bytes_delta"])
            native_bytes = max(int(shape["native_scanned_bytes"]), 1)
        except (TypeError, ValueError) as exc:
            print(
                f"ERROR: shapes[{index}] ({name}) has a non-numeric metric: {exc}",
                file=sys.stderr,
            )
            return 1

        summary_applied = bool(shape["pdu_summary_applied"])
        residual_ratio = abs(residual) / native_bytes

        print(
            f"- {name}: files_delta={files_delta} bytes_delta={bytes_delta} "
            f"(dirs={directory_bytes} symlinks={symlink_bytes}) "
            f"residual={residual} residual_ratio={residual_ratio:.5f}"
        )

        if not summary_applied:
            failures.append(
                f"{name}: pdu_library fell back to the native walker, so backend "
                "agreement is not meaningful"
            )
        if abs(files_delta) > args.max_files_delta:
            failures.append(
                f"{name}: scanned_files_delta {files_delta} exceeds maximum "
                f"{args.max_files_delta}"
            )
        if abs(residual) > args.max_normalized_bytes_delta:
            failures.append(
                f"{name}: residual byte delta {residual} exceeds maximum "
                f"{args.max_normalized_bytes_delta}"
            )
        if residual_ratio > args.max_residual_bytes_delta_ratio:
            failures.append(
                f"{name}: residual byte delta ratio {residual_ratio:.5f} exceeds "
                f"maximum {args.max_residual_bytes_delta_ratio:.5f}"
            )

    if failures:
        for failure in failures:
            print(f"FAIL: {failure}", file=sys.stderr)
        print(
            "Download the parity-result artifact from this job for the full "
            "per-shape breakdown.",
            file=sys.stderr,
        )
        return 1

    print("PASS: backend parity tolerances satisfied")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
