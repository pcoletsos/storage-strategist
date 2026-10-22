"""Tests for scripts/check_parity_thresholds.py.

The script is the last line of the backend parity gate in CI, and its hardening
(required fields, truncation detection, catalogue-sized minimum) is otherwise
guarded only by its own source. A regression such as reading a missing metric as
`0` would let a gate pass while measuring nothing, so each rule is pinned here.
"""

import io
import json
import os
import re
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SCRIPTS_DIR = os.path.join(REPO_ROOT, "scripts")
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)

import check_parity_thresholds as gate  # noqa: E402

PARITY_RS = os.path.join(REPO_ROOT, "crates", "core", "src", "parity.rs")


def make_shape(name, **overrides):
    """A shape that passes the default tolerances, with a directory term only."""
    shape = {
        "name": name,
        "description": f"{name} fixture",
        "passed": True,
        "failures": [],
        "native_elapsed_ms": 1,
        "pdu_library_elapsed_ms": 1,
        "scanned_files_delta": 0,
        "scanned_bytes_delta": 4096,
        "native_scanned_files": 4,
        "native_scanned_bytes": 10_000,
        "pdu_library_scanned_files": 4,
        "pdu_library_scanned_bytes": 14_096,
        "pdu_summary_applied": True,
        "directory_entry_bytes": 4096,
        "symlink_entry_bytes": 0,
        "normalized_scanned_bytes_delta": 0,
    }
    shape.update(overrides)
    return shape


def make_artifact(platform="linux", shape_count=None):
    if shape_count is None:
        shape_count = gate.default_min_shapes(platform)
    shapes = [make_shape(f"shape-{index}") for index in range(shape_count)]
    return {
        "schema_version": gate.SUPPORTED_SCHEMA_VERSION,
        "generated_at": "2026-10-22T00:00:00Z",
        "platform": platform,
        "pdu_backend_feature_enabled": True,
        "tolerances": {
            "max_scanned_files_delta": 0,
            "max_normalized_bytes_delta": 0,
            "max_residual_bytes_delta_ratio": 0.005,
            "require_pdu_summary": True,
        },
        "total_shapes": shape_count,
        "passed_shapes": shape_count,
        "failed_shapes": 0,
        "passed": True,
        "shapes": shapes,
    }


class TestCheckParityThresholds(unittest.TestCase):
    def run_gate(self, artifact, *extra_args):
        """Run the script against `artifact` (or a missing file when `None`)."""
        with tempfile.TemporaryDirectory() as temp_dir:
            path = os.path.join(temp_dir, "parity-result.json")
            if artifact is not None:
                with open(path, "w", encoding="utf-8") as handle:
                    json.dump(artifact, handle)

            stdout, stderr = io.StringIO(), io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                try:
                    code = gate.main(["--input", path, *extra_args])
                except SystemExit as exc:
                    code = exc.code
            return code, stdout.getvalue(), stderr.getvalue()

    def assert_fails(self, artifact, expected_message, *extra_args):
        code, _, stderr = self.run_gate(artifact, *extra_args)
        self.assertEqual(code, 1, f"expected the gate to fail; stderr was:\n{stderr}")
        self.assertIn(expected_message, stderr)

    def test_complete_unix_artifact_passes(self):
        code, stdout, stderr = self.run_gate(make_artifact("linux"), "--require-pdu-backend")
        self.assertEqual(code, 0, stderr)
        self.assertIn("PASS", stdout)

    def test_complete_windows_artifact_passes(self):
        code, _, stderr = self.run_gate(make_artifact("windows"), "--require-pdu-backend")
        self.assertEqual(code, 0, stderr)

    def test_every_required_shape_field_is_enforced(self):
        # Removing any one field must fail outright rather than read as a
        # default. This is what keeps `.get(field, 0)` from creeping back in.
        for field in gate.REQUIRED_SHAPE_FIELDS:
            with self.subTest(field=field):
                artifact = make_artifact()
                del artifact["shapes"][3][field]
                code, _, stderr = self.run_gate(artifact)
                self.assertEqual(code, 1, f"missing {field} was accepted")
                self.assertIn("shapes[3] is missing required field(s)", stderr)
                self.assertIn(field, stderr)

    def test_required_fields_cover_every_metric_the_gate_reads(self):
        with open(gate.__file__, encoding="utf-8") as handle:
            source = handle.read()
        read_fields = set(re.findall(r'shape\["(\w+)"\]', source))
        self.assertTrue(read_fields, "no per-shape reads found in the script")
        self.assertLessEqual(read_fields, set(gate.REQUIRED_SHAPE_FIELDS))

    def test_shapes_dropped_from_the_list_are_rejected(self):
        artifact = make_artifact()
        artifact["shapes"].pop()
        # Lower the floor so only the truncation check can catch it.
        self.assert_fails(artifact, "it is truncated or malformed", "--min-shapes", "1")

    def test_missing_total_shapes_is_rejected(self):
        artifact = make_artifact()
        del artifact["total_shapes"]
        self.assert_fails(artifact, "has no 'total_shapes'")

    def test_non_integer_total_shapes_is_rejected(self):
        artifact = make_artifact()
        artifact["total_shapes"] = "9"
        self.assert_fails(artifact, "it is truncated or malformed")

    def test_retired_schema_version_is_rejected(self):
        artifact = make_artifact()
        artifact["schema_version"] = 1
        self.assert_fails(artifact, "schema_version 1 is not supported")

    def test_missing_schema_version_is_rejected(self):
        artifact = make_artifact()
        del artifact["schema_version"]
        self.assert_fails(artifact, "is not supported")

    def test_missing_shapes_list_is_rejected(self):
        artifact = make_artifact()
        del artifact["shapes"]
        self.assert_fails(artifact, "has no 'shapes' list")

    def test_missing_artifact_fails(self):
        self.assert_fails(None, "the suite did not complete")

    def test_default_minimum_is_the_full_unix_catalogue(self):
        artifact = make_artifact("linux", shape_count=gate.EXPECTED_SHAPES_UNIX - 1)
        self.assert_fails(artifact, f"below the minimum {gate.EXPECTED_SHAPES_UNIX}")

    def test_default_minimum_is_the_full_windows_catalogue(self):
        artifact = make_artifact("windows", shape_count=gate.EXPECTED_SHAPES_NON_UNIX - 1)
        self.assert_fails(artifact, f"below the minimum {gate.EXPECTED_SHAPES_NON_UNIX}")

    def test_unknown_platform_gets_the_larger_minimum(self):
        artifact = make_artifact("plan9", shape_count=gate.EXPECTED_SHAPES_NON_UNIX)
        self.assert_fails(artifact, f"below the minimum {gate.EXPECTED_SHAPES_UNIX}")

    def test_explicit_minimum_overrides_the_default(self):
        artifact = make_artifact("linux", shape_count=gate.EXPECTED_SHAPES_UNIX - 1)
        code, _, stderr = self.run_gate(
            artifact, "--min-shapes", str(gate.EXPECTED_SHAPES_UNIX - 1)
        )
        self.assertEqual(code, 0, stderr)

    def test_non_numeric_metric_is_rejected(self):
        artifact = make_artifact()
        artifact["shapes"][0]["scanned_files_delta"] = "lots"
        self.assert_fails(artifact, "has a non-numeric metric")

    def test_silent_backend_fallback_fails(self):
        artifact = make_artifact()
        artifact["shapes"][0]["pdu_summary_applied"] = False
        self.assert_fails(artifact, "fell back to the native walker")

    def test_file_count_divergence_fails(self):
        artifact = make_artifact()
        artifact["shapes"][0]["scanned_files_delta"] = -1
        self.assert_fails(artifact, "scanned_files_delta -1 exceeds maximum 0")

    def test_residual_byte_divergence_fails(self):
        artifact = make_artifact()
        artifact["shapes"][0]["normalized_scanned_bytes_delta"] = 1
        self.assert_fails(artifact, "residual byte delta 1 exceeds maximum 0")

    def test_residual_ratio_is_enforced_independently(self):
        artifact = make_artifact()
        artifact["shapes"][0]["normalized_scanned_bytes_delta"] = 100
        self.assert_fails(
            artifact,
            "residual byte delta ratio 0.01000 exceeds maximum 0.00500",
            "--max-normalized-bytes-delta",
            "1000",
        )

    def test_missing_pdu_backend_fails_when_required(self):
        artifact = make_artifact()
        artifact["pdu_backend_feature_enabled"] = False
        self.assert_fails(artifact, "without the pdu-backend feature", "--require-pdu-backend")

    def test_default_minimums_mirror_the_rust_catalogue(self):
        with open(PARITY_RS, encoding="utf-8") as handle:
            source = handle.read()
        counts = dict(
            re.findall(
                r"#\[cfg\((unix|not\(unix\))\)\]\s*"
                r"pub const EXPECTED_SHAPE_COUNT: usize = (\d+);",
                source,
            )
        )
        self.assertEqual(
            {cfg: int(count) for cfg, count in counts.items()},
            {
                "unix": gate.EXPECTED_SHAPES_UNIX,
                "not(unix)": gate.EXPECTED_SHAPES_NON_UNIX,
            },
            "update EXPECTED_SHAPES_* in scripts/check_parity_thresholds.py "
            "alongside EXPECTED_SHAPE_COUNT",
        )

    def test_schema_version_mirrors_the_rust_artifact(self):
        with open(PARITY_RS, encoding="utf-8") as handle:
            source = handle.read()
        match = re.search(r"pub const PARITY_SUITE_SCHEMA_VERSION: u32 = (\d+);", source)
        self.assertIsNotNone(match, "PARITY_SUITE_SCHEMA_VERSION not found")
        self.assertEqual(int(match.group(1)), gate.SUPPORTED_SCHEMA_VERSION)


if __name__ == "__main__":
    unittest.main()
