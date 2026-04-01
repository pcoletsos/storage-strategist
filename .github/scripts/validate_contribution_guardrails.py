#!/usr/bin/env python3
"""Validate pull request workflow guardrails for storage-strategist."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from typing import Iterable


ACTORS = ("codex", "claude", "copilot", "gemini", "local", "human")
TYPES = ("feat", "fix", "refactor", "chore", "docs", "test", "perf")
SCOPES = ("core", "cli", "desktop", "compliance", "infra", "docs", "shared")

BRANCH_RE = re.compile(
    rf"^(?:{'|'.join(ACTORS)})/"
    rf"(?:{'|'.join(TYPES)})/"
    rf"(?:{'|'.join(SCOPES)})/"
    r"[a-z0-9]+(?:-[a-z0-9]+)*-[0-9]+$"
)
TITLE_RE = re.compile(rf"^(?:{'|'.join(TYPES)})\((?:{'|'.join(SCOPES)})\): .+")
LINKED_ISSUE_LINE_RE = re.compile(r"(?im)^Linked issue:\s*(.+?)\s*$")
ISSUE_REF_RE = re.compile(r"#(?P<id>\d+)")
ISSUE_URL_RE = re.compile(r"/issues/(?P<id>\d+)")
SCOPED_PATHS = {
    "core": ("crates/core/",),
    "cli": ("crates/cli/",),
    "desktop": ("apps/desktop/",),
    "compliance": (
        "scripts/check_compliance.py",
        "provenance/",
        "THIRD_PARTY_NOTICES.md",
        "CODE_IMPORT_POLICY.md",
        "LICENSE",
    ),
    "infra": (
        ".github/",
        "Cargo.toml",
        "Cargo.lock",
        "benchmark-native.json",
        "benchmark-pdu.json",
        "benchmark-result.json",
        "demo-report.json",
        "demo-report-pdu.json",
        "demo-summary.md",
        "eval-result.json",
    ),
    "docs": (
        "AGENTS.md",
        "CLAUDE.md",
        "CONTRIBUTING.md",
        "DEVELOPMENT.md",
        "GEMINI.md",
        "README.md",
        "ROADMAP.md",
        "ARCHITECTURE.md",
        "CHANGELOG.md",
    ),
}
SCOPE_LABELS = SCOPES
VALIDATION_LABELS = (
    "fmt",
    "clippy",
    "test",
    "compliance checks",
    "desktop smoke",
    "Other validation is described below",
    "Not run (reason described below)",
)
DOCS_LABELS = (
    "No docs changes required",
    "Docs updated in this PR",
    "Docs follow-up issue linked below",
)
COMPLIANCE_LABELS = (
    "No compliance/provenance changes",
    "Compliance or provenance updates are included",
)
ROLLBACK_LABELS = (
    "Not risky / not production impacting",
    "Rollback plan included below",
)
TRIVIAL_CONTENT_LABEL = "This PR changes only `docs/**`, `*.md`, or `*.txt`"
TRIVIAL_EXCLUDE_LABEL = "This PR does not touch workflows, configs, schemas, scripts, or code"


def fail(message: str) -> None:
    errors.append(message)


def run(command: list[str]) -> str:
    return subprocess.check_output(command, text=True).strip()


def checked(body: str, label: str) -> bool:
    pattern = re.compile(rf"(?im)^- \[[xX]\] {re.escape(label)}\s*$")
    return bool(pattern.search(body))


def section_has_content(body: str, heading: str) -> bool:
    pattern = re.compile(rf"(?ims)^{re.escape(heading)}:\s*(.+?)(?:^\#\# |\Z)")
    match = pattern.search(body)
    if not match:
        return False
    content = match.group(1).strip()
    return bool(content and "<" not in content)


def allowed_trivial_path(path: str) -> bool:
    blocked_prefixes = (
        ".github/",
        "crates/",
        "apps/",
        "provenance/",
        "scripts/",
    )
    if path.startswith(blocked_prefixes):
        return False
    return path.startswith("docs/") or path.endswith(".md") or path.endswith(".txt")


def infer_scope(path: str) -> str | None:
    for scope, prefixes in SCOPED_PATHS.items():
        if any(path.startswith(prefix) for prefix in prefixes):
            return scope
    if path.startswith("fixtures/"):
        return "core"
    return None


def infer_scopes(paths: list[str]) -> set[str]:
    return {scope for path in paths if (scope := infer_scope(path))}


def fetch_issue(repo: str, issue_number: int) -> dict:
    token = os.environ["GITHUB_TOKEN"]
    url = f"https://api.github.com/repos/{repo}/issues/{issue_number}"
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "storage-strategist-contribution-guardrails",
        },
    )
    with urllib.request.urlopen(request) as response:
        return json.load(response)


def first_issue_reference(value: str) -> int | None:
    if not value:
        return None
    match = ISSUE_REF_RE.search(value) or ISSUE_URL_RE.search(value)
    if not match:
        return None
    return int(match.group("id"))


def require_any_checked(body: str, labels: Iterable[str], context: str) -> None:
    if not any(checked(body, label) for label in labels):
        fail(f"{context} must have at least one checked option.")


def selected_labels(body: str, labels: Iterable[str]) -> list[str]:
    return [label for label in labels if checked(body, label)]


def main() -> int:
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    base_ref = os.environ.get("BASE_REF")
    repo = os.environ.get("GITHUB_REPOSITORY")

    if not event_path or not base_ref or not repo:
        print("Required GitHub environment variables are missing.", file=sys.stderr)
        return 1

    with open(event_path, "r", encoding="utf-8") as handle:
        event = json.load(handle)

    pr = event.get("pull_request")
    if not pr:
        print("No pull_request payload detected; skipping.")
        return 0

    title = pr.get("title") or ""
    body = pr.get("body") or ""
    branch = pr["head"]["ref"]
    branch_parts = branch.split("/")
    branch_scope = branch_parts[2] if len(branch_parts) >= 3 else ""

    if not BRANCH_RE.fullmatch(branch):
        fail(
            "Branch name must match "
            "`<actor>/<type>/<scope>/<task>-<id>` using the canonical actor, type, and scope sets."
        )

    if not TITLE_RE.fullmatch(title):
        fail(
            "PR title must use Conventional Commit format "
            "`<type>(<scope>): <description>` using the canonical type and scope sets."
        )

    try:
        subprocess.run(
            ["git", "fetch", "--quiet", "origin", base_ref, "--depth", "1"],
            check=True,
        )
        changed_output = run(["git", "diff", "--name-only", f"origin/{base_ref}...HEAD"])
        changed_files = [line for line in changed_output.splitlines() if line]
    except subprocess.CalledProcessError as exc:
        fail(f"Unable to compute changed files against {base_ref}: {exc}")
        changed_files = []

    selected_scopes = selected_labels(body, SCOPE_LABELS)
    require_any_checked(body, SCOPE_LABELS, "Affected scope")
    require_any_checked(body, VALIDATION_LABELS, "Validation")
    require_any_checked(body, DOCS_LABELS, "Docs impact")
    require_any_checked(body, COMPLIANCE_LABELS, "Compliance impact")
    require_any_checked(body, ROLLBACK_LABELS, "Rollback notes")

    if branch_scope and branch_scope not in selected_scopes:
        fail(f"Branch scope `{branch_scope}` must be checked in the affected scope section.")

    if checked(body, "Other validation is described below") and not section_has_content(
        body, "Validation notes"
    ):
        fail("Validation notes must include the extra validation details when selected.")

    if checked(body, "Not run (reason described below)") and not section_has_content(
        body, "Validation notes"
    ):
        fail("Validation notes must explain why checks were not run.")

    if checked(body, "Screenshot(s) or preview link added below") and not section_has_content(
        body, "UI evidence"
    ):
        fail("UI evidence must include screenshots or preview details when selected.")

    if checked(body, "Docs updated in this PR") or checked(
        body, "Docs follow-up issue linked below"
    ):
        if not section_has_content(body, "Docs notes"):
            fail("Docs notes must include the docs detail or follow-up reference when selected.")

    if checked(body, "Compliance or provenance updates are included") and not section_has_content(
        body, "Compliance notes"
    ):
        fail("Compliance notes must describe the provenance or notices update when selected.")

    if checked(body, "Rollback plan included below") and not section_has_content(
        body, "Rollback plan"
    ):
        fail("Rollback plan details are required when the rollback checkbox is selected.")

    linked_issue_match = LINKED_ISSUE_LINE_RE.search(body)
    linked_issue_value = linked_issue_match.group(1).strip() if linked_issue_match else ""
    linked_issue_id = first_issue_reference(linked_issue_value)
    requested_trivial_exception = (
        checked(body, TRIVIAL_CONTENT_LABEL) and checked(body, TRIVIAL_EXCLUDE_LABEL)
    )
    changed_scopes = infer_scopes(changed_files)

    if branch_scope == "shared" and len(changed_scopes) == 1:
        fail(
            "`shared` scope is reserved for work without a clearly dominant single domain."
        )

    if branch_scope and len(changed_scopes) == 1:
        dominant_scope = next(iter(changed_scopes))
        if dominant_scope != branch_scope:
            fail(
                f"Branch scope `{branch_scope}` does not match the dominant changed-file scope "
                f"`{dominant_scope}`."
            )

    if requested_trivial_exception:
        invalid_trivial_paths = [path for path in changed_files if not allowed_trivial_path(path)]
        if invalid_trivial_paths:
            fail(
                "The trivial docs-only exception only allows changes in `docs/**`, `*.md`, or `*.txt`. "
                f"Disallowed paths: {', '.join(invalid_trivial_paths)}"
            )
        if linked_issue_id is not None:
            fail("Do not combine a linked issue with the docs-only no-issue exception.")
        if linked_issue_value and "none" not in linked_issue_value.lower():
            fail(
                "Use `Linked issue: none (trivial docs-only change)` when claiming the docs-only exception."
            )
    else:
        if not linked_issue_match:
            fail("PR body must include a `Linked issue:` line.")
        elif linked_issue_id is None:
            fail("Normal PRs must link a GitHub issue using `Linked issue: #123` or a full issue URL.")
        else:
            try:
                issue = fetch_issue(repo, linked_issue_id)
            except urllib.error.HTTPError as exc:
                fail(f"Linked issue #{linked_issue_id} could not be fetched: HTTP {exc.code}.")
            else:
                if issue.get("pull_request"):
                    fail(f"Linked issue #{linked_issue_id} is a pull request, not an issue.")
                if issue.get("milestone") is None:
                    fail(
                        f"Linked issue #{linked_issue_id} must have a milestone. "
                        "Use an existing thematic milestone or `Backlog`."
                    )

    compliance_paths = (
        "scripts/check_compliance.py",
        "provenance/",
        "THIRD_PARTY_NOTICES.md",
        "CODE_IMPORT_POLICY.md",
        "LICENSE",
    )
    if any(path.startswith(compliance_paths) or path in compliance_paths for path in changed_files):
        if not checked(body, "Compliance or provenance updates are included"):
            fail(
                "Compliance or provenance changes require the compliance impact section to acknowledge the update."
            )

    if any(path.startswith("apps/desktop/") for path in changed_files):
        if not (
            checked(body, "No visible UI changes")
            or checked(body, "Screenshot(s) or preview link added below")
        ):
            fail(
                "Visible desktop UI changes section must declare either no visible UI change or attached evidence."
            )

    if errors:
        print("Contribution guardrails failed:\n")
        for entry in errors:
            print(f"- {entry}")
        return 1

    print("Contribution guardrails passed.")
    if linked_issue_id:
        print(f"Linked issue #{linked_issue_id} is milestone-backed.")
    if requested_trivial_exception:
        print("Docs-only no-issue exception accepted.")
    return 0


errors: list[str] = []


if __name__ == "__main__":
    sys.exit(main())
