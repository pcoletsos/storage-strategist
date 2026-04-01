# Contributing to Storage Strategist

`CONTRIBUTING.md` is the canonical workflow contract for this repository.
Agent-specific files such as `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, and
`.github/copilot-instructions.md` should point here instead of redefining the
process.

## Source of truth

- GitHub is the live source of truth for issues, milestones, pull requests, CI
  runs, and releases.
- `README.md` is the repo orientation layer.
- `ARCHITECTURE.md` captures the current architecture and governance posture.
- `DEVELOPMENT.md` is the local setup and validation guide.
- `ROADMAP.md` is a planning snapshot, not the live tracker.

## Non-trivial changes are issue-first

Treat the following as non-trivial and route them through a GitHub issue
before implementation:

- core, CLI, desktop, compliance, infra, docs, or shared changes
- workflow, CI, repo-governance, or contribution-surface changes
- schema, provenance, or import-policy changes
- refactors, tests, tooling work, or repo-admin changes that affect delivery

Only a narrow docs-only exception may skip issue creation.

### Required workflow

1. Search GitHub issues and milestones first.
2. Reuse an existing issue if it already covers the work.
3. If no matching issue exists, create one before implementation starts.
4. Every non-trivial issue must have a milestone:
   - Use an existing thematic milestone when it clearly fits.
   - Use `Backlog` when no thematic milestone fits.
   - Create a new thematic milestone only for a genuine new workstream or
     roadmap bucket.
5. Create a work branch from `main` using the canonical naming scheme.
6. Implement the change and run the relevant validation.
7. Open a pull request with the required template fields completed.
8. Merge with squash as the normal path. Rebase is a maintainer-only
   exception.

Agents should create missing issues and milestones automatically when the work
requires them. Do not start non-trivial implementation directly on `main`.

## Quick agent prompts

These are shorthand prompts you can use with coding agents. They are not shell
commands. Plain English still works, but these phrases are the preferred
shortcuts for common repo actions.

### Start a task

- `start <task>`:
  Reuse or create the GitHub issue, ensure it has a milestone, create a
  correctly named branch, and begin implementation.

### Save local work

- `record it`:
  Commit the current changes on the current branch. If no commit message is
  provided, the agent should choose a Conventional Commit message that matches
  the branch and diff.

### Publish branch changes

- `publish it`:
  Push the current branch to `origin`.

### Open or update a pull request

- `propose it`:
  Open a PR for the current branch or update the existing PR body/title if one
  already exists.

### Merge the pull request

- `land it`:
  Merge the current PR with squash after required checks and approval pass.
  Rebase stays a maintainer-only exception and should not be the default path.

### Common bundled flows

- `ship it`:
  `record it` + `publish it` + `propose it`
- `finish it`:
  `record it` + `publish it` + `propose it` + `land it`
- `finish it for #<id>`:
  Canonical full-flow shorthand. Commit the current changes, push the branch,
  open or update the PR linked to the given issue, and squash-merge it after
  required checks and approval pass.

Unless you explicitly override the behavior, these shortcuts should still obey
all repo rules in this document, including issue-first flow, milestone
requirements, branch naming, PR title format, and squash-first merge policy.

## Branch naming

Canonical branch format:

```text
<actor>/<type>/<scope>/<task>-<id>
```

Rules:

- all segments must be lowercase and kebab-case
- `<id>` is mandatory
- keep names concise
- use `shared` only when no single domain clearly dominates the work

Allowed values:

| Segment | Allowed values |
|---|---|
| `actor` | `codex`, `claude`, `copilot`, `gemini`, `local`, `human` |
| `type` | `feat`, `fix`, `refactor`, `chore`, `docs`, `test`, `perf` |
| `scope` | `core`, `cli`, `desktop`, `compliance`, `infra`, `docs`, `shared` |

Examples:

- `codex/fix/core/cache-ttl-27`
- `human/chore/infra/contribution-os-1`

## Commits and pull requests

Intermediate commit messages are not a blocking policy surface.

The enforced Conventional Commit format applies to:

- the pull request title
- the final squash commit message

Required format:

```text
<type>(<scope>): <description>
```

Allowed `type` and `scope` values match the branch naming tables above.

### PR requirements

Every normal PR must include:

- a linked issue
- a short summary of what changed and why
- the affected scope
- the validation that was run

Conditionally required:

- screenshots or preview evidence for visible desktop/UI changes
- compliance or provenance notes when import-policy, notices, or provenance
  files change
- docs impact when behavior or contributor flow changed
- rollback notes for risky or production-impacting changes

### Trivial docs-only exception

Issue-less PRs are allowed only when every changed file is limited to:

- `docs/**`
- `*.md`
- `*.txt`

This exception is invalid if the PR touches any of the following:

- workflows
- configs
- schemas
- scripts
- code-bearing paths

Use the PR template checkboxes to declare this exception explicitly.

## Merge and release policy

- `main` is the integration branch.
- Squash merge is the normal and documented merge path.
- Rebase merge remains available only as a maintainer exception.
- Merge commits should stay disabled.
- Plain pushes to `main` are not the normal delivery path.

## Required checks

The branch protection baseline is:

- `Contribution guardrails`
- `fmt`
- `clippy`
- `test`
- `compliance checks`
- `desktop smoke`

## Maintainer override boundaries

Maintainer overrides are reserved for:

- emergency fixes
- repo or admin changes
- operational tasks
- exceptional cases outside the normal workflow

They are not the default path for features, fixes, or refactors that fit the
standard issue -> milestone -> branch -> PR flow.

## Repo-specific engineering constraints

- v1 is strictly read-only for user data.
- Do not delete, move, rename, or modify scanned user files.
- Imported or materially derived code must be recorded in
  `provenance/imported_code.json` and reflected in `THIRD_PARTY_NOTICES.md`.
- Report schema work should stay additive by default; bump `report_version`
  when a breaking schema change is unavoidable.
- Permission and IO failures should be handled as warnings while scans continue
  best-effort.
- GitHub is the live source of truth; markdown snapshots are guidance only.

## Useful commands

```bash
# Core checks
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
python scripts/check_compliance.py

# Desktop smoke
cd apps/desktop && npm install
cd apps/desktop && npm run test:e2e

# Live GitHub state
gh issue list --repo pcoletsos/storage-strategist --state open
gh api repos/pcoletsos/storage-strategist/milestones --paginate
```
