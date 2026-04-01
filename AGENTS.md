# AGENTS.md

`storage-strategist` is an internal multi-agent repo. Read `CONTRIBUTING.md`
first for workflow policy, then use this file as the high-signal repo map.

## Read first

| File | Purpose |
|---|---|
| `CONTRIBUTING.md` | Canonical workflow contract |
| `README.md` | Repo orientation and current status |
| `ARCHITECTURE.md` | Current architecture and governance posture |
| `DEVELOPMENT.md` | Local setup and validation guide |
| `CODE_IMPORT_POLICY.md` | Provenance and reuse rules |
| `ROADMAP.md` | Planning snapshot |

## Live source of truth

GitHub is the live source of truth for:

- issues and milestones
- pull requests and CI runs
- releases

If markdown and GitHub disagree about issue state, milestone state, or required
checks, GitHub wins.

## Before you edit

For any non-trivial task:

1. search for an existing GitHub issue
2. reuse it or create a new one
3. ensure the issue has a milestone
4. use `Backlog` when no thematic milestone fits
5. create a branch before editing
6. do not work directly on `main`

Canonical branch format lives in `CONTRIBUTING.md`:

```text
<actor>/<type>/<scope>/<task>-<id>
```

## Quick prompts

The canonical shorthand prompt vocabulary lives in `CONTRIBUTING.md`.

- `start <task>`: issue + milestone + branch, then begin work
- `record it`: commit current changes
- `publish it`: push current branch
- `propose it`: open or update the PR
- `land it`: squash-merge the PR after checks and approval
- `ship it`: commit + push + PR
- `finish it`: commit + push + PR + merge
- `finish it for #<id>`: canonical full-flow shorthand tied to an issue

## Repo map

- `crates/core/`: scanning, recommendations, parity, evaluation, schema
- `crates/cli/`: user-facing command surface
- `crates/service/`: application facade for UI-style consumers
- `apps/desktop/`: Tauri + React read-only review UI scaffold
- `fixtures/`: synthetic report, eval, and benchmark fixtures
- `scripts/`: validation and benchmark helpers
- `provenance/` and `THIRD_PARTY_NOTICES.md`: imported-code tracking
- `.github/`: workflow, template, ownership, and guardrail surfaces

## Hard engineering constraints

- v1 is strictly read-only for user data.
- Do not delete, move, rename, or modify scanned user files.
- Handle permission or IO failures as warnings; continue best-effort scanning.
- Imported or materially derived code must be recorded in
  `provenance/imported_code.json` and reflected in `THIRD_PARTY_NOTICES.md`.
- Report schema work should stay additive by default; bump `report_version`
  when a breaking schema change is unavoidable.
- GitHub is the live source of truth for workflow, milestone, and merge policy.

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
