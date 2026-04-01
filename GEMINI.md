# Gemini Instructions

Read `CONTRIBUTING.md` first, then use `AGENTS.md` as the concise repo map.

- GitHub is the live source of truth for issues, milestones, CI, and releases.
- Non-trivial work must be issue-first and milestone-backed.
- Create a branch before editing and use the canonical branch format.
- Keep work aligned to the repo scopes: `core`, `cli`, `desktop`, `compliance`, `infra`, `docs`, `shared`.
- Validate with `cargo fmt --all`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`, and `python scripts/check_compliance.py`.
