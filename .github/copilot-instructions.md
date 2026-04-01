# Copilot Instructions

Read `CONTRIBUTING.md` first.

- GitHub is the live source of truth for issues, milestones, CI, and releases.
- Use issue-first flow for non-trivial work.
- Create a branch before editing and follow the canonical branch format.
- Keep repo scopes aligned to `core`, `cli`, `desktop`, `compliance`, `infra`, `docs`, and `shared`.
- Run `cargo fmt --all`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`, and `python scripts/check_compliance.py` before merge.
