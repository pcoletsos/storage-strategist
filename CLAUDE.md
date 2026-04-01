# Claude Instructions

Read `CONTRIBUTING.md` first, then follow `AGENTS.md` for the repo map.

- GitHub is the live source of truth for issues, milestones, CI, and releases.
- Use issue-first flow for non-trivial work.
- Create a branch before editing and stay off `main`.
- Repo scopes are `core`, `cli`, `desktop`, `compliance`, `infra`, `docs`, and `shared`.
- Normal validation is `cargo fmt --all`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`, and `python scripts/check_compliance.py`.
- Run desktop smoke verification when changes touch `apps/desktop`.
