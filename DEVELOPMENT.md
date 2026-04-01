# Development

Local setup and validation notes for `storage-strategist`.

## Prerequisites

- Rust stable
- Python 3.12+
- Node.js 20+ for the desktop app

## Core workflow

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
python scripts/check_compliance.py
```

## Desktop app

```bash
cd apps/desktop
npm install
npm run build
npm run test:e2e
```

## Useful commands

```bash
cargo run -p storage-strategist -- scan --paths "D:\\" "G:\\" --output storage-strategist-report.json --backend native --dedupe --incremental-cache --cache-ttl-seconds 900
cargo run -p storage-strategist -- recommend --report storage-strategist-report.json --md summary.md
cargo run -p storage-strategist -- doctor
cargo run -p storage-strategist -- eval --suite fixtures/eval-suite.json --output eval-result.json
cargo run -p storage-strategist -- benchmark --paths fixtures --max-depth 3 --iterations 2 --output benchmark-result.json
cargo run -p storage-strategist -- parity --paths fixtures --max-depth 3
cargo run -p storage-strategist -- plan --report storage-strategist-report.json --output scenario-plan.json
cargo run -p storage-strategist -- diagnostics --report storage-strategist-report.json --output storage-strategist-diagnostics.json
```
