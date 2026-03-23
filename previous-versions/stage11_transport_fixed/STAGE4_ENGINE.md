# Stage 4 test run

Run these next:

```bash
cargo fmt
cargo check
cargo test
```

## New tests in this stage

- `stage4_warm_http_feed.rs`
  - SQLite warm-store persistence beyond hot-memory pruning
  - live HTTP JSON adapter mapping
  - live RSS/feed adapter mapping with deterministic entities

## What success means

If this stage passes cleanly, the crate has crossed into a practical local-first engine slice:

- hot history in memory
- warm history in SQLite
- real HTTP/feed acquisition
- config-driven source normalization

## What should come next

- source auth/header/Tor transport
- SQLite-backed entity/source config loading
- first topology/sparse-geo materializers
- operator-facing snapshot/export pipeline
