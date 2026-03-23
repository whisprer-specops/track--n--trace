# Stage 3 test run

Run these next:

```bash
cargo fmt
cargo check
cargo test
```

## New tests in this stage

- `engine_runtime_contracts.rs`
  - manual enqueue -> poll -> store -> card hydrate
  - NDJSON tailing without replaying old lines
- `scheduler_store_contracts.rs`
  - backoff/recovery behavior
  - store unknown-metric rejection
  - warm-retention pruning
  - automatic vs manual schedules

## What success means

If this stage passes cleanly, the crate has crossed from “validated schema” to “early runnable engine core.”

The next logical build target after this is:

- SQLite warm store
- first real network adapter(s)
- source mapping/normalization config
- topology/sparse-geo materializers
