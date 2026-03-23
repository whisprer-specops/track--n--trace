# Stage 5 test run

Run these next:

```bash
cargo fmt
cargo check
cargo test
```

## New tests in this stage

- `stage5_transport_materialize.rs`
  - HTTP adapter applies custom headers and bearer auth
  - Tor-capable adapter advertises the Tor transport kind
  - topology and sparse-geo materializers emit stable, serializable shapes

## What success means

If this stage passes cleanly, the crate has gained:

- authenticated/header-aware HTTP transport profiles
- a Tor-capable HTTP acquisition path
- first operator-facing topology and sparse-geo materializers
- GeoJSON generation from sparse-geo view slices

## What should come next

- profile/config loading from local files or SQLite
- authenticated source families beyond plain HTTP/feed polling
- export pipelines for materialized view artifacts
- stronger cache byte-budget enforcement and view-driven pruning
