# Stage 9: Workload Replay + Benchmark Reports

## Run

```bash
cargo fmt
cargo check
cargo test
```

## What to look for
- replay batches can be loaded from JSON and injected without live network access
- replay runs produce stable workload reports
- operator layer can trigger workload runs directly
- replay provenance is distinguishable from live adapter pulls

## New tests
- replay-ready ingestion records replay provenance
- replay workload tracks checkpoints and view profiles
- JSON fixture round-trip + operator workload execution
