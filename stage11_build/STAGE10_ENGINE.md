# Stage 10 testing focus

Run:

```bash
cargo fmt
cargo check
cargo test
```

Primary checks introduced in this stage:

- replay benchmarks run against **freshly instantiated profiles** each iteration
- workload benchmark reports expose deterministic per-source fixture summaries
- warm-store maintenance reports are queryable through the operator layer
- warm-store optimize/maintenance paths stay visible without requiring a debugger
- batch ingest helpers do not disturb the older hot/warm retention behavior

Likeliest teething spots, if any appear:
- new operator enum/request plumbing
- warm-store pragma/maintenance query return types
- benchmark/profile glue rather than the older engine core
