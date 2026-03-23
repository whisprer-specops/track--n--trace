# Skeletrace Stage 9 Notes

This stage adds source-agnostic workload replay and benchmark reporting.

## New areas
- `src/workload.rs`
  - JSON fixture load/save
  - deterministic replay workload requests
  - workload reports with before/after health snapshots
- `src/engine.rs`
  - replay-ready batch ingestion
  - replay workload runner
  - replay provenance marker (`TransformStep::ReplayInject`)
- `src/operator.rs`
  - operator request/response for workload runs
- `src/replay.rs`
  - `total_pending()` and `is_empty()` helpers

## Intent
This stays in the universally useful lane:
- deterministic replay from local fixtures
- operator-visible workload reports
- benchmarkable view profiling on top of realistic replayed data

It deliberately does **not** move into:
- source/account rotation
- evasive scraping behavior
- transport choreography tied to ethically sensitive source choices
