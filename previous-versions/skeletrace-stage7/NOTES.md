# Skeletrace Stage 7 Notes

This stage focuses on production hardening, runtime health visibility, retention tuning,
and low-overhead perf probing without widening the engine into a heavier framework.

## Added
- `src/observability.rs`
  - bounded in-memory event ring
  - structured engine events
  - event counts by severity
- `src/profiling.rs`
  - cache-health report
  - engine-health report
  - small perf probe helpers for materialization/prune cycles
- retention tuning
  - `RetentionTuning`
  - `MetricRetentionReport`
  - store/engine/operator entrypoints for live retention adjustments
- export hardening
  - post-write file size verification
- operator/API expansion
  - health report
  - recent events
  - live retention tuning
  - view materialization perf probe
  - CLI `health` command
- tests
  - `tests/stage7_hardening_perf.rs`

## Intent
Keep the hot path lean while making the engine easier to trust under real load:
- observability is bounded and local
- perf probes are explicit and low overhead
- retention tuning is live-adjustable without redefining schemas
