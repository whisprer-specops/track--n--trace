# Stage 7: Production Hardening + Perf Profiling + Retention Tuning

## New runtime surfaces
- `SkeletraceEngine::health_report(...)`
- `SkeletraceEngine::recent_events(...)`
- `SkeletraceEngine::configure_event_buffer(...)`
- `SkeletraceEngine::retune_metric_retention(...)`
- `SkeletraceEngine::profile_view_materialization(...)`
- `SkeletraceEngine::profile_prune_cycle(...)`

## Operator/API additions
- `OperatorRequest::HealthReport`
- `OperatorRequest::RecentEvents`
- `OperatorRequest::TuneMetricRetention`
- `OperatorRequest::ProfileView`
- `CliCommand::Health`

## What this stage is for
- seeing source/runtime health at a glance
- inspecting recent engine events without log spam
- tuning retention behavior while preserving the metric model
- measuring view/prune costs before richer adapters/UI layers pile on

## Run
```bash
cargo fmt
cargo check
cargo test
```

## Main new test file
- `tests/stage7_hardening_perf.rs`
