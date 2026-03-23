# Stage 11 — Query / Watchlist / Alert Layer

This stage adds universally useful operator-side retrieval and monitoring primitives without committing to any ethically or cost-sensitive acquisition tactics.

## Added
- `src/query.rs`
  - current-state query contracts
  - lightweight watchlist/alert contracts
- `SkeletraceEngine::query_latest(...)`
- `SkeletraceEngine::evaluate_watchlist(...)`
- `OperatorRequest::QueryLatest`
- `OperatorRequest::EvaluateWatchlist`
- `OperatorResponse::Query`
- `OperatorResponse::Watchlist`
- CLI support:
  - `query-latest <profile.json> <filter.json>`
  - `evaluate-watchlist <profile.json> <watchlist.json>`

## Why now
This exercises the engine as an operator tool without forcing decisions about live-source ethics, rate-limit strategies, identity rotation, or transport workarounds.

## Focus
- ask the engine for the current truth slice
- track a small set of important entity+metric pairs
- surface alerts from latest values only
- keep memory/CPU impact tiny
