# Skeletrace Stage 3 — Early Engine Slice

This stage moves beyond contracts and tests into a small real runtime core.

## Added

- `src/adapter.rs`
  - `SourceAdapter` trait
  - `SourcePull`
  - `ManualPushAdapter`
  - `NdjsonSampleFileAdapter`
  - `FileSampleRecord`
- `src/store.rs`
  - `EngineStore`
  - `StoreError`
  - `SampleIngestOutcome`
  - append-only NDJSON journaling for raw records and retained samples
- `src/engine.rs`
  - `EngineConfig`
  - `SkeletraceEngine`
  - `TickReport`
  - source registration
  - scheduling
  - cache promotion for view jobs
  - on-demand manual polling
  - data-card hydration from latest state + retained history

## Scope and intent

This is still intentionally small and dependency-light:

- no async runtime
- no HTTP client yet
- no SQLite yet
- no dynamic plugins yet
- no globe renderer

The purpose of this slice is to prove that the engine can:

1. register metrics/entities/sources
2. ingest normalized data through adapter classes
3. schedule and poll sources
4. retain latest state + significant history
5. update the hot cache
6. hydrate lightweight user-facing cards

## Design choices

- Manual and NDJSON adapters were chosen because they compile cleanly with the current dependency set.
- `GeoJSON` is still treated as an output/view concern, not the internal truth store.
- Journaling is append-only NDJSON to keep early runtime I/O simple and inspectable.
- The cache only keeps latest values unless a view promotes an entity into sampled mode.

## Known next steps

- replace cloned metric-map validation with direct registry lookups
- add SQLite-backed warm store
- add HTTP/Feed adapters with careful dependency review
- add source normalization/mapping config instead of requiring pre-normalized file lines
- enforce cache byte budgets, not just entity counts
- materialize topology/sparse-geo view payload builders
