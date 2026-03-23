# Skeletrace Stage 4 — SQLite Warm Store + Real HTTP/Feed Adapters

This stage extends the validated Stage 3 engine into a more realistic local-first runtime.

## Added

- `src/warm_store.rs`
  - `SqliteWarmStore`
  - append/query/prune support for warm history in SQLite
- `src/mapping.rs`
  - `SourceMappingConfig`
  - `EntityMapping`
  - `MetricBinding`
  - `ValueSelector`
  - `FeedField`
- `src/adapter.rs`
  - `HttpJsonAdapter`
  - `FeedPollAdapter`
  - mapping-driven normalization from live HTTP/feed payloads into samples
- `src/store.rs`
  - optional SQLite-backed warm layer alongside the in-memory hot buffers
  - merged hot + warm history lookup
- `src/engine.rs`
  - `EngineConfig.warm_store_path`
  - engine startup against both journal and warm-store backends

## Scope and intent

This stage still keeps the architecture intentionally disciplined:

- hot state stays in memory
- warm state moves to SQLite
- source-specific logic lives in adapters + mapping config
- `GeoJSON` remains a view/output concern rather than the internal truth store

## Design choices

- Mapping config currently lives on the adapter side, not inside `SourceDefinition`, to avoid destabilizing the Stage 3 source contract.
- The HTTP adapter currently targets JSON object/array responses.
- The feed adapter targets RSS-style feeds and creates deterministic item entities via GUID/link/title mapping.
- SQLite is the warm layer only; it is not used for the active hot cache.

## Known next steps

- source-auth/header config and Tor-capable HTTP transport
- materialized topology/sparse-geo outputs
- cache byte-budget enforcement under real pressure
- richer selector transforms and source-mapping files
- disk-backed snapshot/export pipelines beyond NDJSON/SQLite warm storage
