# Skeletrace Stage 5 — Auth/Header/Tor Transport + First Materializers

This stage extends the validated Stage 4 engine with two tightly scoped additions:

- configurable HTTP transport profiles for auth, headers, and proxy routing
- first lightweight materializers for topology and sparse-geo outputs

## Added

- `src/transport.rs`
  - `HttpRequestProfile`
  - `HeaderPair`
  - `AuthConfig`
  - `ProxyRoute`
  - `http_get_text()`
- `src/adapter.rs`
  - `HttpJsonAdapter::with_request_profile()`
  - `FeedPollAdapter::with_request_profile()`
  - `TorHttpJsonAdapter`
- `src/materialize.rs`
  - `TopologyMaterializer`
  - `SparseGeoMaterializer`
  - serializable topology/sparse-geo view structs
  - GeoJSON feature-collection generation for sparse geo
- `src/store.rs`
  - lightweight node/edge/boundary getters for materialization
- `src/engine.rs`
  - `materialize_topology()`
  - `materialize_sparse_geo()`

## Design choices

- request/auth/proxy config remains adapter-side for now, so the core source contract stays stable
- Tor support is introduced as a transport route rather than a bespoke engine path
- materializers derive view-ready data from the store instead of turning the store itself into a map model
- sparse-geo output remains intentionally skeletal: points, lines, and coarse boundary extents

## Scope

This stage does **not** yet add:

- full auth/profile registries loaded from SQLite
- a Tor-specific feed adapter
- topology layout algorithms
- full snapshot/export persistence for materialized views
- byte-budget enforcement under adversarial adapter payloads

## Likely next steps

- profile/config loading from disk/SQLite
- richer selectors/transforms and authenticated source families
- operator-facing snapshot/export pipeline for materialized outputs
- optional topology layout heuristics and boundary overlays
