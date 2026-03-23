# Skeletrace Stage 6

This stage adds the first operator-facing runtime shell around the clean Stage 5 engine:

- disk/JSON runtime profile loading and saving
- SQLite profile catalog for named local profiles
- snapshot/export pipeline for topology, sparse-geo, and data-card materializations
- SQLite snapshot manifest catalog
- first operator API request/response surface
- first thin CLI binary (`src/bin/skeletrace.rs`)

The hot path remains unchanged:

- hot cache stays in memory
- warm history stays in SQLite
- materialization still happens on demand
- GeoJSON is still an output/view format, not the internal truth model

## Main additions

### `src/profile.rs`
- `EngineProfile`
- `SourceProfile`
- `AdapterProfile`
- `SqliteProfileStore`

Profiles are JSON-first and instantiate the engine without introducing a plugin ABI.

### `src/export.rs`
- `SnapshotExportJob`
- `SnapshotExporter`
- `SnapshotExportResult`
- `SqliteSnapshotCatalog`

Exports support:
- `NativeJson` for all supported materializations
- `GeoJson` for sparse-geo materializations
- `Csv` flattening for topology, sparse-geo, and data-card exports

### `src/operator.rs`
- `OperatorApi`
- `OperatorRequest`
- `OperatorResponse`
- `CliCommand`
- `run_cli_command(...)`

This is deliberately thin. It is an operator shell, not yet a full daemon/API server.

## Intended next move after this stage
If Stage 6 lands cleanly, the strongest next step is:

- persistent auth/profile references in SQLite
- richer source mapping transforms
- first HTTP service / local socket API for external control
- first real UI-facing command contract rather than ad hoc JSON files
