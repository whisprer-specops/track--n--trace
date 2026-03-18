# Skeletrace polish pass

This crate is the cleaned-up continuation of the uploaded Stage-1 core contracts.

## What was tightened

- Converted the loose file drop into a proper Cargo crate layout (`src/` + `tests/`).
- Enabled UUID v4 generation so IDs can be created directly.
- Added cross-module `ValidationError` and validation helpers.
- Added WGS-84 helpers for geo <-> ECEF conversion and bbox utilities.
- Extended the entity model with `Boundary` and more OSINT-suitable node/edge variants.
- Added metric popup priority plus absolute/relative significance thresholds.
- Added `RetentionPolicy::should_store()` so frequent polling does not imply frequent persistence.
- Added ring-buffer push/wrap logic.
- Added hot-cache byte budgets in addition to entity/sample-count budgets.
- Added adapter-class and source-schedule enums for a performance-first ingest architecture.
- Added a small core test suite.

## One honest limitation

The current environment did not include `cargo` or `rustc`, so I could not execute a real compile/test pass here.
The crate is structured and reviewed to be build-ready, but it still deserves a first local:

```bash
cargo fmt
cargo check
cargo test
```

run on your machine before further work.
