# Stage 12 ViewJob compatibility fix

Patched `tests/stage13_lookyloo_topology_adapter.rs` to match the actual `ViewJob` and `TimeRange` contracts in the crate:

- removed nonexistent `ViewJob.label`
- changed `TimeRange::Latest` to `TimeRange::LatestOnly`
- removed nonexistent `ViewJob.render_rules`

No engine/view core changes were made; this is a test alignment fix.
