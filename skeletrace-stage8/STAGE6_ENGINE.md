# Stage 6 testing focus

Run:

```bash
cargo fmt
cargo check
cargo test
```

This stage is trying to prove three things:

1. **Profiles are portable**
   - JSON save/load works
   - SQLite catalog round-trips a named profile cleanly

2. **Exports are real artifacts**
   - materialized outputs write to disk
   - manifests are indexed in SQLite
   - sparse-geo GeoJSON export stays valid and small

3. **The operator shell is usable**
   - operator request/response paths work
   - manual-source polling still works through the operator layer
   - CLI parsing is stable enough for the first binary shell

## Most likely teething points
If anything wobbles, the most likely places are:

- a missing import or trait bound in the new profile/operator modules
- a CSV flattening formatting mistake
- the thin CLI path rather than the engine core itself

The core engine/store/materializer path from Stages 3–5 is intentionally left alone.
