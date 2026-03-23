# Stage 2 testing

The crate has already passed initial compile and core contract tests.

This stage adds four broader test bands:

1. **Entity contracts**
   - node / edge / flow / boundary invariant checks
   - hot/stale lifecycle semantics

2. **Ingest, view, and snapshot contracts**
   - source schedule validation
   - source backoff windows
   - viewport requirements
   - snapshot manifest hygiene

3. **Metric and cache behavior**
   - ring-buffer capacity guarantees
   - cache byte-growth checks
   - heartbeat retention behavior
   - metric/sample type consistency

4. **Serialization contracts**
   - JSON round-trips for core portable types
   - ID stability through serde
   - view/snapshot envelope structure

## Commands

```bash
cargo fmt
cargo check
cargo test
```

## What this stage is meant to prove

- the public contracts stay stable under normal serialization
- low-RAM structures keep bounded behavior
- validation paths reject malformed state before the real engine loop arrives
- export/view payloads stay clean and portable

## What should come after this

- a lightweight in-memory store layer
- adapter trait + first built-in adapter implementations
- a scheduler loop with significance-gated persistence
- snapshot materialization tests against real sample sets
