# Stage 8 testing focus

Run:

```bash
cargo fmt
cargo check
cargo test
```

This stage should prove that:
- restrictive policies can deny source registration before acquisition begins
- sample ingestion creates an operator-visible provenance trail
- snapshot exports can be added to the same audit stream
- adapter failures are classified into stable operator-facing reason codes
- replay/fixture batches can drive deterministic tests without live sources

Likeliest teething spots, if any appear:
- newly added operator request/response variants
- audit/provenance type imports / derives
- failure-classification glue around engine/adapters
