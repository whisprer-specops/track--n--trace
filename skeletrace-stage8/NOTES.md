# Skeletrace Stage 8

This stage adds the source-agnostic governance layer that remains useful regardless of the eventual source mix.

## Added
- `src/governance.rs`
  - source capability descriptors
  - source policy gate
  - failure taxonomy / failure records
  - sample/export audit trail
- `src/replay.rs`
  - deterministic replay/fixture harness for offline testing
- engine integration
  - per-source capability registry
  - configurable source policy
  - recent audit lookup
  - recent failure lookup
  - export audit recording
- operator integration
  - set policy
  - set capability
  - fetch recent audit records
  - fetch recent failure records
- tests
  - policy denial
  - sample/export audit recording
  - failure classification
  - replay harness release rules

## Intentionally deferred
- token / cookie / identity rotation
- proxy pool rotation
- source-evasion behaviour
- anti-bot mechanics
- anything that assumes ethically or legally sensitive acquisition paths
