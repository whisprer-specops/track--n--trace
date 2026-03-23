Stage 12 compatibility fix

This patch fixes the backwards-compatibility break introduced when `SourcePull`
was extended with topology-bearing fields:
- `nodes`
- `edges`
- `boundaries`

The runtime engine changes were fine, but several existing tests still used
older `SourcePull { ... }` struct literals that only populated:
- `raw_records`
- `samples`
- `touched_entities`

Rust requires all public struct fields to be initialized in literals, so the
older tests failed to compile.

Fix applied:
- updated affected test files to add empty topology vectors:
  - `nodes: vec![]`
  - `edges: vec![]`
  - `boundaries: vec![]`

This preserves the Stage 12 topology-capable `SourcePull` shape while restoring
full test-suite compatibility with older sample-only test cases.
