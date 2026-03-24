This bundle contains drop-in replacements for the next `skeletrace` implementation slice:

- `src/query.rs`
- `src/engine.rs`
- `src/operator.rs`
- `src/lib.rs`
- `tests/stage11_query_watchlist.rs`
- `tests/stage14_query_advanced.rs`

What this slice adds:
- richer `QueryFilter` support:
  - `source_ids`
  - `entity_statuses`
  - `required_tags`
- new advanced operator query contract:
  - `QueryRequest`
  - `SavedQuery`
  - `QuerySortKey`
  - `QueryGroupKey`
  - `QueryResultEnvelope`
  - `QueryGroupSummary`
  - `QueryRowComparison`
- engine support for:
  - historical compare windows using retained/warm samples
  - sort/group on query results
  - saved-query execution through operator API/CLI
- new CLI/operator surface:
  - `query-advanced <profile.json> <saved-query.json>`
- regression coverage for the advanced query path in `tests/stage14_query_advanced.rs`

Important integration note:
`src/lib.rs` in your live repo likely already includes the packet-verification exports added after the uploaded tarball snapshot. Keep those packet exports intact and merge the new query exports from this file into your current `src/lib.rs` rather than blindly reverting unrelated packet work.
