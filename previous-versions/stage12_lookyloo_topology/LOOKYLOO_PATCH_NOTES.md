# Skeletrace Lookyloo adapter patch

This patch adds a Rust-native Skeletrace source adapter for Lookyloo-style
capture summary payloads.

## Added

- `src/lookyloo.rs`
  - `LookylooCaptureSummary`
  - `LookylooMetricBindings`
  - `LookylooSourceConfig`
  - `LookylooSummaryAdapter`
- `tests/stage12_lookyloo_adapter.rs`
- `examples/lookyloo_source_profile.json`
- `LOOKYLOO_ADAPTER_NOTES.md`

## Changed

- `src/lib.rs`
  - exports the new Lookyloo types
- `src/profile.rs`
  - adds `AdapterProfile::LookylooSummary`
  - wires it into validation and adapter construction

## Scope

This is intentionally a **source/plugin conversion**, not a full port of the
whole Lookyloo application. It focuses on the part that is actually relevant to
Skeletrace: ingesting capture summaries into normalized samples.

## Payload compatibility

The adapter accepts:

- a single summary object
- an array of summary objects
- a wrapper object with a configured JSON pointer such as `/captures`

It also tolerates Python-side serialized list fields such as:

- `redirects: "[\"https://...\"]"`
- `categories: "[\"phish\", \"kit\"]"`

and bool-ish `no_index` fields like `1`, `0`, `true`, `false`, `"yes"`, `"no"`.
