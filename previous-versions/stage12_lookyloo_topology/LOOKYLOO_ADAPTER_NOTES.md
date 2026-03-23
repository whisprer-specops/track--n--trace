# Lookyloo adapter notes

This patch does **not** try to rewrite the whole Lookyloo application into Rust.
That would be the wrong integration boundary.

What it adds instead is a Skeletrace source adapter that consumes Lookyloo-style
capture summary payloads and turns them into normalized Skeletrace samples.

## What the adapter expects

Each capture summary object can contain these fields:

- `uuid` (required)
- `title`
- `timestamp`
- `url`
- `redirects`
- `error`
- `no_index`
- `categories`
- `parent`
- `user_agent`
- `referer`
- `capture_dir`

The payload can be:

- a single object
- an array of objects
- an object containing the array at a JSON pointer such as `/captures`

## Why this boundary is the right one

The Python repository is a large application with web UI, background workers,
Redis cache management, capture orchestration, and a large dependency surface.
The practical Rust conversion for Skeletrace is the *source layer*, not a full
port of Lookyloo itself.

## Files added/changed

- `src/lookyloo.rs`
- `src/profile.rs`
- `src/lib.rs`
- `tests/stage12_lookyloo_adapter.rs`
- `examples/lookyloo_source_profile.json`

## Current scope

This adapter is intentionally summary-oriented. It ingests capture metadata and
exposes it as metric samples.

It does **not** yet attempt to:

- parse HAR files directly
- rebuild Lookyloo trees
- mirror Redis/cache internals
- construct full Skeletrace topology from capture domain trees

Those are possible later, but they are a larger and riskier second step.
