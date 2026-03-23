# Suggested `skeletrace` integration shape

## Recommended boundary

Treat this subsystem as an **optional packet-analysis view/service**, not as core truth.

- Keep `skeletrace`'s source-agnostic model as the primary architecture.
- Normalize packet observations into a small `PacketEvent`-like struct at the adapter boundary.
- Feed those events into the detector library only when the operator enables the feature.
- Materialize the ASCII landscape as a secondary operator view, not as a storage primitive.

## Why this shape fits

- preserves local-first / low-RAM design
- keeps packet capture and terminal UI out of the core engine
- allows offline verification from replayed workloads or stored summaries
- makes live capture an explicit optional dependency rather than a universal one

## Two viable integration options

### Option A — Embedded library (recommended)

Link the library with `default-features = false` and feed normalized packet events from a `skeletrace` adapter.

Pros:
- no process boundary
- easier API/operator integration
- direct reuse of replay/workload data
- optional ASCII landscape view can be mounted as another operator view

Cons:
- requires a small translation layer from `skeletrace` event/sample types into `PacketEvent`
- packet-specific semantics remain a side subsystem that needs explicit lifecycle management

### Option B — External sidecar process

Run the detector as a separate CLI/TUI binary and communicate over JSONL/stdin or a local socket.

Pros:
- very low coupling
- easiest to swap out
- keeps pcap and TUI completely outside `skeletrace`

Cons:
- weaker operator/API integration
- extra process management
- duplicated buffering / transport concerns

## Minimal first wiring

1. Add an optional `packet-analysis` feature to `skeletrace`.
2. Introduce a tiny adapter mapping packet observations into `PacketEvent`.
3. Use `verify_events(...)` for offline verification/replay paths.
4. Use `AppState::ingest(...)` + `finalize_tick()` for live operator views.
5. Mount `render::frame_string(...)` as an optional ASCII landscape pane/view.

## Things to avoid

- do not move packet data into core truth/storage unnecessarily
- do not force libpcap/Npcap into default builds
- do not tie the detector state to GUI lifecycle
- do not let this subsystem dictate global polling semantics
