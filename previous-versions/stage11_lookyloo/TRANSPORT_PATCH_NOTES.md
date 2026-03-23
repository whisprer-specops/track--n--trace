# Stage 11 + transport modularization (patched)

Applied Claude transport migration onto Stage 11 and fixed the doctest field reference in `src/transport/client.rs` from `meta.duration` to `meta.total_duration` to match `ResponseMeta`.

Included changes from the transport notes:
- replaced `src/transport.rs` with `src/transport/mod.rs` + submodules
- widened `TransportError` with `RateLimited`, `CircuitOpen`, `RetriesExhausted`
- added `ProxyRoute::label()`
- preserved `http_get_text()` compatibility path
- kept `lib.rs` unchanged
