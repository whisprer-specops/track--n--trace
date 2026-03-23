//! # Skeletrace
//!
//! Sparse spatiotemporal flow-graph engine for OSINT telemetry.
//!
//! Skeletrace models the world as math, not data. It tracks nodes,
//! edges, and flows through a skeletal geographic frame, keeping only
//! what is actively needed in memory and evicting everything else.
//!
//! ## Architecture
//!
//! - **`types`** — Identity newtypes, timestamps, bounded scalars.
//! - **`spatial`** — Minimal world scaffold: coordinates, ellipsoid math.
//! - **`entity`** — The sparse graph core: nodes, edges, flows.
//! - **`metric`** — Metric dictionary and append-only sample records.
//! - **`cache`** — Tiered hot/warm/cold memory model with TTL eviction.
//! - **`view`** — View/render contract: what gets fetched and when.
//! - **`ingest`** — Scheduler/collector/normalizer pipeline definitions.
//! - **`snapshot`** — Selective investigation artifacts for export.

pub mod types;
pub mod spatial;
pub mod entity;
pub mod metric;
pub mod cache;
pub mod view;
pub mod ingest;
pub mod snapshot;
