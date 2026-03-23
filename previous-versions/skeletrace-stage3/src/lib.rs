//! # Skeletrace
//!
//! Sparse spatiotemporal flow-graph engine for OSINT telemetry.
//!
//! Skeletrace keeps the runtime truth as:
//! - identity-bearing entities and relations
//! - metric definitions and append-only samples
//! - a small hot cache of active / selected / visible state
//! - selectively generated view payloads (including GeoJSON)
//!
//! It does **not** keep a full world model in memory.

pub mod adapter;
pub mod cache;
pub mod engine;
pub mod entity;
pub mod ingest;
pub mod metric;
pub mod snapshot;
pub mod spatial;
pub mod store;
pub mod types;
pub mod view;

pub use adapter::{
    AdapterError, FileSampleRecord, ManualPushAdapter, NdjsonSampleFileAdapter, SourceAdapter,
    SourcePull,
};
pub use cache::{CacheBudget, CacheEntry, DetailTier, EvictionPolicy, RingBuffer};
pub use engine::{EngineConfig, EngineError, SkeletraceEngine, TickReport};
pub use entity::{
    Boundary, BoundaryKind, Edge, EdgeDirection, EdgeKind, EntityStatus, Flow, FlowKind,
    GeometryMode, Node, NodeKind,
};
pub use ingest::{
    AdapterKind, RawIngestRecord, ScheduleEntry, SourceDefinition, SourceHealth, SourceKind,
    SourceSchedule,
};
pub use metric::{
    InterpolationMethod, LatestValue, MetricDefinition, MetricValueType, PollCadence,
    RetentionPolicy, Sample, SampleValue,
};
pub use snapshot::{ExportFormat, SnapshotManifest, SnapshotRequest};
pub use spatial::{CartesianCoord, Ellipsoid, GeoBBox, GeoCoord, WGS84};
pub use store::{EngineStore, SampleIngestOutcome, StoreError, StoreStats};
pub use types::{
    Confidence, EntityId, FlowId, MetricId, Priority, Quality, SnapshotId, SourceId, Tag,
    Timestamp, ValidationError, ViewJobId,
};
pub use view::{DataCard, DataCardField, RenderRule, TimeRange, ViewJob, ViewKind};
