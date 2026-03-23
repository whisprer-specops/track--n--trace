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
pub mod mapping;
pub mod metric;
pub mod snapshot;
pub mod spatial;
pub mod store;
pub mod transport;
pub mod materialize;
pub mod observability;
pub mod profiling;
pub mod types;
pub mod view;
pub mod warm_store;
pub mod profile;
pub mod export;
pub mod operator;
pub mod governance;
pub mod replay;
pub mod workload;
pub mod query;
pub mod lookyloo;
pub mod packet;
pub mod packet_workflow;

pub use adapter::{
    AdapterError, FeedPollAdapter, FileSampleRecord, HttpJsonAdapter, ManualPushAdapter,
    NdjsonSampleFileAdapter, SourceAdapter, SourcePull, TorHttpJsonAdapter,
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
pub use mapping::{
    EntityMapping, FeedField, MetricBinding, SourceMappingConfig, ValueSelector,
};
pub use metric::{
    InterpolationMethod, LatestValue, MetricDefinition, MetricValueType, PollCadence,
    RetentionPolicy, Sample, SampleValue,
};
pub use snapshot::{ExportFormat, SnapshotManifest, SnapshotRequest};
pub use spatial::{CartesianCoord, Ellipsoid, GeoBBox, GeoCoord, WGS84};
pub use store::{BatchIngestReport, EngineStore, SampleIngestOutcome, StoreError, StoreStats};
pub use transport::{AuthConfig, HeaderPair, HttpRequestProfile, ProxyRoute, TransportError};
pub use materialize::{MaterializedMetricValue, SparseGeoFeature, SparseGeoFeatureCollection, SparseGeoGeometry, SparseGeoMaterializer, SparseGeoViewMaterialization, TopologyBoundaryView, TopologyEdgeView, TopologyMaterializer, TopologyNodeView, TopologyViewMaterialization};
pub use types::{
    Confidence, EntityId, FlowId, MetricId, Priority, Quality, SnapshotId, SourceId, Tag,
    Timestamp, ValidationError, ViewJobId,
};
pub use view::{DataCard, DataCardField, RenderRule, TimeRange, ViewJob, ViewKind};
pub use warm_store::{SqliteWarmStore, WarmStoreError, WarmStoreMaintenanceReport};


pub use export::{ExportError, SnapshotExportJob, SnapshotExportResult, SnapshotExporter, SqliteSnapshotCatalog};
pub use operator::{
    CliCommand, OperatorApi, OperatorError, OperatorRequest, OperatorResponse, run_cli_command,
};
pub use profile::{AdapterProfile, EngineProfile, ProfileError, SourceProfile, SqliteProfileStore};


pub use metric::{MetricRetentionReport, RetentionTuning};
pub use observability::{EngineEvent, EventBuffer, EventBufferConfig, EventCounts, EventKind, EventLevel};
pub use profiling::{CacheHealthReport, DurationStats, EngineHealthReport, PerfProbeConfig, PerfProbeReport, SourceHealthCount};


pub use governance::{
    AuditRecord, AuditTrail, AutomationSupport, ExportAuditRecord, FailureClass, FailureRecord,
    PolicyVerdict, SampleAuditRecord, SampleProvenance, SourceAccessMode,
    SourceCapabilityProfile, SourceCostModel, SourcePolicy, TransformStep, TransportSupport,
};
pub use replay::{ReplayBatch, ReplayHarness};


pub use workload::{ReplayBenchmarkReport, ReplayBenchmarkRequest, ReplayIngestReport, ReplayWorkloadRequest, SourceWorkloadSummary, ViewProfileTarget, WorkloadCheckpointReport, WorkloadFixture, WorkloadRunReport};


pub use query::{AlertEvent, AlertRule, EntityClass, EntitySelector, NumericPredicate, QueryFilter, QueryResult, QueryRow, WatchItem, Watchlist, WatchlistEvaluation};

pub use lookyloo::{LookylooCaptureSummary, LookylooMetricBindings, LookylooSourceConfig, LookylooSummaryAdapter, LookylooTopologyAdapter, LookylooTopologyConfig};

pub use packet::{
    analyze_packets, render_packet_landscape_frame, verify_packet_events, PacketEvent,
    PacketLandscapeOptions, PacketLane, PacketLaneSummary, PacketLandscapeState,
    PacketVerificationReport, PacketVerificationRequest, PacketVerificationResponse,
    PacketVerificationSummary,
};

pub use packet_workflow::{
    verify_packet_request, PacketRenderSurface, PacketVerificationOptions, PacketWorkflowError,
};