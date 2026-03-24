//! # Skeletrace: Sparse Spatiotemporal Flow-Graph Engine
//!
//! Skeletrace is a topology-aware probe engine for OSINT telemetry and
//! communications signal flow monitoring. It provides the foundational
//! data structures and algorithms for building resilient monitoring systems
//! that can adapt to changing network conditions and identify critical
//! infrastructure dependencies.
//!
//! ## Architecture
//!
//! - **`types`** — Identity newtypes, timestamps, bounded scalars.
//! - **`spatial`** — Minimal world scaffold: coordinates, ellipsoid math.
//! - **`entity`** — The sparse graph core: nodes, edges, flows.
//! - **`metric`** — Metric dictionary and append-only sample records.
//! - **`cache`** — Tiered hot/warm/cold memory model with TTL eviction.
//! - **`view`** — View/render contract: what gets fetched and when.
//! - **`graph`** — The sparse graph store: add/get/remove nodes, edges, flows.
//! - **`ingest`** — Scheduler/collector/normalizer pipeline definitions.
//! - **`snapshot`** — Selective investigation artifacts for export.
//! - **`probe`** — Topology-aware probe engine for communications signal flow monitoring.
//! - **`security`** — Multi-vector threat detection and security risk assessment engine.
//! - **`privacy`** — Data protection and privacy breach monitoring with compliance assessment.
//! - **`network`** — Network security and administrative monitoring for comprehensive infrastructure assessment.
//!
//! ## Example Usage
//!
//! ```rust
//! use skeletrace::{Graph, probe::{ProbeEngine, ProbeTarget}, security::{SecurityEngine, SecurityTarget}, privacy::{PrivacyEngine, PrivacyTarget}, network::{NetworkEngine, NetworkSecurityTarget}};
//! use skeletrace::entity::{Node, NodeKind};
//! use skeletrace::types::EntityId;
//!
//! // Create a graph and add some nodes
//! let mut graph = Graph::new();
//! 
//! // Set up probe engine for network monitoring
//! let mut probe_engine = ProbeEngine::new();
//! 
//! // Set up security engine for threat detection
//! let mut security_engine = SecurityEngine::new();
//! 
//! // Set up privacy engine for data protection
//! let mut privacy_engine = PrivacyEngine::new();
//! 
//! // Set up network engine for infrastructure security
//! let mut network_engine = NetworkEngine::new();
//! 
//! // Add monitoring targets
//! let entity_id = EntityId(uuid::Uuid::new_v4());
//! let probe_target = ProbeTarget::http_get(entity_id, "https://api.example.com", "API Health");
//! let security_target = SecurityTarget::email_gateway(entity_id, "Email Gateway");
//! let privacy_target = PrivacyTarget::database_encryption(entity_id, "Customer Database");
//! let network_target = NetworkSecurityTarget::wifi_security(entity_id, "Corporate Wi-Fi");
//! 
//! probe_engine.add_target(probe_target);
//! security_engine.add_target(security_target);
//! privacy_engine.add_target(privacy_target);
//! network_engine.add_target(network_target);
//! ```

pub mod types;
pub mod spatial;
pub mod entity;
pub mod metric;
pub mod cache;
pub mod view;
pub mod graph;
pub mod ingest;
pub mod snapshot;
pub mod probe;
pub mod security;
pub mod privacy;
pub mod network;

// Re-export commonly used types
pub use graph::Graph;
pub use types::{EntityId, MetricId, SourceId, Timestamp};
