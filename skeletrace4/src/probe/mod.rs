//! Topology-aware probe engine for communications signal flow monitoring.
//!
//! This module implements a generalized node health and flow monitor that borrows
//! resilience patterns from multiple domains:
//!
//! - **Undersea fiber optic cable protection systems** → Geographic path diversity
//! - **Cellular network resilience** → Interference event detection and fallback
//! - **911 emergency call routing** → Geographic redundancy planning  
//! - **Mobile carrier core network security** → Encrypted monitoring with anomaly detection
//! - **Satellite ground station hardening** → Signal jamming threat resistance
//! - **SS7 signaling network security** → Firewall filtering and anomaly detection
//! - **Radio frequency spectrum management** → Dense urban area interference handling
//! - **Internet exchange point security** → DDoS mitigation and monitoring
//! - **Anycast DNS routing** → Root server resilience and distribution
//! - **Cloud provider data center redundancy** → Service availability maintenance
//!
//! ## Architecture
//!
//! The probe engine consists of four main components:
//!
//! - **`types`** — Core data structures for targets, results, and health metrics
//! - **`transport`** — Rate-limit aware HTTP client using ureq (sync, no TLS drama)
//! - **`analysis`** — Path diversity algorithms and node health aggregation
//! - **`engine`** — Main orchestrator tying everything together
//!
//! ## Integration with Skeletrace
//!
//! The probe engine integrates with the existing Skeletrace architecture:
//!
//! - Uses `entity::Node` and `entity::Edge` as probe targets
//! - Records results as `metric::Sample` entries  
//! - Leverages `graph::Graph` for topology analysis
//! - Respects `cache` tiering for hot/warm/cold result storage
//!
//! ## Usage
//!
//! ```rust
//! use skeletrace::probe::{ProbeEngine, ProbeTarget};
//! use skeletrace::types::EntityId;
//!
//! // Create probe engine
//! let mut engine = ProbeEngine::new();
//!
//! // Add HTTP endpoint to monitor
//! let target = ProbeTarget::http_get(
//!     EntityId(uuid::Uuid::new_v4()),
//!     "https://api.example.com/health",
//!     "API Health Check"
//! );
//! engine.add_target(target);
//!
//! // Execute probe cycle
//! let probes_executed = engine.execute_probe_cycle();
//!
//! // Generate metrics for Skeletrace
//! let samples = engine.generate_metric_samples();
//! ```
//!
//! ## Resilience Patterns Implemented
//!
//! ### Path Diversity Analysis
//! Finds node-disjoint paths between critical endpoints, inspired by undersea cable
//! route planning. Identifies single points of failure (articulation points) that
//! could isolate network segments.
//!
//! ### Anomaly Detection  
//! Monitors latency patterns and flags deviations beyond configurable thresholds.
//! Similar to satellite ground station monitoring for signal jamming detection.
//!
//! ### Rate-Limited Transport
//! Respects per-host rate limits to avoid overwhelming targets, following best
//! practices from internet exchange point monitoring systems.
//!
//! ### Geographic Redundancy Assessment
//! When nodes have geographic coordinates, computes geographic spread of
//! independent paths for disaster resilience planning.

pub mod types;
pub mod transport;
pub mod analysis;
pub mod engine;

// Re-export key types for convenience
pub use engine::{ProbeEngine, ProbeEngineConfig, ProbeEngineStats};
pub use transport::{ProbeTransport, TransportConfig};
pub use types::{
    NodeHealth, PathDiversity, ProbeResult, ProbeStatus, ProbeTarget, TopologyReport,
};
pub use analysis::{HealthAnalyzer, PathAnalyzer};
