//! Probe-specific types for the topology-aware probe engine.
//!
//! These extend skeletrace's core type vocabulary with probe concepts:
//! what to probe, what came back, aggregated health, and path analysis.

use std::collections::HashMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::types::{Confidence, EntityId, Timestamp};

// ── Probe target ───────────────────────────────────────────────────

/// HTTP method for probe requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProbeMethod {
    Get,
    Head,
    Post,
    Options,
}

impl ProbeMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Head => "HEAD",
            Self::Post => "POST",
            Self::Options => "OPTIONS",
        }
    }
}

/// What to probe: a URL endpoint associated with a graph entity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeTarget {
    /// The graph entity this probe monitors.
    pub entity_id: EntityId,
    /// Target URL to hit.
    pub url: String,
    /// HTTP method.
    pub method: ProbeMethod,
    /// Expected HTTP status codes (e.g., [200, 204]).
    pub expected_status: Vec<u16>,
    /// Request timeout.
    #[serde(with = "serde_duration_millis")]
    pub timeout: Duration,
    /// Minimum interval between probes of this target.
    #[serde(with = "serde_duration_millis")]
    pub interval: Duration,
    /// Optional request body (for POST probes).
    pub body: Option<String>,
    /// Optional headers to send.
    pub headers: HashMap<String, String>,
    /// Human-readable label.
    pub label: String,
    /// Whether this target is currently enabled.
    pub enabled: bool,
}

impl ProbeTarget {
    /// Convenience constructor for a simple GET probe.
    pub fn http_get(entity_id: EntityId, url: impl Into<String>, label: impl Into<String>) -> Self {
        Self {
            entity_id,
            url: url.into(),
            method: ProbeMethod::Get,
            expected_status: vec![200],
            timeout: Duration::from_secs(10),
            interval: Duration::from_secs(60),
            body: None,
            headers: HashMap::new(),
            label: label.into(),
            enabled: true,
        }
    }

    /// Convenience constructor for a HEAD probe (lighter weight).
    pub fn http_head(entity_id: EntityId, url: impl Into<String>, label: impl Into<String>) -> Self {
        let mut t = Self::http_get(entity_id, url, label);
        t.method = ProbeMethod::Head;
        t
    }
}

// ── Probe result ───────────────────────────────────────────────────

/// Outcome status of a single probe execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProbeStatus {
    /// Response received, status code matched expected.
    Up,
    /// Response received, but status code did not match expected.
    Degraded,
    /// No response within timeout, or connection refused/reset.
    Down,
    /// Probe was skipped (rate-limited, disabled, or circuit-broken).
    Skipped,
}

/// Result of a single probe execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeResult {
    /// Which target was probed.
    pub entity_id: EntityId,
    /// When the probe was initiated.
    pub timestamp: Timestamp,
    /// Outcome status.
    pub status: ProbeStatus,
    /// Round-trip latency. `None` if Down.
    #[serde(with = "serde_option_duration_millis")]
    pub latency: Option<Duration>,
    /// HTTP status code received. `None` if connection failed.
    pub http_status: Option<u16>,
    /// Response body size in bytes. `None` if no response.
    pub response_bytes: Option<usize>,
    /// Error message if the probe failed.
    pub error: Option<String>,
    /// URL that was probed (for logging/audit).
    pub url: String,
}

// ── Node health (aggregated) ───────────────────────────────────────

/// Aggregated health assessment for a single graph node, computed
/// from recent probe results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeHealth {
    pub entity_id: EntityId,
    /// Rolling availability: fraction of successful probes in window.
    pub availability: f64,
    /// Mean latency over the window (milliseconds).
    pub mean_latency_ms: f64,
    /// Latency standard deviation (milliseconds).
    pub latency_stddev_ms: f64,
    /// Jitter: mean absolute deviation of consecutive latencies (ms).
    pub jitter_ms: f64,
    /// Anomaly score: 0.0 = nominal, 1.0 = extreme deviation.
    pub anomaly_score: f64,
    /// Overall health confidence (factors in sample count, recency).
    pub confidence: Confidence,
    /// Number of samples in the current window.
    pub sample_count: usize,
    /// Timestamp of the most recent probe.
    pub last_probed: Option<Timestamp>,
    /// Current status based on most recent probe.
    pub current_status: ProbeStatus,
}

impl Default for NodeHealth {
    fn default() -> Self {
        Self {
            entity_id: EntityId(uuid::Uuid::nil()),
            availability: 0.0,
            mean_latency_ms: 0.0,
            latency_stddev_ms: 0.0,
            jitter_ms: 0.0,
            anomaly_score: 0.0,
            confidence: Confidence::new(0.0),
            sample_count: 0,
            last_probed: None,
            current_status: ProbeStatus::Skipped,
        }
    }
}

// ── Path diversity ─────────────────────────────────────────────────

/// Path diversity analysis for a source→destination pair.
/// Inspired by undersea cable route planning and 911 geographic redundancy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathDiversity {
    pub source: EntityId,
    pub destination: EntityId,
    /// Number of node-disjoint paths found.
    pub disjoint_path_count: usize,
    /// Shortest path length (hop count).
    pub min_hops: Option<usize>,
    /// Longest independent path length.
    pub max_hops: Option<usize>,
    /// Geographic diversity: max haversine distance between path midpoints (metres).
    pub geographic_spread_m: Option<f64>,
    /// Redundancy score: 0.0 = single path, 1.0 = highly redundant.
    pub redundancy_score: f64,
}

// ── Topology report ────────────────────────────────────────────────

/// Full topology health report: aggregates node health + path analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopologyReport {
    pub timestamp: Timestamp,
    /// Per-node health summaries.
    pub node_health: HashMap<EntityId, NodeHealth>,
    /// Articulation points (single points of failure).
    pub articulation_points: Vec<EntityId>,
    /// Path diversity between key pairs.
    pub path_diversity: Vec<PathDiversity>,
    /// Overall topology health: 0.0 = critical, 1.0 = fully healthy.
    pub overall_health: f64,
    /// Human-readable summary.
    pub summary: String,
}

// ── Serde helpers for Duration ─────────────────────────────────────

mod serde_duration_millis {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn serialize<S: Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u64(d.as_millis() as u64)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        let ms = u64::deserialize(d)?;
        Ok(Duration::from_millis(ms))
    }
}

mod serde_option_duration_millis {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn serialize<S: Serializer>(d: &Option<Duration>, s: S) -> Result<S::Ok, S::Error> {
        match d {
            Some(dur) => s.serialize_some(&(dur.as_millis() as u64)),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Duration>, D::Error> {
        let opt: Option<u64> = Option::deserialize(d)?;
        Ok(opt.map(Duration::from_millis))
    }
}
