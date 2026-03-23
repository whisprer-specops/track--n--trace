//! Metric definitions and sample records.
//!
//! The metric dictionary is what keeps "anything under the sun" manageable.
//! Every datum is classified: what type it is, how often it's sampled,
//! how long it lives, whether to interpolate it, and how to display it.
//!
//! Samples are the timestamped observations — append-only, never rewritten.

use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::types::{EntityId, MetricId, Quality, SourceId, Timestamp};

// ════════════════════════════════════════════════════════════════════
//  METRIC DICTIONARY
// ════════════════════════════════════════════════════════════════════

/// The data type a metric carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MetricValueType {
    /// f64 numeric (latency, throughput, packet loss, etc.).
    Numeric,
    /// Short string code / enum label (status, country code, ASN name).
    Code,
    /// Boolean flag (up/down, reachable, encrypted).
    Flag,
}

/// How to fill gaps when aligning samples to a common time grid.
/// Interpolation is ONLY performed on render/query — never stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum InterpolationMethod {
    /// No interpolation; gaps are gaps.
    None,
    /// Linear interpolation between adjacent numeric samples.
    Linear,
    /// Carry the last known value forward until next sample.
    StepForward,
    /// Use the next known value backward.
    StepBackward,
}

/// How frequently a metric is expected to be sampled.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum PollCadence {
    /// Fixed interval (e.g., every 30s, every 5m).
    Fixed(Duration),
    /// Arrives when something happens — no regular schedule.
    EventDriven,
    /// Analyst triggers collection manually.
    Manual,
    /// Adaptive: faster when volatile, slower when stable.
    Adaptive {
        min_interval: Duration,
        max_interval: Duration,
    },
}

/// How long samples survive in each storage tier.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct RetentionPolicy {
    /// Max time in hot (RAM) cache.
    pub hot_duration: Duration,
    /// Max time in warm (on-disk indexed) store.
    pub warm_duration: Duration,
    /// If true, only store a new sample when the value has actually changed
    /// (or the time gap exceeds `max_silent_gap`). Huge space saver.
    pub store_on_change_only: bool,
    /// For numeric metrics: absolute change threshold below which
    /// we treat the value as unchanged. `None` for non-numeric.
    pub change_threshold: Option<f64>,
    /// If `store_on_change_only` is true, still store at least one
    /// sample per this interval even if unchanged (heartbeat).
    pub max_silent_gap: Duration,
}

/// A single entry in the metric dictionary.
/// Defines what a tracked field means and how it behaves.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricDefinition {
    pub id: MetricId,
    /// Human-readable name (e.g., "latency_ms", "asn_name", "is_encrypted").
    pub name: String,
    /// Display unit (e.g., "ms", "Mbps", "hops", "" for dimensionless).
    pub unit: String,
    pub value_type: MetricValueType,
    pub cadence: PollCadence,
    pub interpolation: InterpolationMethod,
    pub retention: RetentionPolicy,
    /// Which sources can provide this metric.
    pub source_ids: Vec<SourceId>,
    /// Whether this metric shows by default in a popup data card.
    pub show_in_popup: bool,
    /// Short description for tooltips / documentation.
    pub description: String,
}

// ════════════════════════════════════════════════════════════════════
//  SAMPLE
// ════════════════════════════════════════════════════════════════════

/// The actual value carried by a sample.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SampleValue {
    /// Numeric observation.
    Numeric(f64),
    /// Short string / enum code.
    Code(String),
    /// Boolean flag.
    Flag(bool),
    /// Observation attempted but value was unavailable.
    Missing,
}

/// A single timestamped observation of one metric on one entity.
/// This is the fundamental unit of the append-only sample store.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sample {
    /// Which entity (node or edge) this sample belongs to.
    pub entity_id: EntityId,
    /// Which metric this is an observation of.
    pub metric_id: MetricId,
    /// When the observation was made at the source.
    pub ts_observed: Timestamp,
    /// When the sample was ingested into skeletrace.
    pub ts_ingested: Timestamp,
    /// The observed value.
    pub value: SampleValue,
    /// Confidence / quality score for this particular reading.
    pub quality: Quality,
    /// Which source provided this sample.
    pub source_id: SourceId,
}

// ════════════════════════════════════════════════════════════════════
//  LATEST VALUE SUMMARY
// ════════════════════════════════════════════════════════════════════

/// A compact summary of the most recent value for one metric on one entity.
/// Lives in the hot cache for instant popup hydration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatestValue {
    pub metric_id: MetricId,
    pub value: SampleValue,
    pub timestamp: Timestamp,
    pub quality: Quality,
    pub source_id: SourceId,
}
