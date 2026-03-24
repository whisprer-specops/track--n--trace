//! Metric dictionary and append-only sample records.

use serde::{Deserialize, Serialize};
use crate::types::{EntityId, MetricId, Quality, SourceId, Timestamp};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MetricValueType {
    Numeric,
    Code,
    Flag,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PollCadence {
    Seconds(u32),
    Minutes(u32),
    Hours(u32),
    OnChange,
    Manual,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum InterpolationMethod {
    None,
    Linear,
    StepForward,
    StepBackward,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionPolicy {
    pub raw_ttl_hours: u32,
    pub rollup_ttl_days: u32,
    pub rollup_interval_minutes: u32,
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        Self {
            raw_ttl_hours: 168,
            rollup_ttl_days: 365,
            rollup_interval_minutes: 60,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricDefinition {
    pub id: MetricId,
    pub name: String,
    pub unit: String,
    pub value_type: MetricValueType,
    pub cadence: PollCadence,
    pub interpolation: InterpolationMethod,
    pub retention: RetentionPolicy,
    pub source_ids: Vec<SourceId>,
    pub show_in_popup: bool,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SampleValue {
    Numeric(f64),
    Code(String),
    Flag(bool),
    Missing,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sample {
    pub metric_id: MetricId,
    pub entity_id: EntityId,
    pub timestamp: Timestamp,
    pub value: SampleValue,
    pub quality: Quality,
    pub source_id: SourceId,
}
