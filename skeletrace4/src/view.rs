//! View/render contract: what gets fetched and when.

use serde::{Deserialize, Serialize};
use crate::spatial::GeoBBox;
use crate::types::{EntityId, MetricId, Timestamp};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ViewPriority {
    Critical,
    High,
    Normal,
    Low,
    Background,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ViewJob {
    pub entity_ids: Vec<EntityId>,
    pub metric_ids: Vec<MetricId>,
    pub time_range: Option<(Timestamp, Timestamp)>,
    pub bbox: Option<GeoBBox>,
    pub priority: ViewPriority,
}
