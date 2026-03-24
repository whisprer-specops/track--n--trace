//! Selective investigation artifacts for export.

use serde::{Deserialize, Serialize};
use crate::types::{EntityId, FlowId, MetricId, SnapshotId, Timestamp};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub id: SnapshotId,
    pub label: String,
    pub created_at: Timestamp,
    pub entity_ids: Vec<EntityId>,
    pub flow_ids: Vec<FlowId>,
    pub metric_ids: Vec<MetricId>,
    pub time_range: Option<(Timestamp, Timestamp)>,
    pub notes: String,
}
