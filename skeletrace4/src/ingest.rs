//! Scheduler/collector/normalizer pipeline definitions.

use serde::{Deserialize, Serialize};
use crate::types::{MetricId, SourceId};
use crate::metric::PollCadence;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CollectorState {
    Idle,
    Running,
    Backoff,
    Failed,
    Disabled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectorSpec {
    pub source_id: SourceId,
    pub metric_ids: Vec<MetricId>,
    pub cadence: PollCadence,
    pub state: CollectorState,
    pub consecutive_failures: u32,
    pub max_retries: u32,
}
