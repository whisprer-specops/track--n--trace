//! Ingest definitions — adapters, scheduling, and raw record capture.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::types::{SourceId, Tag, Timestamp, ValidationError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SourceKind {
    Database,
    Stream,
    Api,
    File,
    Manual,
    Scraper,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AdapterKind {
    HttpPoller,
    FeedPoller,
    StreamAdapter,
    TorHttpPoller,
    FileImport,
    DatabaseQuery,
    Manual,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum SourceSchedule {
    Fixed(Duration),
    EventDriven,
    Manual,
}

impl SourceSchedule {
    pub fn validate(self) -> Result<(), ValidationError> {
        match self {
            Self::Fixed(interval) if interval.is_zero() => Err(ValidationError::ZeroCapacity(
                "source_schedule.fixed".into(),
            )),
            _ => Ok(()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SourceHealth {
    Healthy,
    Degraded,
    Unreachable,
    Disabled,
    Pending,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceDefinition {
    pub id: SourceId,
    pub name: String,
    pub kind: SourceKind,
    pub adapter: AdapterKind,
    pub schedule: SourceSchedule,
    pub endpoint: String,
    pub auth_ref: Option<String>,
    pub health: SourceHealth,
    pub last_polled: Option<Timestamp>,
    pub last_error: Option<Timestamp>,
    pub backoff: Duration,
    pub max_backoff: Duration,
    pub tags: Vec<Tag>,
}

impl SourceDefinition {
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.name.trim().is_empty() {
            return Err(ValidationError::EmptyField("source.name".into()));
        }
        if self.endpoint.trim().is_empty() && !matches!(self.kind, SourceKind::Manual) {
            return Err(ValidationError::EmptyField("source.endpoint".into()));
        }
        self.schedule.validate()?;
        if self.max_backoff < self.backoff {
            return Err(ValidationError::InvalidWindow {
                start_field: "backoff".into(),
                end_field: "max_backoff".into(),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduleEntry {
    pub source_id: SourceId,
    pub next_due: Timestamp,
    pub priority: u8,
    pub jitter: Duration,
    pub consecutive_failures: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawIngestRecord {
    pub source_id: SourceId,
    pub source_timestamp: Option<Timestamp>,
    pub ingested_at: Timestamp,
    pub payload: serde_json::Value,
}
