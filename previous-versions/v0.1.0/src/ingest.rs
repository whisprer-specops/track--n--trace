//! Data ingest types — sources, scheduling, and normalization.
//!
//! Each data source has its own rhythm. The scheduler knows when to
//! poll, the collector pulls, the normalizer converts to standard
//! Sample records. No giant polling loop rebuilding the world every tick.

use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::types::{SourceId, Timestamp};

// ════════════════════════════════════════════════════════════════════
//  SOURCE KIND
// ════════════════════════════════════════════════════════════════════

/// What type of data source this is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SourceKind {
    /// SQL or NoSQL database query.
    Database,
    /// Continuous data stream (Kafka, WebSocket, SSE, etc.).
    Stream,
    /// REST / GraphQL / gRPC API endpoint.
    Api,
    /// File-based import (CSV, JSON, GeoJSON, etc.).
    File,
    /// Analyst-triggered manual entry.
    Manual,
    /// OSINT-specific: scraper or crawler output.
    Scraper,
}

/// Current health of a source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SourceHealth {
    /// Responding normally within expected cadence.
    Healthy,
    /// Responding but slower or with partial data.
    Degraded,
    /// Not responding; using backoff.
    Unreachable,
    /// Disabled by analyst or system policy.
    Disabled,
    /// Never been polled yet.
    Pending,
}

// ════════════════════════════════════════════════════════════════════
//  SOURCE DEFINITION
// ════════════════════════════════════════════════════════════════════

/// A registered data source that the ingest pipeline can pull from.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceDefinition {
    pub id: SourceId,
    /// Human-readable name (e.g., "shodan-api", "ripe-atlas", "manual-import").
    pub name: String,
    pub kind: SourceKind,
    /// How often this source should be polled (if applicable).
    pub cadence: Duration,
    /// Connection string, URL, file path, etc.
    pub endpoint: String,
    /// Reference to an auth credential (opaque string — resolved elsewhere).
    pub auth_ref: Option<String>,
    pub health: SourceHealth,
    /// When this source was last successfully polled.
    pub last_polled: Option<Timestamp>,
    /// When this source last returned an error.
    pub last_error: Option<Timestamp>,
    /// Current backoff duration (grows on repeated failures).
    pub backoff: Duration,
    /// Max backoff ceiling.
    pub max_backoff: Duration,
}

// ════════════════════════════════════════════════════════════════════
//  SCHEDULE ENTRY
// ════════════════════════════════════════════════════════════════════

/// A single entry in the ingest scheduler's queue.
/// The scheduler fires collectors when `next_due` arrives.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduleEntry {
    pub source_id: SourceId,
    /// When this source should next be polled.
    pub next_due: Timestamp,
    /// Priority for scheduling conflicts (higher = poll first).
    pub priority: u8,
    /// Random jitter to avoid thundering herd on many sources.
    pub jitter: Duration,
    /// How many consecutive failures since last success.
    pub consecutive_failures: u32,
}

// ════════════════════════════════════════════════════════════════════
//  RAW INGEST RECORD
// ════════════════════════════════════════════════════════════════════

/// A raw record from a source before normalization.
/// The normalizer converts these into typed `Sample` records.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawIngestRecord {
    pub source_id: SourceId,
    /// Timestamp as reported by the source (may differ from ingest time).
    pub source_timestamp: Option<Timestamp>,
    /// When skeletrace received this record.
    pub ingested_at: Timestamp,
    /// The raw payload as a JSON value — normalizer interprets per source config.
    pub payload: serde_json::Value,
}
