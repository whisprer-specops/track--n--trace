//! Common type aliases and identity newtypes used across skeletrace.
//!
//! Every entity, metric, source, and snapshot is identified by a UUID-backed
//! newtype. This prevents accidental cross-domain ID confusion at compile time.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ── Identity newtypes ──────────────────────────────────────────────

/// Identifies a spatial entity (node or edge).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EntityId(pub Uuid);

/// Identifies a metric definition in the metric dictionary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MetricId(pub Uuid);

/// Identifies a data source (API, database, stream, file, manual).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SourceId(pub Uuid);

/// Identifies a flow (a time-bound traversal across edges).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FlowId(pub Uuid);

/// Identifies a persisted snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SnapshotId(pub Uuid);

/// Identifies a view/render job request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ViewJobId(pub Uuid);

// ── Timestamp alias ────────────────────────────────────────────────

/// All timestamps in skeletrace are UTC.
pub type Timestamp = DateTime<Utc>;

// ── Bounded scalars ────────────────────────────────────────────────

/// Confidence score clamped to [0.0, 1.0].
/// Stored as raw f64 — validation happens at construction (Stage 2).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Confidence(pub f64);

/// Quality score for a sample, clamped to [0.0, 1.0].
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Quality(pub f64);

/// Priority value. Higher = more important for retention/rendering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Priority(pub u8);

// ── Tag ────────────────────────────────────────────────────────────

/// Freeform key-value tag attached to entities.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Tag {
    pub key: String,
    pub value: String,
}
