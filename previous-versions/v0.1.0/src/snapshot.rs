//! Snapshot types — selective investigation artifacts.
//!
//! A snapshot is NOT "dump the whole world." It is a compact record of
//! chosen entities + chosen metrics + chosen time window + view context.
//! Snapshots are the only path to GeoJSON export.

use serde::{Deserialize, Serialize};

use crate::types::{EntityId, MetricId, SnapshotId, Timestamp};
use crate::view::TimeRange;

// ════════════════════════════════════════════════════════════════════
//  EXPORT FORMAT
// ════════════════════════════════════════════════════════════════════

/// What format to export a snapshot in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ExportFormat {
    /// GeoJSON FeatureCollection — the primary portable output.
    GeoJson,
    /// Compact JSON (skeletrace-native schema).
    NativeJson,
    /// CSV for metric tables.
    Csv,
}

// ════════════════════════════════════════════════════════════════════
//  SNAPSHOT REQUEST
// ════════════════════════════════════════════════════════════════════

/// A request to create a snapshot — specifies what to capture.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotRequest {
    /// Which entities to include. Empty = all currently active.
    pub entities: Vec<EntityId>,
    /// Which metrics to include. Empty = all with `show_in_popup`.
    pub metrics: Vec<MetricId>,
    /// Time scope for included samples.
    pub time_range: TimeRange,
    /// Desired output format.
    pub format: ExportFormat,
    /// Optional analyst notes / investigation label.
    pub notes: Option<String>,
}

// ════════════════════════════════════════════════════════════════════
//  SNAPSHOT MANIFEST
// ════════════════════════════════════════════════════════════════════

/// Metadata about a persisted snapshot — stored in the cold tier index.
/// The actual snapshot payload lives on disk; this is the catalogue entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotManifest {
    pub id: SnapshotId,
    pub created_at: Timestamp,
    /// Number of entities captured.
    pub entity_count: usize,
    /// Number of distinct metrics captured.
    pub metric_count: usize,
    /// Number of sample records included.
    pub sample_count: usize,
    /// Time range of included samples.
    pub time_range: TimeRange,
    /// Format the snapshot was exported in.
    pub format: ExportFormat,
    /// Approximate size in bytes on disk.
    pub size_bytes: u64,
    /// Analyst notes.
    pub notes: Option<String>,
    /// File path or object key where the payload is stored.
    pub storage_path: String,
}
