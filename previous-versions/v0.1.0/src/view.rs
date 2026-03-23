//! View and render types.
//!
//! A ViewJob is a request to the engine: "show me these entities,
//! these metrics, in this time range, at this detail level."
//! Nothing renders unless a ViewJob asks for it.
//!
//! The three-pane model:
//!   Pane A — Topology (who connects to whom)
//!   Pane B — Sparse Geo (rough spatial context)
//!   Pane C — Timeline/Metrics (sampled values over time)
//! Plus on-demand data cards for click-popup.

use serde::{Deserialize, Serialize};

use crate::cache::DetailTier;
use crate::spatial::GeoBBox;
use crate::types::{EntityId, MetricId, Timestamp, ViewJobId};

// ════════════════════════════════════════════════════════════════════
//  VIEW KIND
// ════════════════════════════════════════════════════════════════════

/// Which pane / mode is requesting this render.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ViewKind {
    /// Pane A: abstract graph topology — no geography.
    Topology,
    /// Pane B: sparse geographic projection on the skeletal globe.
    SparseGeo,
    /// Pane C: time-series / metric chart view.
    Timeline,
    /// On-demand popup card for a clicked entity.
    DataCard,
    /// Comparison mode: two or more entities side by side.
    Compare,
    /// Export a snapshot to GeoJSON or other format.
    SnapshotExport,
}

// ════════════════════════════════════════════════════════════════════
//  TIME RANGE
// ════════════════════════════════════════════════════════════════════

/// A window in time for querying samples.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum TimeRange {
    /// Only the latest value per metric (instant popup).
    LatestOnly,
    /// From a start time to now (live tail).
    Since(Timestamp),
    /// A bounded historical window.
    Window {
        start: Timestamp,
        end: Timestamp,
    },
}

// ════════════════════════════════════════════════════════════════════
//  VIEW JOB
// ════════════════════════════════════════════════════════════════════

/// A render / query request. The engine fulfils these on demand.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ViewJob {
    pub id: ViewJobId,
    pub kind: ViewKind,
    /// Which entities to include. Empty = "whatever is active/visible."
    pub entities: Vec<EntityId>,
    /// Which metrics to fetch. Empty = "all metrics with `show_in_popup`."
    pub metrics: Vec<MetricId>,
    /// Time scope for sample retrieval.
    pub time_range: TimeRange,
    /// Override the default detail tier for these entities.
    pub detail_override: Option<DetailTier>,
    /// For `SparseGeo` views: the current viewport bounding box.
    pub viewport: Option<GeoBBox>,
}

// ════════════════════════════════════════════════════════════════════
//  RENDER RULES
// ════════════════════════════════════════════════════════════════════

/// The rule engine that decides what detail level an entity gets.
/// Evaluated per-entity per-frame by the render pipeline (Stage 2+).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RenderRule {
    /// Not visible and not selected → no render geometry at all.
    SkipInvisible,
    /// Visible but low priority → endpoints only, minimal line.
    MinimalLowPriority,
    /// Selected or zoomed → show labels + metrics + denser samples.
    DetailSelected,
    /// Alert condition active → temporarily raise detail + retention.
    PromoteAlerting,
    /// Stale → fade out, then evict from render pipeline.
    FadeStale,
    /// Currently being compared → pin short history buffer.
    PinForCompare,
}

// ════════════════════════════════════════════════════════════════════
//  DATA CARD
// ════════════════════════════════════════════════════════════════════

/// The result of hydrating a popup / data card for one entity.
/// Built on-demand by joining the feature shell + hot cache + recent history.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataCard {
    pub entity_id: EntityId,
    /// Human-readable entity label.
    pub label: String,
    /// Entity kind as a string (for display).
    pub kind_label: String,
    /// Key-value pairs of latest metric values for display.
    /// Ordered by metric definition's popup priority.
    pub summary_fields: Vec<DataCardField>,
    /// Whether deeper history is available for lazy-load.
    pub history_available: bool,
}

/// A single field in a data card popup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataCardField {
    pub metric_name: String,
    pub display_value: String,
    pub unit: String,
    pub timestamp: Timestamp,
}
