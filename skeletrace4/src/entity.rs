//! Graph entity types — the core data model of skeletrace.

use serde::{Deserialize, Serialize};
use crate::spatial::GeoCoord;
use crate::types::{Confidence, EntityId, FlowId, Quality, SourceId, Timestamp};

// ── Node ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NodeKind {
    Infrastructure,
    Logical,
    Endpoint,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Node {
    pub id: EntityId,
    pub kind: NodeKind,
    pub label: String,
    pub position: Option<GeoCoord>,
    pub source_id: SourceId,
    pub first_seen: Timestamp,
    pub last_seen: Timestamp,
    pub confidence: Confidence,
    pub quality: Quality,
    pub tags: Vec<String>,
}

// ── Edge ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EdgeKind {
    Physical,
    Logical,
    Temporal,
    Causal,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Edge {
    pub id: EntityId,
    pub kind: EdgeKind,
    pub source: EntityId,
    pub target: EntityId,
    pub label: String,
    pub weight: f64,
    pub directed: bool,
    pub source_id: SourceId,
    pub first_seen: Timestamp,
    pub last_seen: Timestamp,
    pub confidence: Confidence,
    pub tags: Vec<String>,
}

// ── Flow ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FlowKind {
    Network,
    Signal,
    Data,
    Temporal,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Flow {
    pub id: FlowId,
    pub kind: FlowKind,
    pub label: String,
    /// Ordered path of entity IDs (alternating node-edge-node).
    pub path: Vec<EntityId>,
    pub source_id: SourceId,
    pub first_seen: Timestamp,
    pub last_seen: Timestamp,
    pub confidence: Confidence,
    pub tags: Vec<String>,
}
