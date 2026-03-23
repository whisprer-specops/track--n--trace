//! Graph entity types — the core data model of skeletrace.
//!
//! Everything in the engine is a Node, Edge, or Flow.
//! These are the "plumbing and wiring" — no carpets, curtains, or
//! pictures on the walls.

use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::spatial::GeoCoord;
use crate::types::{Confidence, EntityId, FlowId, Priority, Tag, Timestamp};

// ════════════════════════════════════════════════════════════════════
//  NODE
// ════════════════════════════════════════════════════════════════════

/// What kind of thing this node represents in the graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NodeKind {
    /// A terminal IP / service / host.
    Endpoint,
    /// An intermediate routing hop (traceroute, BGP path, etc.).
    Hop,
    /// A relay, proxy, VPN exit, or anonymising node.
    Relay,
    /// A passive observer / sensor / collector.
    Observer,
    /// A geographic or infrastructure anchor (city, IXP, data centre).
    Anchor,
    /// An exchange point (IX, peering fabric).
    Exchange,
    /// Kind not yet determined.
    Unknown,
}

/// Current lifecycle status of any entity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EntityStatus {
    /// Actively being sampled / updated.
    Active,
    /// No recent updates but still in memory.
    Stale,
    /// An alert condition has been triggered.
    Alerting,
    /// Demoted from hot cache, pending eviction.
    Dormant,
    /// Fully evicted from hot memory (exists only in warm/cold store).
    Evicted,
}

/// A point entity in the sparse graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Node {
    pub id: EntityId,
    pub kind: NodeKind,
    pub label: String,
    /// Geographic position, if known or inferred.
    /// `None` for nodes that only exist in topology space.
    pub position: Option<GeoCoord>,
    /// How confident we are in the position fix.
    pub position_confidence: Confidence,
    pub status: EntityStatus,
    pub priority: Priority,
    pub tags: Vec<Tag>,
    /// When this node was first observed.
    pub first_seen: Timestamp,
    /// Most recent observation or sample.
    pub last_seen: Timestamp,
}

// ════════════════════════════════════════════════════════════════════
//  EDGE
// ════════════════════════════════════════════════════════════════════

/// Semantic type of an edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EdgeKind {
    /// A known or observed network route.
    Route,
    /// A physical or logical link (cable, tunnel, VLAN).
    Link,
    /// An inferred connection (correlation, co-occurrence).
    Inference,
    /// A loose association (same ASN, same operator, etc.).
    Association,
}

/// Directionality of an edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EdgeDirection {
    /// A → B only.
    Directed,
    /// A — B (no inherent direction).
    Undirected,
    /// A ⇄ B (both directions, possibly asymmetric metrics).
    Bidirectional,
}

/// How this edge should be projected into geographic space.
/// Since IP routes are not real geographic curves, we let the
/// analyst choose the visual representation per-edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GeometryMode {
    /// Straight line between endpoints (cheapest).
    Straight,
    /// Great-circle arc on the ellipsoid surface.
    Geodesic,
    /// Raised arc for visual separation of overlapping routes.
    RaisedArc,
    /// Chord through the globe interior (for shortcut / submarine).
    ThroughGlobe,
    /// No geographic geometry — topology-only edge.
    Abstract,
}

/// A connection between two nodes in the sparse graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Edge {
    pub id: EntityId,
    pub kind: EdgeKind,
    pub direction: EdgeDirection,
    /// Source node of this edge.
    pub source: EntityId,
    /// Target node of this edge.
    pub target: EntityId,
    /// How to render in the geo view.
    pub geometry_mode: GeometryMode,
    /// Optional intermediate waypoints for finer-grained display.
    /// Empty means "just draw source→target".
    pub waypoints: Vec<GeoCoord>,
    pub confidence: Confidence,
    pub status: EntityStatus,
    pub priority: Priority,
    pub tags: Vec<Tag>,
    pub first_seen: Timestamp,
    pub last_seen: Timestamp,
}

// ════════════════════════════════════════════════════════════════════
//  FLOW
// ════════════════════════════════════════════════════════════════════

/// What kind of thing is flowing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FlowKind {
    /// Network traffic (packets, bytes).
    Traffic,
    /// Financial transaction stream.
    Financial,
    /// Physical goods / logistics movement.
    Logistics,
    /// Signal / broadcast / electromagnetic.
    Signal,
    /// Information / data / document movement.
    Information,
    /// Generic / unclassified flow.
    Generic,
}

/// A time-bound traversal across one or more edges.
/// Represents "something moving through the plumbing."
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Flow {
    pub id: FlowId,
    pub kind: FlowKind,
    /// Ordered list of edges this flow traverses.
    pub edge_path: Vec<EntityId>,
    /// Optional human label.
    pub label: Option<String>,
    /// Start of the observation window.
    pub window_start: Timestamp,
    /// End of the observation window (`None` = still active).
    pub window_end: Option<Timestamp>,
    /// Time-to-live for this flow's hot cache entry.
    pub ttl: Duration,
    pub status: EntityStatus,
    pub priority: Priority,
    pub tags: Vec<Tag>,
}
