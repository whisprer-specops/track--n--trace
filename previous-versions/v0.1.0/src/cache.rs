//! Cache and lifecycle types.
//!
//! The hot cache holds only active/recent/visible entities. Everything
//! else lives in warm (disk) or cold (archive) tiers, or is evicted
//! entirely. This is where "only active entities earn hot memory" is enforced.

use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::metric::{LatestValue, Sample};
use crate::types::{EntityId, MetricId, Priority, Timestamp};

// ════════════════════════════════════════════════════════════════════
//  DETAIL TIERS
// ════════════════════════════════════════════════════════════════════

/// The data tiers from the architecture doc.
/// Controls how much state is held for an entity at any given moment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum DetailTier {
    /// Tier 0: world math only — entity exists as an ID, no loaded state.
    Skeleton,
    /// Tier 1: active nodes/edges — identity, geometry, current status.
    Active,
    /// Tier 2: recent dynamic metrics — latest values + short ring buffer.
    Sampled,
    /// Tier 3: high-resolution local samples — temporarily dense data
    /// for selected/zoomed/forensic entities.
    HighRes,
}

/// How an entity gets removed from a cache tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EvictionPolicy {
    /// Evict when TTL expires since last access.
    TTL,
    /// Evict least recently used when capacity is hit.
    LRU,
    /// Evict lowest priority first.
    PriorityBased,
    /// Never auto-evict — analyst must manually release.
    Pinned,
}

// ════════════════════════════════════════════════════════════════════
//  RING BUFFER DESCRIPTOR
// ════════════════════════════════════════════════════════════════════

/// A fixed-capacity circular buffer of recent samples for one metric
/// on one entity. When full, the oldest sample is overwritten.
/// Actual storage impl is Stage 2 — this defines the shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RingBuffer {
    pub entity_id: EntityId,
    pub metric_id: MetricId,
    /// Maximum number of samples retained.
    pub capacity: usize,
    /// The samples themselves, oldest-first.
    /// Length ≤ capacity; wraps when full.
    pub samples: Vec<Sample>,
    /// Write cursor position within `samples`.
    pub cursor: usize,
}

// ════════════════════════════════════════════════════════════════════
//  CACHE ENTRY
// ════════════════════════════════════════════════════════════════════

/// A single entity's presence in the hot cache.
/// This is the runtime object that the view/render pipeline reads from.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEntry {
    pub entity_id: EntityId,
    /// Current detail tier for this entity.
    pub detail_tier: DetailTier,
    /// Latest value per metric — instant popup hydration.
    pub latest_by_metric: Vec<LatestValue>,
    /// Short ring buffers for metrics that need recent history.
    /// Only populated for entities at `Sampled` or `HighRes` tier.
    pub ring_buffers: Vec<RingBuffer>,
    /// Last time anything in this entry was accessed (read or written).
    pub last_accessed: Timestamp,
    /// Time-to-live from last access before demotion.
    pub ttl: Duration,
    /// How this entry should be evicted when resources are tight.
    pub eviction_policy: EvictionPolicy,
    pub priority: Priority,
    /// Entity is currently inside the viewport.
    pub is_visible: bool,
    /// Entity is currently selected / focused by the analyst.
    pub is_selected: bool,
    /// Entity has an active alert condition.
    pub is_alerting: bool,
}

// ════════════════════════════════════════════════════════════════════
//  CACHE BUDGET
// ════════════════════════════════════════════════════════════════════

/// Global limits for the hot cache.
/// The engine uses these to decide when to demote or evict.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct CacheBudget {
    /// Max number of entities at `Active` tier or above.
    pub max_active_entities: usize,
    /// Max total ring buffer samples across all entities.
    pub max_total_ring_samples: usize,
    /// Max total `HighRes` entities at once.
    pub max_highres_entities: usize,
}
