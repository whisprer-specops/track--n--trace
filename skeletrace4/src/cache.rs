//! Tiered hot/warm/cold memory model with TTL eviction.

use serde::{Deserialize, Serialize};
use crate::types::Timestamp;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CacheTier {
    Hot,
    Warm,
    Cold,
    Evicted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEntry<T> {
    pub data: T,
    pub tier: CacheTier,
    pub inserted_at: Timestamp,
    pub last_accessed: Timestamp,
    pub access_count: u64,
    pub ttl_seconds: Option<u32>,
}
