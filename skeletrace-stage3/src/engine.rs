//! Early engine slice: source scheduling, adapter dispatch, local storage, and hot cache.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::adapter::{AdapterError, ManualPushAdapter, SourceAdapter, SourcePull};
use crate::cache::{CacheBudget, CacheEntry, DetailTier, RingBuffer};
use crate::entity::{Boundary, Edge, Node};
use crate::ingest::{ScheduleEntry, SourceDefinition, SourceHealth};
use crate::metric::{LatestValue, MetricDefinition, Sample};
use crate::store::{EngineStore, StoreError, StoreStats};
use crate::types::{EntityId, MetricId, SourceId, Timestamp, ValidationError};
use crate::view::{DataCard, DataCardField, TimeRange, ViewJob};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EngineError {
    Validation(String),
    UnknownSource(SourceId),
    MissingAdapter(SourceId),
    WrongAdapterKind(SourceId),
    Adapter(String),
    Store(String),
}

impl std::fmt::Display for EngineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Validation(msg) => write!(f, "engine validation error: {msg}"),
            Self::UnknownSource(id) => write!(f, "unknown source: {id}"),
            Self::MissingAdapter(id) => write!(f, "missing adapter for source: {id}"),
            Self::WrongAdapterKind(id) => write!(f, "wrong adapter kind for source: {id}"),
            Self::Adapter(msg) => write!(f, "adapter error: {msg}"),
            Self::Store(msg) => write!(f, "store error: {msg}"),
        }
    }
}

impl std::error::Error for EngineError {}

impl From<ValidationError> for EngineError {
    fn from(value: ValidationError) -> Self {
        Self::Validation(value.to_string())
    }
}

impl From<AdapterError> for EngineError {
    fn from(value: AdapterError) -> Self {
        Self::Adapter(value.to_string())
    }
}

impl From<StoreError> for EngineError {
    fn from(value: StoreError) -> Self {
        Self::Store(value.to_string())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineConfig {
    pub cache_budget: CacheBudget,
    pub default_ring_capacity: usize,
    pub default_entity_ttl: Duration,
    pub journal_dir: Option<PathBuf>,
}

impl EngineConfig {
    pub fn validate(&self) -> Result<(), ValidationError> {
        self.cache_budget.validate()?;
        if self.default_ring_capacity == 0 {
            return Err(ValidationError::ZeroCapacity(
                "engine.default_ring_capacity".into(),
            ));
        }
        if self.default_entity_ttl.is_zero() {
            return Err(ValidationError::ZeroCapacity(
                "engine.default_entity_ttl".into(),
            ));
        }
        Ok(())
    }
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            cache_budget: CacheBudget {
                max_active_entities: 1_024,
                max_total_ring_samples: 8_192,
                max_highres_entities: 64,
                max_approx_hot_bytes: 16 * 1024 * 1024,
                max_per_entity_hot_bytes: 256 * 1024,
            },
            default_ring_capacity: 32,
            default_entity_ttl: Duration::from_secs(600),
            journal_dir: None,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct TickReport {
    pub due_sources: usize,
    pub polled_sources: usize,
    pub failed_sources: usize,
    pub raw_records_seen: usize,
    pub samples_seen: usize,
    pub samples_stored: usize,
}

pub struct SkeletraceEngine {
    config: EngineConfig,
    store: EngineStore,
    cache_entries: HashMap<EntityId, CacheEntry>,
    schedule: HashMap<SourceId, ScheduleEntry>,
    adapters: HashMap<SourceId, Box<dyn SourceAdapter>>,
}

impl SkeletraceEngine {
    pub fn new(config: EngineConfig) -> Result<Self, EngineError> {
        config.validate()?;
        let store = if let Some(path) = &config.journal_dir {
            EngineStore::with_journal_dir(path.clone())?
        } else {
            EngineStore::new()
        };

        Ok(Self {
            config,
            store,
            cache_entries: HashMap::new(),
            schedule: HashMap::new(),
            adapters: HashMap::new(),
        })
    }

    #[must_use]
    pub fn store(&self) -> &EngineStore {
        &self.store
    }

    #[must_use]
    pub fn cache_entry(&self, entity_id: EntityId) -> Option<&CacheEntry> {
        self.cache_entries.get(&entity_id)
    }

    #[must_use]
    pub fn stats(&self) -> StoreStats {
        self.store.stats()
    }

    pub fn register_metric(&mut self, metric: MetricDefinition) -> Result<(), EngineError> {
        self.store.register_metric(metric)?;
        Ok(())
    }

    pub fn register_node(&mut self, node: Node) -> Result<(), EngineError> {
        self.store.upsert_node(node)?;
        Ok(())
    }

    pub fn register_edge(&mut self, edge: Edge) -> Result<(), EngineError> {
        self.store.upsert_edge(edge)?;
        Ok(())
    }

    pub fn register_boundary(&mut self, boundary: Boundary) -> Result<(), EngineError> {
        self.store.upsert_boundary(boundary)?;
        Ok(())
    }

    pub fn register_source(
        &mut self,
        source: SourceDefinition,
        adapter: Box<dyn SourceAdapter>,
        now: Timestamp,
    ) -> Result<(), EngineError> {
        source.validate()?;
        if source.adapter != adapter.kind() {
            return Err(EngineError::Validation(format!(
                "source adapter mismatch: definition says {:?}, adapter is {:?}",
                source.adapter,
                adapter.kind()
            )));
        }

        self.store.register_source(source.clone())?;
        self.adapters.insert(source.id, adapter);
        self.schedule.insert(
            source.id,
            ScheduleEntry::new(source.id, source.schedule, now, 128, Duration::ZERO)?,
        );
        Ok(())
    }

    pub fn enqueue_manual_batch(
        &mut self,
        source_id: SourceId,
        batch: SourcePull,
    ) -> Result<(), EngineError> {
        let adapter = self
            .adapters
            .get_mut(&source_id)
            .ok_or(EngineError::MissingAdapter(source_id))?;
        let manual = adapter
            .as_any_mut()
            .downcast_mut::<ManualPushAdapter>()
            .ok_or(EngineError::WrongAdapterKind(source_id))?;
        manual.push_batch(batch);
        Ok(())
    }

    pub fn promote_for_view(
        &mut self,
        view_job: &ViewJob,
        now: Timestamp,
    ) -> Result<(), EngineError> {
        view_job.validate()?;
        let requested_tier = view_job
            .detail_override
            .unwrap_or(if view_job.requests_history() {
                DetailTier::Sampled
            } else {
                DetailTier::Active
            });

        let default_ring_capacity = self.config.default_ring_capacity;
        let requests_history = view_job.requests_history();

        for entity_id in &view_job.entities {
            let entry = self.ensure_cache_entry(*entity_id, requested_tier, now)?;
            entry.is_visible = true;
            if requests_history {
                entry.detail_tier = DetailTier::Sampled;
                for metric_id in &view_job.metrics {
                    ensure_ring_buffer(entry, *metric_id, default_ring_capacity)?;
                }
            }
        }

        Ok(())
    }

    pub fn tick(&mut self, now: Timestamp) -> Result<TickReport, EngineError> {
        let due_sources: Vec<SourceId> = self
            .schedule
            .iter()
            .filter_map(|(source_id, entry)| {
                self.store
                    .source(*source_id)
                    .filter(|source| source.schedule.is_automatic() && entry.is_due(now))
                    .map(|_| *source_id)
            })
            .collect();

        let mut report = TickReport {
            due_sources: due_sources.len(),
            ..TickReport::default()
        };

        for source_id in due_sources {
            report.polled_sources += 1;
            match self.poll_source(source_id, now) {
                Ok(batch_report) => {
                    self.mark_source_success(source_id, now)?;
                    report.raw_records_seen += batch_report.raw_records_seen;
                    report.samples_seen += batch_report.samples_seen;
                    report.samples_stored += batch_report.samples_stored;
                }
                Err(err) => {
                    self.mark_source_failure(source_id, now)?;
                    return Err(err);
                }
            }
        }

        self.store.prune_retained_samples(now);
        self.evict_expired_cache(now);
        Ok(report)
    }

    pub fn poll_source_now(
        &mut self,
        source_id: SourceId,
        now: Timestamp,
    ) -> Result<TickReport, EngineError> {
        let report = self.poll_source(source_id, now)?;
        self.mark_source_success(source_id, now)?;
        self.store.prune_retained_samples(now);
        self.evict_expired_cache(now);
        Ok(report)
    }

    pub fn hydrate_data_card(
        &self,
        entity_id: EntityId,
        metrics: &[MetricId],
        now: Timestamp,
        time_range: TimeRange,
    ) -> Result<DataCard, EngineError> {
        let label = self
            .store
            .entity_label(entity_id)
            .unwrap_or_else(|| entity_id.to_string());
        let mut fields = Vec::new();
        let mut history_available = false;

        for metric_id in metrics {
            if let Some(latest) = self.store.latest_value(entity_id, *metric_id) {
                let metric = self
                    .store
                    .metric(*metric_id)
                    .ok_or(EngineError::Store(format!("metric missing: {metric_id}")))?;
                let display_value = sample_value_to_string(&latest.value);
                fields.push(DataCardField {
                    metric_name: metric.name.clone(),
                    display_value,
                    unit: metric.unit.clone(),
                    timestamp: latest.timestamp,
                });

                if !self
                    .store
                    .samples_for(entity_id, *metric_id, time_range, now)
                    .is_empty()
                {
                    history_available = true;
                }
            }
        }

        Ok(DataCard {
            entity_id,
            label,
            kind_label: "entity".into(),
            summary_fields: fields,
            history_available,
        })
    }

    fn poll_source(
        &mut self,
        source_id: SourceId,
        now: Timestamp,
    ) -> Result<TickReport, EngineError> {
        let source = self
            .store
            .source(source_id)
            .cloned()
            .ok_or(EngineError::UnknownSource(source_id))?;
        let adapter = self
            .adapters
            .get_mut(&source_id)
            .ok_or(EngineError::MissingAdapter(source_id))?;
        let batch = adapter.pull(&source, now)?;
        batch.validate_against(&self.metric_map())?;

        let mut report = TickReport::default();
        report.raw_records_seen = batch.raw_count();
        report.samples_seen = batch.sample_count();

        for raw in &batch.raw_records {
            self.store.ingest_raw_record(raw)?;
        }
        for sample in batch.samples {
            let stored = self.store.ingest_sample(sample.clone())?;
            if stored.stored_history {
                report.samples_stored += 1;
            }
            self.update_cache_from_sample(&sample, now)?;
        }

        Ok(report)
    }

    fn metric_map(&self) -> HashMap<MetricId, MetricDefinition> {
        self.store
            .metric_ids()
            .into_iter()
            .filter_map(|id| self.store.metric(id).cloned().map(|metric| (id, metric)))
            .collect()
    }

    fn update_cache_from_sample(
        &mut self,
        sample: &Sample,
        now: Timestamp,
    ) -> Result<(), EngineError> {
        let hot_duration = self
            .store
            .metric(sample.metric_id)
            .ok_or_else(|| EngineError::Store(format!("unknown metric {}", sample.metric_id)))?
            .retention
            .hot_duration;
        let latest = LatestValue::from_sample(sample);

        let entry = self.ensure_cache_entry(sample.entity_id, DetailTier::Active, now)?;
        entry.ttl = hot_duration;
        entry.touch(now);
        entry.upsert_latest(latest);

        if let Some(buffer) = entry
            .ring_buffers
            .iter_mut()
            .find(|buffer| buffer.metric_id == sample.metric_id)
        {
            buffer.push(sample.clone());
        }
        Ok(())
    }

    fn ensure_cache_entry(
        &mut self,
        entity_id: EntityId,
        detail_tier: DetailTier,
        now: Timestamp,
    ) -> Result<&mut CacheEntry, EngineError> {
        if !self.cache_entries.contains_key(&entity_id)
            && self.cache_entries.len() >= self.config.cache_budget.max_active_entities
        {
            self.evict_one_for_capacity();
        }

        let ttl = self.config.default_entity_ttl;
        let entry = self
            .cache_entries
            .entry(entity_id)
            .or_insert(CacheEntry::new(entity_id, detail_tier, ttl, now)?);
        if entry.detail_tier < detail_tier {
            entry.detail_tier = detail_tier;
        }
        Ok(entry)
    }

    fn evict_expired_cache(&mut self, now: Timestamp) {
        self.cache_entries.retain(|_, entry| {
            if matches!(entry.eviction_policy, crate::cache::EvictionPolicy::Pinned) {
                return true;
            }
            let age = now.signed_duration_since(entry.last_accessed);
            let Ok(age) = age.to_std() else {
                return true;
            };
            age <= entry.ttl
        });
    }

    fn evict_one_for_capacity(&mut self) {
        if let Some(candidate) = self
            .cache_entries
            .iter()
            .filter(|(_, entry)| !entry.is_selected && !entry.is_visible)
            .min_by_key(|(_, entry)| (entry.priority, entry.last_accessed))
            .map(|(entity_id, _)| *entity_id)
        {
            self.cache_entries.remove(&candidate);
        }
    }

    fn mark_source_success(
        &mut self,
        source_id: SourceId,
        now: Timestamp,
    ) -> Result<(), EngineError> {
        let schedule = {
            let source = self
                .store
                .source_mut(source_id)
                .ok_or(EngineError::UnknownSource(source_id))?;
            source.health = SourceHealth::Healthy;
            source.last_polled = Some(now);
            source.last_error = None;
            source.schedule
        };

        let entry = self
            .schedule
            .get_mut(&source_id)
            .ok_or(EngineError::UnknownSource(source_id))?;
        entry.mark_success(schedule, now)?;
        Ok(())
    }

    fn mark_source_failure(
        &mut self,
        source_id: SourceId,
        now: Timestamp,
    ) -> Result<(), EngineError> {
        let (backoff, max_backoff) = {
            let source = self
                .store
                .source_mut(source_id)
                .ok_or(EngineError::UnknownSource(source_id))?;
            source.health = SourceHealth::Degraded;
            source.last_error = Some(now);
            (source.backoff, source.max_backoff)
        };

        let entry = self
            .schedule
            .get_mut(&source_id)
            .ok_or(EngineError::UnknownSource(source_id))?;
        entry.mark_failure(backoff, max_backoff, now)?;
        Ok(())
    }
}

fn ensure_ring_buffer(
    entry: &mut CacheEntry,
    metric_id: MetricId,
    capacity: usize,
) -> Result<(), EngineError> {
    if entry
        .ring_buffers
        .iter()
        .any(|buffer| buffer.metric_id == metric_id)
    {
        return Ok(());
    }
    entry
        .ring_buffers
        .push(RingBuffer::new(entry.entity_id, metric_id, capacity)?);
    Ok(())
}

fn sample_value_to_string(value: &crate::metric::SampleValue) -> String {
    match value {
        crate::metric::SampleValue::Numeric(v) => format!("{v}"),
        crate::metric::SampleValue::Code(v) => v.clone(),
        crate::metric::SampleValue::Flag(v) => v.to_string(),
        crate::metric::SampleValue::Missing => "missing".into(),
    }
}
