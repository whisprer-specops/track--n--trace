//! Source adapter contracts and a few built-in low-overhead adapters.
//!
//! Adapters are responsible for acquiring data and yielding normalized batches
//! that the engine can validate, store, and cache.

use std::any::Any;
use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::io::{BufRead, BufReader};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::ingest::{AdapterKind, RawIngestRecord, SourceDefinition};
use crate::metric::{MetricDefinition, Sample, SampleValue};
use crate::types::{EntityId, MetricId, Quality, Timestamp, ValidationError};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdapterError {
    Validation(String),
    Io(String),
    Parse(String),
    Unsupported(String),
}

impl std::fmt::Display for AdapterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Validation(msg) => write!(f, "adapter validation error: {msg}"),
            Self::Io(msg) => write!(f, "adapter I/O error: {msg}"),
            Self::Parse(msg) => write!(f, "adapter parse error: {msg}"),
            Self::Unsupported(msg) => write!(f, "adapter unsupported: {msg}"),
        }
    }
}

impl std::error::Error for AdapterError {}

impl From<ValidationError> for AdapterError {
    fn from(value: ValidationError) -> Self {
        Self::Validation(value.to_string())
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SourcePull {
    pub raw_records: Vec<RawIngestRecord>,
    pub samples: Vec<Sample>,
    pub touched_entities: Vec<EntityId>,
}

impl SourcePull {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.raw_records.is_empty() && self.samples.is_empty() && self.touched_entities.is_empty()
    }

    #[must_use]
    pub fn sample_count(&self) -> usize {
        self.samples.len()
    }

    #[must_use]
    pub fn raw_count(&self) -> usize {
        self.raw_records.len()
    }

    pub fn validate_against(
        &self,
        metrics: &HashMap<MetricId, MetricDefinition>,
    ) -> Result<(), ValidationError> {
        for sample in &self.samples {
            let definition = metrics.get(&sample.metric_id).ok_or_else(|| {
                ValidationError::InvalidReference(format!(
                    "sample references unknown metric {}",
                    sample.metric_id
                ))
            })?;
            sample.validate(definition)?;
        }
        Ok(())
    }
}

pub trait SourceAdapter: Send {
    fn kind(&self) -> AdapterKind;
    fn pull(
        &mut self,
        source: &SourceDefinition,
        now: Timestamp,
    ) -> Result<SourcePull, AdapterError>;
    fn as_any_mut(&mut self) -> &mut dyn Any;
}

/// Simple FIFO adapter for tests, operator injection, and synthetic/manual feeds.
#[derive(Debug, Default)]
pub struct ManualPushAdapter {
    queue: VecDeque<SourcePull>,
}

impl ManualPushAdapter {
    #[must_use]
    pub fn new() -> Self {
        Self {
            queue: VecDeque::new(),
        }
    }

    pub fn push_batch(&mut self, batch: SourcePull) {
        self.queue.push_back(batch);
    }

    #[must_use]
    pub fn pending_batches(&self) -> usize {
        self.queue.len()
    }
}

impl SourceAdapter for ManualPushAdapter {
    fn kind(&self) -> AdapterKind {
        AdapterKind::Manual
    }

    fn pull(
        &mut self,
        _source: &SourceDefinition,
        _now: Timestamp,
    ) -> Result<SourcePull, AdapterError> {
        Ok(self.queue.pop_front().unwrap_or_default())
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

/// Line-delimited JSON file adapter for pre-normalized sample ingestion.
///
/// Each line must deserialize to [`FileSampleRecord`]. The adapter remembers how
/// many lines it has already consumed per source, so repeated polls only ingest
/// newly appended lines.
#[derive(Debug, Default)]
pub struct NdjsonSampleFileAdapter {
    offsets_by_source: HashMap<crate::types::SourceId, usize>,
}

impl NdjsonSampleFileAdapter {
    #[must_use]
    pub fn new() -> Self {
        Self {
            offsets_by_source: HashMap::new(),
        }
    }
}

impl SourceAdapter for NdjsonSampleFileAdapter {
    fn kind(&self) -> AdapterKind {
        AdapterKind::FileImport
    }

    fn pull(
        &mut self,
        source: &SourceDefinition,
        now: Timestamp,
    ) -> Result<SourcePull, AdapterError> {
        let file = File::open(&source.endpoint)
            .map_err(|err| AdapterError::Io(format!("{}: {err}", source.endpoint)))?;
        let reader = BufReader::new(file);
        let already_seen = self.offsets_by_source.get(&source.id).copied().unwrap_or(0);

        let mut batch = SourcePull::default();
        let mut total_lines = 0usize;

        for (idx, line) in reader.lines().enumerate() {
            total_lines = idx + 1;
            if idx < already_seen {
                continue;
            }

            let line = line.map_err(|err| AdapterError::Io(err.to_string()))?;
            if line.trim().is_empty() {
                continue;
            }

            let record: FileSampleRecord = serde_json::from_str(&line)
                .map_err(|err| AdapterError::Parse(format!("line {}: {err}", idx + 1)))?;
            let raw_payload = record.raw_payload.clone().unwrap_or_else(|| {
                serde_json::json!({
                    "entity_id": record.entity_id,
                    "metric_id": record.metric_id,
                    "value": record.value.clone(),
                    "observed_at": record.ts_observed,
                })
            });

            batch.raw_records.push(RawIngestRecord {
                source_id: source.id,
                source_timestamp: Some(record.ts_observed),
                ingested_at: now,
                payload: raw_payload,
            });
            batch.samples.push(Sample {
                entity_id: record.entity_id,
                metric_id: record.metric_id,
                ts_observed: record.ts_observed,
                ts_ingested: record.ts_ingested.unwrap_or(now),
                value: record.value,
                quality: record.quality,
                source_id: source.id,
            });
            batch.touched_entities.push(record.entity_id);
        }

        self.offsets_by_source.insert(source.id, total_lines);
        Ok(batch)
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileSampleRecord {
    pub entity_id: EntityId,
    pub metric_id: MetricId,
    pub ts_observed: Timestamp,
    pub ts_ingested: Option<Timestamp>,
    pub value: SampleValue,
    pub quality: Quality,
    pub raw_payload: Option<Value>,
}
