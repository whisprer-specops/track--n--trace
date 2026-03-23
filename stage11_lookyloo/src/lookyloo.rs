//! Lookyloo-specific source adapter.
//!
//! This is a Rust-side source/plugin layer for ingesting Lookyloo capture-summary
//! payloads into Skeletrace without trying to reimplement the entire Lookyloo
//! application in Rust.
//!
//! The adapter targets the summary shape exposed by Lookyloo cache/export data:
//! - `uuid`
//! - `title`
//! - `timestamp`
//! - `url`
//! - `redirects`
//! - `error`
//! - `no_index`
//! - `categories`
//! - `parent`
//! - `user_agent`
//! - `referer`
//! - `capture_dir`
//!
//! The input payload may be:
//! - a single summary object
//! - an array of summary objects
//! - an object containing an array at a configured JSON pointer such as
//!   `/captures`.

use std::any::Any;
use std::time::Duration;

use chrono::{DateTime, FixedOffset, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::adapter::{AdapterError, SourceAdapter, SourcePull};
use crate::ingest::{AdapterKind, RawIngestRecord, SourceDefinition};
use crate::metric::{Sample, SampleValue};
use crate::transport::{http_get_text, HttpRequestProfile};
use crate::types::{EntityId, MetricId, Quality, SourceId, Timestamp, ValidationError};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LookylooMetricBindings {
    pub title: Option<MetricId>,
    pub root_url: Option<MetricId>,
    pub final_url: Option<MetricId>,
    pub redirect_count: Option<MetricId>,
    pub has_error: Option<MetricId>,
    pub error_text: Option<MetricId>,
    pub no_index: Option<MetricId>,
    pub category_count: Option<MetricId>,
    pub categories_joined: Option<MetricId>,
    pub has_parent: Option<MetricId>,
    pub parent_capture: Option<MetricId>,
    pub user_agent: Option<MetricId>,
    pub referer: Option<MetricId>,
    pub capture_dir: Option<MetricId>,
}

impl LookylooMetricBindings {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.title.is_none()
            && self.root_url.is_none()
            && self.final_url.is_none()
            && self.redirect_count.is_none()
            && self.has_error.is_none()
            && self.error_text.is_none()
            && self.no_index.is_none()
            && self.category_count.is_none()
            && self.categories_joined.is_none()
            && self.has_parent.is_none()
            && self.parent_capture.is_none()
            && self.user_agent.is_none()
            && self.referer.is_none()
            && self.capture_dir.is_none()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LookylooSourceConfig {
    /// Optional JSON pointer to the array/object containing capture summaries.
    /// Examples: `/captures`, `/response/items`.
    pub payload_root_pointer: Option<String>,
    /// Include the original upstream summary object as a raw ingest record.
    pub include_raw_payload: bool,
    pub default_quality: Quality,
    pub metrics: LookylooMetricBindings,
}

impl LookylooSourceConfig {
    pub fn validate(&self) -> Result<(), ValidationError> {
        if let Some(pointer) = &self.payload_root_pointer {
            if pointer.trim().is_empty() {
                return Err(ValidationError::EmptyField(
                    "lookyloo.payload_root_pointer".into(),
                ));
            }
            if !pointer.starts_with('/') {
                return Err(ValidationError::InvalidState(
                    "lookyloo.payload_root_pointer must be a JSON pointer starting with '/'".into(),
                ));
            }
        }
        if self.metrics.is_empty() {
            return Err(ValidationError::ZeroCapacity("lookyloo.metrics".into()));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LookylooCaptureSummary {
    pub uuid: String,
    pub title: Option<String>,
    pub timestamp: Option<Timestamp>,
    pub url: Option<String>,
    pub redirects: Vec<String>,
    pub error: Option<String>,
    pub no_index: bool,
    pub categories: Vec<String>,
    pub parent: Option<String>,
    pub user_agent: Option<String>,
    pub referer: Option<String>,
    pub capture_dir: Option<String>,
}

impl LookylooCaptureSummary {
    pub fn from_value(value: &Value) -> Result<Self, AdapterError> {
        let object = value.as_object().ok_or_else(|| {
            AdapterError::Parse("lookyloo summary entry must be a JSON object".into())
        })?;

        let uuid = object
            .get("uuid")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
            .ok_or_else(|| AdapterError::Parse("lookyloo summary missing `uuid`".into()))?;

        Ok(Self {
            uuid,
            title: optional_string_field(object.get("title")),
            timestamp: match object.get("timestamp") {
                Some(value) => parse_timestamp_value(value)?,
                None => None,
            },
            url: optional_string_field(object.get("url")),
            redirects: parse_string_list_field(object.get("redirects"))?,
            error: optional_string_field(object.get("error")),
            no_index: parse_boolish_field(object.get("no_index"))?,
            categories: parse_string_list_field(object.get("categories"))?,
            parent: optional_string_field(object.get("parent")),
            user_agent: optional_string_field(object.get("user_agent")),
            referer: optional_string_field(object.get("referer")),
            capture_dir: optional_string_field(object.get("capture_dir")),
        })
    }

    #[must_use]
    pub fn entity_id(&self, source_id: SourceId) -> EntityId {
        if let Ok(uuid) = Uuid::parse_str(&self.uuid) {
            return EntityId::from_uuid(Uuid::new_v5(&source_id.as_uuid(), uuid.as_bytes()));
        }
        EntityId::from_uuid(Uuid::new_v5(&source_id.as_uuid(), self.uuid.as_bytes()))
    }

    #[must_use]
    pub fn observed_at(&self, now: Timestamp) -> Timestamp {
        self.timestamp.unwrap_or(now)
    }

    #[must_use]
    pub fn final_url(&self) -> Option<&str> {
        self.redirects
            .last()
            .map(String::as_str)
            .or(self.url.as_deref())
    }
}

#[derive(Debug, Clone)]
pub struct LookylooSummaryAdapter {
    config: LookylooSourceConfig,
    request_profile: HttpRequestProfile,
}

impl LookylooSummaryAdapter {
    pub fn new(config: LookylooSourceConfig, timeout: Duration) -> Result<Self, AdapterError> {
        Self::with_request_profile(config, HttpRequestProfile::direct(timeout))
    }

    pub fn with_request_profile(
        config: LookylooSourceConfig,
        request_profile: HttpRequestProfile,
    ) -> Result<Self, AdapterError> {
        config.validate()?;
        request_profile.validate()?;
        Ok(Self {
            config,
            request_profile,
        })
    }

    pub fn pull_from_text(
        &self,
        source: &SourceDefinition,
        now: Timestamp,
        body: &str,
    ) -> Result<SourcePull, AdapterError> {
        let payload: Value =
            serde_json::from_str(body).map_err(|err| AdapterError::Parse(err.to_string()))?;
        self.pull_from_value(source, now, payload)
    }

    pub fn pull_from_value(
        &self,
        source: &SourceDefinition,
        now: Timestamp,
        payload: Value,
    ) -> Result<SourcePull, AdapterError> {
        let items = lookyloo_payload_items(&payload, self.config.payload_root_pointer.as_deref())?;

        let mut batch = SourcePull::default();
        for item in items {
            let summary = LookylooCaptureSummary::from_value(item)?;
            let entity_id = summary.entity_id(source.id);
            let observed_at = summary.observed_at(now);

            if self.config.include_raw_payload {
                batch.raw_records.push(RawIngestRecord {
                    source_id: source.id,
                    source_timestamp: Some(observed_at),
                    ingested_at: now,
                    payload: item.clone(),
                });
            }

            let samples = build_samples_from_summary(
                source.id,
                entity_id,
                observed_at,
                now,
                &summary,
                &self.config,
            );
            if !samples.is_empty() {
                batch.touched_entities.push(entity_id);
                batch.samples.extend(samples);
            }
        }

        Ok(batch)
    }
}

impl SourceAdapter for LookylooSummaryAdapter {
    fn kind(&self) -> AdapterKind {
        AdapterKind::HttpPoller
    }

    fn pull(
        &mut self,
        source: &SourceDefinition,
        now: Timestamp,
    ) -> Result<SourcePull, AdapterError> {
        let body = http_get_text(&source.endpoint, &self.request_profile)?;
        self.pull_from_text(source, now, &body)
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

fn lookyloo_payload_items<'a>(
    payload: &'a Value,
    pointer: Option<&str>,
) -> Result<Vec<&'a Value>, AdapterError> {
    let root = match pointer {
        Some(pointer) => payload.pointer(pointer).ok_or_else(|| {
            AdapterError::Parse(format!(
                "lookyloo payload root pointer `{pointer}` not present"
            ))
        })?,
        None => payload,
    };

    match root {
        Value::Array(items) => Ok(items.iter().collect()),
        Value::Object(map) => {
            if let Some(captures) = map.get("captures") {
                match captures {
                    Value::Array(items) => Ok(items.iter().collect()),
                    other => Ok(vec![other]),
                }
            } else {
                Ok(vec![root])
            }
        }
        _ => Err(AdapterError::Parse(
            "lookyloo payload root must be an object or array".into(),
        )),
    }
}

fn build_samples_from_summary(
    source_id: SourceId,
    entity_id: EntityId,
    observed_at: Timestamp,
    ingested_at: Timestamp,
    summary: &LookylooCaptureSummary,
    config: &LookylooSourceConfig,
) -> Vec<Sample> {
    let mut out = Vec::new();
    let bindings = &config.metrics;

    push_code_sample(
        &mut out,
        bindings.title,
        summary.title.as_deref(),
        source_id,
        entity_id,
        observed_at,
        ingested_at,
        config.default_quality,
    );
    push_code_sample(
        &mut out,
        bindings.root_url,
        summary.url.as_deref(),
        source_id,
        entity_id,
        observed_at,
        ingested_at,
        config.default_quality,
    );
    push_code_sample(
        &mut out,
        bindings.final_url,
        summary.final_url(),
        source_id,
        entity_id,
        observed_at,
        ingested_at,
        config.default_quality,
    );
    push_numeric_sample(
        &mut out,
        bindings.redirect_count,
        summary.redirects.len() as f64,
        source_id,
        entity_id,
        observed_at,
        ingested_at,
        config.default_quality,
    );
    push_flag_sample(
        &mut out,
        bindings.has_error,
        summary.error.is_some(),
        source_id,
        entity_id,
        observed_at,
        ingested_at,
        config.default_quality,
    );
    push_code_sample(
        &mut out,
        bindings.error_text,
        summary.error.as_deref(),
        source_id,
        entity_id,
        observed_at,
        ingested_at,
        config.default_quality,
    );
    push_flag_sample(
        &mut out,
        bindings.no_index,
        summary.no_index,
        source_id,
        entity_id,
        observed_at,
        ingested_at,
        config.default_quality,
    );
    push_numeric_sample(
        &mut out,
        bindings.category_count,
        summary.categories.len() as f64,
        source_id,
        entity_id,
        observed_at,
        ingested_at,
        config.default_quality,
    );
    let joined_categories = if summary.categories.is_empty() {
        None
    } else {
        Some(summary.categories.join("|"))
    };
    push_code_sample_owned(
        &mut out,
        bindings.categories_joined,
        joined_categories,
        source_id,
        entity_id,
        observed_at,
        ingested_at,
        config.default_quality,
    );
    push_flag_sample(
        &mut out,
        bindings.has_parent,
        summary.parent.is_some(),
        source_id,
        entity_id,
        observed_at,
        ingested_at,
        config.default_quality,
    );
    push_code_sample(
        &mut out,
        bindings.parent_capture,
        summary.parent.as_deref(),
        source_id,
        entity_id,
        observed_at,
        ingested_at,
        config.default_quality,
    );
    push_code_sample(
        &mut out,
        bindings.user_agent,
        summary.user_agent.as_deref(),
        source_id,
        entity_id,
        observed_at,
        ingested_at,
        config.default_quality,
    );
    push_code_sample(
        &mut out,
        bindings.referer,
        summary.referer.as_deref(),
        source_id,
        entity_id,
        observed_at,
        ingested_at,
        config.default_quality,
    );
    push_code_sample(
        &mut out,
        bindings.capture_dir,
        summary.capture_dir.as_deref(),
        source_id,
        entity_id,
        observed_at,
        ingested_at,
        config.default_quality,
    );

    out
}

fn push_numeric_sample(
    out: &mut Vec<Sample>,
    metric_id: Option<MetricId>,
    value: f64,
    source_id: SourceId,
    entity_id: EntityId,
    observed_at: Timestamp,
    ingested_at: Timestamp,
    quality: Quality,
) {
    if let Some(metric_id) = metric_id {
        out.push(Sample {
            entity_id,
            metric_id,
            ts_observed: observed_at,
            ts_ingested: ingested_at,
            value: SampleValue::Numeric(value),
            quality,
            source_id,
        });
    }
}

fn push_flag_sample(
    out: &mut Vec<Sample>,
    metric_id: Option<MetricId>,
    value: bool,
    source_id: SourceId,
    entity_id: EntityId,
    observed_at: Timestamp,
    ingested_at: Timestamp,
    quality: Quality,
) {
    if let Some(metric_id) = metric_id {
        out.push(Sample {
            entity_id,
            metric_id,
            ts_observed: observed_at,
            ts_ingested: ingested_at,
            value: SampleValue::Flag(value),
            quality,
            source_id,
        });
    }
}

fn push_code_sample(
    out: &mut Vec<Sample>,
    metric_id: Option<MetricId>,
    value: Option<&str>,
    source_id: SourceId,
    entity_id: EntityId,
    observed_at: Timestamp,
    ingested_at: Timestamp,
    quality: Quality,
) {
    if let (Some(metric_id), Some(value)) = (metric_id, value) {
        out.push(Sample {
            entity_id,
            metric_id,
            ts_observed: observed_at,
            ts_ingested: ingested_at,
            value: SampleValue::Code(value.to_owned()),
            quality,
            source_id,
        });
    }
}

fn push_code_sample_owned(
    out: &mut Vec<Sample>,
    metric_id: Option<MetricId>,
    value: Option<String>,
    source_id: SourceId,
    entity_id: EntityId,
    observed_at: Timestamp,
    ingested_at: Timestamp,
    quality: Quality,
) {
    if let (Some(metric_id), Some(value)) = (metric_id, value) {
        out.push(Sample {
            entity_id,
            metric_id,
            ts_observed: observed_at,
            ts_ingested: ingested_at,
            value: SampleValue::Code(value),
            quality,
            source_id,
        });
    }
}

fn optional_string_field(value: Option<&Value>) -> Option<String> {
    match value {
        Some(Value::String(v)) => Some(v.clone()),
        Some(Value::Number(v)) => Some(v.to_string()),
        Some(Value::Bool(v)) => Some(v.to_string()),
        Some(Value::Null) | None => None,
        Some(other) => Some(other.to_string()),
    }
}

fn parse_string_list_field(value: Option<&Value>) -> Result<Vec<String>, AdapterError> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };

    match value {
        Value::Null => Ok(Vec::new()),
        Value::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                let Some(text) = optional_string_field(Some(item)) else {
                    continue;
                };
                if !text.trim().is_empty() {
                    out.push(text);
                }
            }
            Ok(out)
        }
        Value::String(text) => parse_string_list_string(text),
        other => Ok(vec![other.to_string()]),
    }
}

fn parse_string_list_string(text: &str) -> Result<Vec<String>, AdapterError> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    if trimmed.starts_with('[') {
        let parsed: Value = serde_json::from_str(trimmed)
            .map_err(|err| AdapterError::Parse(format!("invalid JSON string list: {err}")))?;
        return parse_string_list_field(Some(&parsed));
    }
    Ok(vec![trimmed.to_owned()])
}

fn parse_boolish_field(value: Option<&Value>) -> Result<bool, AdapterError> {
    let Some(value) = value else {
        return Ok(false);
    };

    match value {
        Value::Bool(v) => Ok(*v),
        Value::Number(v) => Ok(v.as_i64().unwrap_or_default() != 0),
        Value::String(v) => match v.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "y" => Ok(true),
            "0" | "false" | "no" | "n" | "" => Ok(false),
            other => Err(AdapterError::Parse(format!(
                "cannot coerce lookyloo boolish field `{other}`"
            ))),
        },
        Value::Null => Ok(false),
        other => Err(AdapterError::Parse(format!(
            "cannot coerce lookyloo boolish field from {other:?}"
        ))),
    }
}

fn parse_timestamp_value(value: &Value) -> Result<Option<Timestamp>, AdapterError> {
    match value {
        Value::Null => Ok(None),
        Value::String(text) => parse_timestamp_string(text).map(Some),
        other => Err(AdapterError::Parse(format!(
            "lookyloo timestamp must be a string, got {other:?}"
        ))),
    }
}

fn parse_timestamp_string(text: &str) -> Result<Timestamp, AdapterError> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Err(AdapterError::Parse(
            "lookyloo timestamp string must not be empty".into(),
        ));
    }

    if let Ok(parsed) = DateTime::parse_from_rfc3339(trimmed) {
        return Ok(parsed.with_timezone(&Utc));
    }
    if let Ok(parsed) = DateTime::parse_from_str(trimmed, "%Y-%m-%dT%H:%M:%S.%f%z") {
        return Ok(parsed.with_timezone(&Utc));
    }
    if let Ok(parsed) = DateTime::parse_from_str(trimmed, "%Y-%m-%dT%H:%M:%S%z") {
        return Ok(parsed.with_timezone(&Utc));
    }
    if let Ok(parsed) = DateTime::parse_from_str(trimmed, "%Y-%m-%d %H:%M:%S%z") {
        return Ok(parsed.with_timezone(&Utc));
    }
    if let Ok(parsed) = DateTime::<FixedOffset>::parse_from_str(trimmed, "%a, %d %b %Y %H:%M:%S %z")
    {
        return Ok(parsed.with_timezone(&Utc));
    }

    Err(AdapterError::Parse(format!(
        "unsupported lookyloo timestamp `{trimmed}`"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Timelike};

    use crate::ingest::{SourceHealth, SourceKind, SourceSchedule};
    use crate::types::{Quality, SourceId, Tag};

    fn test_source() -> SourceDefinition {
        SourceDefinition {
            id: SourceId::new(),
            name: "lookyloo-test".into(),
            kind: SourceKind::Api,
            adapter: AdapterKind::HttpPoller,
            schedule: SourceSchedule::Manual,
            endpoint: "https://example.invalid/lookyloo".into(),
            auth_ref: None,
            health: SourceHealth::Pending,
            last_polled: None,
            last_error: None,
            backoff: Duration::from_secs(5),
            max_backoff: Duration::from_secs(30),
            tags: vec![Tag::new("source", "lookyloo").unwrap()],
        }
    }

    fn test_config() -> LookylooSourceConfig {
        LookylooSourceConfig {
            payload_root_pointer: None,
            include_raw_payload: true,
            default_quality: Quality::new(0.9).unwrap(),
            metrics: LookylooMetricBindings {
                title: Some(MetricId::new()),
                root_url: Some(MetricId::new()),
                final_url: Some(MetricId::new()),
                redirect_count: Some(MetricId::new()),
                has_error: Some(MetricId::new()),
                error_text: Some(MetricId::new()),
                no_index: Some(MetricId::new()),
                category_count: Some(MetricId::new()),
                categories_joined: Some(MetricId::new()),
                has_parent: Some(MetricId::new()),
                parent_capture: Some(MetricId::new()),
                user_agent: Some(MetricId::new()),
                referer: Some(MetricId::new()),
                capture_dir: Some(MetricId::new()),
            },
        }
    }

    #[test]
    fn parse_lookyloo_summary_with_python_style_serialized_fields() {
        let value = serde_json::json!({
            "uuid": "8e8cc8dd-fc9e-4717-a7cb-a8b76f7bb6e5",
            "title": "Example Title",
            "timestamp": "2025-03-23T12:34:56.123456+0000",
            "url": "https://example.com",
            "redirects": "[\"https://redirect-1.example\",\"https://redirect-2.example\"]",
            "error": "boom",
            "no_index": 1,
            "categories": "[\"phish\",\"kit\"]",
            "parent": "parent-uuid",
            "user_agent": "Mozilla/5.0",
            "referer": "https://ref.example",
            "capture_dir": "/captures/one"
        });

        let summary = LookylooCaptureSummary::from_value(&value).unwrap();
        assert_eq!(summary.redirects.len(), 2);
        assert_eq!(summary.categories.len(), 2);
        assert!(summary.no_index);
        assert_eq!(summary.final_url(), Some("https://redirect-2.example"));
        assert_eq!(
            summary.timestamp.unwrap(),
            Utc.with_ymd_and_hms(2025, 3, 23, 12, 34, 56)
                .unwrap()
                .with_nanosecond(123_456_000)
                .unwrap()
        );
    }

    #[test]
    fn adapter_builds_samples_from_wrapper_payload() {
        let mut config = test_config();
        config.payload_root_pointer = Some("/captures".into());
        let adapter = LookylooSummaryAdapter::with_request_profile(
            config,
            HttpRequestProfile::direct(Duration::from_secs(5)),
        )
        .unwrap();
        let source = test_source();
        let now = Utc.with_ymd_and_hms(2025, 3, 23, 13, 0, 0).unwrap();
        let body = serde_json::json!({
            "captures": [
                {
                    "uuid": "capture-a",
                    "title": "A",
                    "timestamp": "2025-03-23T12:00:00+0000",
                    "url": "https://example-a.test",
                    "redirects": ["https://example-a.test/landing"],
                    "categories": ["news"],
                    "no_index": false
                },
                {
                    "uuid": "capture-b",
                    "url": "https://example-b.test",
                    "error": "network",
                    "no_index": true,
                    "categories": []
                }
            ]
        })
        .to_string();

        let batch = adapter.pull_from_text(&source, now, &body).unwrap();
        assert_eq!(batch.raw_records.len(), 2);
        assert_eq!(batch.touched_entities.len(), 2);
        assert!(batch.samples.len() >= 10);
        assert!(batch
            .samples
            .iter()
            .any(|sample| matches!(sample.value, SampleValue::Flag(true))));
        assert!(batch
            .samples
            .iter()
            .any(|sample| matches!(&sample.value, SampleValue::Code(code) if code == "https://example-a.test/landing")));
    }
}
