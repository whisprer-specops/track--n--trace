//! Query, watchlist, and alert contracts.
//!
//! These are intentionally lightweight and source-agnostic. They let an
//! operator search current engine state, define a small set of tracked
//! entity+metric pairs, and evaluate alert conditions without assuming any
//! specific acquisition tactic.

use serde::{Deserialize, Serialize};

use crate::entity::EntityStatus;
use crate::metric::SampleValue;
use crate::types::{EntityId, MetricId, Quality, SourceId, Timestamp, ValidationError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EntityClass {
    Node,
    Edge,
    Boundary,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntitySelector {
    pub entity_ids: Vec<EntityId>,
    pub label_contains: Option<String>,
    pub class: Option<EntityClass>,
}

impl EntitySelector {
    pub fn validate(&self) -> Result<(), ValidationError> {
        if let Some(value) = &self.label_contains {
            if value.trim().is_empty() {
                return Err(ValidationError::EmptyField(
                    "entity_selector.label_contains".into(),
                ));
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn matches_label(&self, label: &str) -> bool {
        self.label_contains
            .as_ref()
            .map(|needle| {
                label
                    .to_ascii_lowercase()
                    .contains(&needle.to_ascii_lowercase())
            })
            .unwrap_or(true)
    }

    #[must_use]
    pub fn matches_id(&self, entity_id: EntityId) -> bool {
        self.entity_ids.is_empty() || self.entity_ids.contains(&entity_id)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum NumericPredicate {
    AtLeast(f64),
    AtMost(f64),
    BetweenInclusive { min: f64, max: f64 },
}

impl NumericPredicate {
    pub fn validate(&self) -> Result<(), ValidationError> {
        match self {
            Self::AtLeast(v) | Self::AtMost(v) if !v.is_finite() => Err(
                ValidationError::InvalidState("numeric predicate bound must be finite".into()),
            ),
            Self::BetweenInclusive { min, max } => {
                if !min.is_finite() || !max.is_finite() {
                    return Err(ValidationError::InvalidState(
                        "numeric predicate bounds must be finite".into(),
                    ));
                }
                if max < min {
                    return Err(ValidationError::InvalidWindow {
                        start_field: "numeric_predicate.min".into(),
                        end_field: "numeric_predicate.max".into(),
                    });
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    #[must_use]
    pub fn matches(&self, value: f64) -> bool {
        match self {
            Self::AtLeast(min) => value >= *min,
            Self::AtMost(max) => value <= *max,
            Self::BetweenInclusive { min, max } => value >= *min && value <= *max,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QueryFilter {
    pub entities: EntitySelector,
    pub metric_ids: Vec<MetricId>,
    pub only_hot: bool,
    pub numeric_predicate: Option<NumericPredicate>,
    pub limit: Option<usize>,
}

impl QueryFilter {
    pub fn validate(&self) -> Result<(), ValidationError> {
        self.entities.validate()?;
        if let Some(predicate) = &self.numeric_predicate {
            predicate.validate()?;
        }
        if let Some(limit) = self.limit {
            if limit == 0 {
                return Err(ValidationError::ZeroCapacity("query.limit".into()));
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn matches_metric(&self, metric_id: MetricId) -> bool {
        self.metric_ids.is_empty() || self.metric_ids.contains(&metric_id)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QueryRow {
    pub entity_id: EntityId,
    pub entity_label: String,
    pub entity_class: EntityClass,
    pub entity_status: EntityStatus,
    pub metric_id: MetricId,
    pub metric_name: String,
    pub value: SampleValue,
    pub display_value: String,
    pub timestamp: Timestamp,
    pub quality: Quality,
    pub source_id: SourceId,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QueryResult {
    pub generated_at: Timestamp,
    pub rows: Vec<QueryRow>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AlertRule {
    NumericAtLeast(f64),
    NumericAtMost(f64),
    NumericOutsideInclusive { min: f64, max: f64 },
    CodeEquals(String),
    FlagIs(bool),
    AnyPresent,
}

impl AlertRule {
    pub fn validate(&self) -> Result<(), ValidationError> {
        match self {
            Self::NumericAtLeast(v) | Self::NumericAtMost(v) if !v.is_finite() => Err(
                ValidationError::InvalidState("alert threshold must be finite".into()),
            ),
            Self::NumericOutsideInclusive { min, max } => {
                if !min.is_finite() || !max.is_finite() {
                    return Err(ValidationError::InvalidState(
                        "alert threshold bounds must be finite".into(),
                    ));
                }
                if max < min {
                    return Err(ValidationError::InvalidWindow {
                        start_field: "alert_rule.min".into(),
                        end_field: "alert_rule.max".into(),
                    });
                }
                Ok(())
            }
            Self::CodeEquals(value) if value.trim().is_empty() => {
                Err(ValidationError::EmptyField("alert_rule.code".into()))
            }
            _ => Ok(()),
        }
    }

    #[must_use]
    pub fn matches(&self, value: &SampleValue) -> bool {
        match (self, value) {
            (Self::NumericAtLeast(threshold), SampleValue::Numeric(v)) => *v >= *threshold,
            (Self::NumericAtMost(threshold), SampleValue::Numeric(v)) => *v <= *threshold,
            (Self::NumericOutsideInclusive { min, max }, SampleValue::Numeric(v)) => {
                *v < *min || *v > *max
            }
            (Self::CodeEquals(expected), SampleValue::Code(found)) => found == expected,
            (Self::FlagIs(expected), SampleValue::Flag(found)) => found == expected,
            (Self::AnyPresent, SampleValue::Missing) => false,
            (Self::AnyPresent, _) => true,
            _ => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WatchItem {
    pub label: String,
    pub entity_id: EntityId,
    pub metric_id: MetricId,
    pub rule: AlertRule,
}

impl WatchItem {
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.label.trim().is_empty() {
            return Err(ValidationError::EmptyField("watch_item.label".into()));
        }
        self.rule.validate()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Watchlist {
    pub label: String,
    pub items: Vec<WatchItem>,
}

impl Watchlist {
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.label.trim().is_empty() {
            return Err(ValidationError::EmptyField("watchlist.label".into()));
        }
        if self.items.is_empty() {
            return Err(ValidationError::EmptyField("watchlist.items".into()));
        }
        for item in &self.items {
            item.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AlertEvent {
    pub watch_label: String,
    pub item_label: String,
    pub entity_id: EntityId,
    pub entity_label: String,
    pub metric_id: MetricId,
    pub metric_name: String,
    pub display_value: String,
    pub triggered_at: Timestamp,
    pub source_id: SourceId,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WatchlistEvaluation {
    pub evaluated_at: Timestamp,
    pub watchlist_label: String,
    pub checked_items: usize,
    pub missing_items: usize,
    pub alerts: Vec<AlertEvent>,
}
