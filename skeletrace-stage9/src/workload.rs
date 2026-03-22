//! Deterministic replay workloads and operator-facing workload reports.

use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::engine::TickReport;
use crate::profiling::{EngineHealthReport, PerfProbeConfig, PerfProbeReport};
use crate::replay::{ReplayBatch, ReplayHarness};
use crate::types::{Timestamp, ValidationError};
use crate::view::ViewJob;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkloadFixture {
    pub label: String,
    pub batches: Vec<ReplayBatch>,
}

impl WorkloadFixture {
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.label.trim().is_empty() {
            return Err(ValidationError::EmptyField("workload_fixture.label".into()));
        }
        Ok(())
    }

    pub fn load_json(path: impl AsRef<Path>) -> Result<Self, std::io::Error> {
        let text = fs::read_to_string(path)?;
        serde_json::from_str(&text)
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err.to_string()))
    }

    pub fn save_json(&self, path: impl AsRef<Path>) -> Result<(), std::io::Error> {
        let text = serde_json::to_string_pretty(self)
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err.to_string()))?;
        fs::write(path, text)
    }

    #[must_use]
    pub fn into_harness(&self) -> ReplayHarness {
        let mut harness = ReplayHarness::new();
        for batch in &self.batches {
            harness.push_batch(batch.clone());
        }
        harness
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct ReplayIngestReport {
    pub ready_sources: usize,
    pub pulls_processed: usize,
    pub raw_records_seen: usize,
    pub samples_seen: usize,
    pub samples_stored: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ViewProfileTarget {
    pub view: ViewJob,
    pub config: PerfProbeConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayWorkloadRequest {
    pub label: String,
    pub checkpoints: Vec<Timestamp>,
    pub profile_views: Vec<ViewProfileTarget>,
}

impl ReplayWorkloadRequest {
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.label.trim().is_empty() {
            return Err(ValidationError::EmptyField("workload.label".into()));
        }
        if self.checkpoints.is_empty() {
            return Err(ValidationError::EmptyField("workload.checkpoints".into()));
        }
        for window in self.checkpoints.windows(2) {
            if window[0] > window[1] {
                return Err(ValidationError::InvalidWindow {
                    start_field: "workload.checkpoints[i]".into(),
                    end_field: "workload.checkpoints[i+1]".into(),
                });
            }
        }
        for target in &self.profile_views {
            target.view.validate()?;
            target.config.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkloadCheckpointReport {
    pub at: Timestamp,
    pub replay: ReplayIngestReport,
    pub tick: TickReport,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkloadRunReport {
    pub label: String,
    pub started_at: Timestamp,
    pub finished_at: Timestamp,
    pub health_before: EngineHealthReport,
    pub health_after: EngineHealthReport,
    pub checkpoints: Vec<WorkloadCheckpointReport>,
    pub view_profiles: Vec<PerfProbeReport>,
    pub audit_delta: usize,
    pub failure_delta: usize,
    pub event_delta: usize,
}
