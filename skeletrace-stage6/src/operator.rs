//! First operator-facing API and thin CLI command layer.

use std::fs;
use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::engine::{EngineError, SkeletraceEngine, TickReport};
use crate::export::{ExportError, SnapshotExportJob, SnapshotExportResult, SnapshotExporter};
use crate::materialize::{SparseGeoFeatureCollection, TopologyViewMaterialization};
use crate::profile::{EngineProfile, ProfileError};
use crate::types::{EntityId, MetricId, SourceId, Timestamp, ValidationError};
use crate::view::{DataCard, ViewJob};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OperatorError {
    Validation(String),
    Profile(String),
    Engine(String),
    Export(String),
    Io(String),
    Serde(String),
    Cli(String),
}

impl std::fmt::Display for OperatorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Validation(msg) => write!(f, "operator validation error: {msg}"),
            Self::Profile(msg) => write!(f, "operator profile error: {msg}"),
            Self::Engine(msg) => write!(f, "operator engine error: {msg}"),
            Self::Export(msg) => write!(f, "operator export error: {msg}"),
            Self::Io(msg) => write!(f, "operator I/O error: {msg}"),
            Self::Serde(msg) => write!(f, "operator serialization error: {msg}"),
            Self::Cli(msg) => write!(f, "operator CLI error: {msg}"),
        }
    }
}

impl std::error::Error for OperatorError {}

impl From<ValidationError> for OperatorError {
    fn from(value: ValidationError) -> Self {
        Self::Validation(value.to_string())
    }
}

impl From<ProfileError> for OperatorError {
    fn from(value: ProfileError) -> Self {
        Self::Profile(value.to_string())
    }
}

impl From<EngineError> for OperatorError {
    fn from(value: EngineError) -> Self {
        Self::Engine(value.to_string())
    }
}

impl From<ExportError> for OperatorError {
    fn from(value: ExportError) -> Self {
        Self::Export(value.to_string())
    }
}

pub struct OperatorApi {
    engine: SkeletraceEngine,
    exporter: SnapshotExporter,
}

impl std::fmt::Debug for OperatorApi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OperatorApi")
            .field("exporter", &self.exporter)
            .field("engine_stats", &self.engine.stats())
            .finish()
    }
}

impl OperatorApi {
    pub fn new(engine: SkeletraceEngine, exporter: SnapshotExporter) -> Self {
        Self { engine, exporter }
    }

    pub fn from_profile(
        profile: &EngineProfile,
        exporter: SnapshotExporter,
        now: Timestamp,
    ) -> Result<Self, OperatorError> {
        Ok(Self::new(profile.instantiate(now)?, exporter))
    }

    #[must_use]
    pub fn engine(&self) -> &SkeletraceEngine {
        &self.engine
    }

    #[must_use]
    pub fn engine_mut(&mut self) -> &mut SkeletraceEngine {
        &mut self.engine
    }

    pub fn execute(&mut self, request: OperatorRequest) -> Result<OperatorResponse, OperatorError> {
        Ok(match request {
            OperatorRequest::Tick { now } => OperatorResponse::Tick(self.engine.tick(now)?),
            OperatorRequest::PollSource { source_id, now } => {
                OperatorResponse::Tick(self.engine.poll_source_now(source_id, now)?)
            }
            OperatorRequest::MaterializeTopology { view, now } => {
                OperatorResponse::Topology(self.engine.materialize_topology(&view, now)?)
            }
            OperatorRequest::MaterializeSparseGeo { view, now } => {
                let mat = self.engine.materialize_sparse_geo(&view, now)?;
                OperatorResponse::SparseGeo(mat.to_feature_collection())
            }
            OperatorRequest::HydrateDataCard {
                entity_id,
                metrics,
                now,
                time_range,
            } => OperatorResponse::DataCard(
                self.engine
                    .hydrate_data_card(entity_id, &metrics, now, time_range)?,
            ),
            OperatorRequest::ExportSnapshot { job, now } => {
                OperatorResponse::Export(self.exporter.export(&self.engine, &job, now)?)
            }
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OperatorRequest {
    Tick {
        now: Timestamp,
    },
    PollSource {
        source_id: SourceId,
        now: Timestamp,
    },
    MaterializeTopology {
        view: ViewJob,
        now: Timestamp,
    },
    MaterializeSparseGeo {
        view: ViewJob,
        now: Timestamp,
    },
    HydrateDataCard {
        entity_id: EntityId,
        metrics: Vec<MetricId>,
        now: Timestamp,
        time_range: crate::view::TimeRange,
    },
    ExportSnapshot {
        job: SnapshotExportJob,
        now: Timestamp,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OperatorResponse {
    Tick(TickReport),
    Topology(TopologyViewMaterialization),
    SparseGeo(SparseGeoFeatureCollection),
    DataCard(DataCard),
    Export(SnapshotExportResult),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliCommand {
    ValidateProfile {
        profile_path: PathBuf,
    },
    Tick {
        profile_path: PathBuf,
    },
    PollSource {
        profile_path: PathBuf,
        source_id: String,
    },
    MaterializeTopology {
        profile_path: PathBuf,
        view_path: PathBuf,
    },
    MaterializeSparseGeo {
        profile_path: PathBuf,
        view_path: PathBuf,
    },
    ExportSnapshot {
        profile_path: PathBuf,
        job_path: PathBuf,
        output_dir: PathBuf,
        catalog_path: Option<PathBuf>,
    },
}

impl CliCommand {
    pub fn parse_from<I, S>(args: I) -> Result<Self, OperatorError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let values: Vec<String> = args.into_iter().map(Into::into).collect();
        if values.len() < 2 {
            return Err(OperatorError::Cli("missing subcommand".into()));
        }
        match values[1].as_str() {
            "profile-validate" if values.len() == 3 => Ok(Self::ValidateProfile {
                profile_path: PathBuf::from(&values[2]),
            }),
            "tick" if values.len() == 3 => Ok(Self::Tick {
                profile_path: PathBuf::from(&values[2]),
            }),
            "poll-source" if values.len() == 4 => Ok(Self::PollSource {
                profile_path: PathBuf::from(&values[2]),
                source_id: values[3].clone(),
            }),
            "materialize-topology" if values.len() == 4 => Ok(Self::MaterializeTopology {
                profile_path: PathBuf::from(&values[2]),
                view_path: PathBuf::from(&values[3]),
            }),
            "materialize-sparse-geo" if values.len() == 4 => Ok(Self::MaterializeSparseGeo {
                profile_path: PathBuf::from(&values[2]),
                view_path: PathBuf::from(&values[3]),
            }),
            "export-snapshot" if values.len() == 5 || values.len() == 6 => {
                Ok(Self::ExportSnapshot {
                    profile_path: PathBuf::from(&values[2]),
                    job_path: PathBuf::from(&values[3]),
                    output_dir: PathBuf::from(&values[4]),
                    catalog_path: values.get(5).map(|v| PathBuf::from(v.as_str())),
                })
            }
            other => Err(OperatorError::Cli(format!(
                "unsupported or malformed command `{other}`"
            ))),
        }
    }
}

pub fn run_cli_command(command: CliCommand) -> Result<OperatorResponse, OperatorError> {
    let now = Utc::now();
    match command {
        CliCommand::ValidateProfile { profile_path } => {
            let profile = EngineProfile::load_json_file(profile_path)?;
            let view = ViewJob {
                id: crate::types::ViewJobId::new(),
                kind: crate::view::ViewKind::DataCard,
                entities: Vec::new(),
                metrics: Vec::new(),
                time_range: crate::view::TimeRange::LatestOnly,
                detail_override: None,
                viewport: None,
            };
            Ok(OperatorResponse::Topology(TopologyViewMaterialization {
                view_id: view.id,
                nodes: profile
                    .nodes
                    .iter()
                    .map(|node| crate::materialize::TopologyNodeView {
                        entity_id: node.id,
                        label: node.label.clone(),
                        kind_label: format!("{:?}", node.kind),
                        position: node.position,
                        metrics: Vec::new(),
                    })
                    .collect(),
                edges: Vec::new(),
                boundaries: Vec::new(),
            }))
        }
        CliCommand::Tick { profile_path } => {
            let profile = EngineProfile::load_json_file(profile_path)?;
            let exporter =
                SnapshotExporter::new(std::env::temp_dir().join("skeletrace-cli"), None)?;
            let mut api = OperatorApi::from_profile(&profile, exporter, now)?;
            api.execute(OperatorRequest::Tick { now })
        }
        CliCommand::PollSource {
            profile_path,
            source_id,
        } => {
            let profile = EngineProfile::load_json_file(profile_path)?;
            let exporter =
                SnapshotExporter::new(std::env::temp_dir().join("skeletrace-cli"), None)?;
            let mut api = OperatorApi::from_profile(&profile, exporter, now)?;
            let parsed = uuid::Uuid::parse_str(&source_id)
                .map_err(|err| OperatorError::Cli(err.to_string()))?;
            api.execute(OperatorRequest::PollSource {
                source_id: SourceId::from_uuid(parsed),
                now,
            })
        }
        CliCommand::MaterializeTopology {
            profile_path,
            view_path,
        } => {
            let profile = EngineProfile::load_json_file(profile_path)?;
            let exporter =
                SnapshotExporter::new(std::env::temp_dir().join("skeletrace-cli"), None)?;
            let mut api = OperatorApi::from_profile(&profile, exporter, now)?;
            let view: ViewJob = load_json(view_path)?;
            api.execute(OperatorRequest::MaterializeTopology { view, now })
        }
        CliCommand::MaterializeSparseGeo {
            profile_path,
            view_path,
        } => {
            let profile = EngineProfile::load_json_file(profile_path)?;
            let exporter =
                SnapshotExporter::new(std::env::temp_dir().join("skeletrace-cli"), None)?;
            let mut api = OperatorApi::from_profile(&profile, exporter, now)?;
            let view: ViewJob = load_json(view_path)?;
            api.execute(OperatorRequest::MaterializeSparseGeo { view, now })
        }
        CliCommand::ExportSnapshot {
            profile_path,
            job_path,
            output_dir,
            catalog_path,
        } => {
            let profile = EngineProfile::load_json_file(profile_path)?;
            let exporter = SnapshotExporter::new(output_dir, catalog_path)?;
            let mut api = OperatorApi::from_profile(&profile, exporter, now)?;
            let job: SnapshotExportJob = load_json(job_path)?;
            api.execute(OperatorRequest::ExportSnapshot { job, now })
        }
    }
}

fn load_json<T: for<'de> Deserialize<'de>>(path: PathBuf) -> Result<T, OperatorError> {
    let bytes = fs::read(path).map_err(|err| OperatorError::Io(err.to_string()))?;
    serde_json::from_slice(&bytes).map_err(|err| OperatorError::Serde(err.to_string()))
}

#[allow(dead_code)]
fn _parse_timestamp(value: &str) -> Result<Timestamp, OperatorError> {
    Ok(DateTime::parse_from_rfc3339(value)
        .map_err(|err| OperatorError::Cli(err.to_string()))?
        .with_timezone(&Utc))
}
