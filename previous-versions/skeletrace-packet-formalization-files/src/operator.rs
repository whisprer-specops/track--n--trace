//! First operator-facing API and thin CLI command layer.

use std::fs;
use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::engine::{EngineError, SkeletraceEngine, TickReport};
use crate::export::{ExportError, SnapshotExportJob, SnapshotExportResult, SnapshotExporter};
use crate::governance::{AuditRecord, FailureRecord, SourceCapabilityProfile, SourcePolicy};
use crate::materialize::{SparseGeoFeatureCollection, TopologyViewMaterialization};
use crate::packet_workflow::{
    verify_packet_request, PacketVerificationReport, PacketWorkflowError,
    PacketVerificationRequest,
};
use crate::metric::{MetricRetentionReport, RetentionTuning};
use crate::observability::EngineEvent;
use crate::profile::{EngineProfile, ProfileError};
use crate::profiling::{DurationStats, EngineHealthReport, PerfProbeConfig, PerfProbeReport};
use crate::query::{QueryFilter, QueryResult, Watchlist, WatchlistEvaluation};
use crate::types::{EntityId, MetricId, SourceId, Timestamp, ValidationError};
use crate::view::{DataCard, ViewJob};
use crate::warm_store::WarmStoreMaintenanceReport;
use crate::workload::{
    ReplayBenchmarkReport, ReplayBenchmarkRequest, ReplayWorkloadRequest, WorkloadFixture,
    WorkloadRunReport,
};

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

impl From<PacketWorkflowError> for OperatorError {
    fn from(value: PacketWorkflowError) -> Self {
        Self::Cli(value.to_string())
    }
}

pub struct OperatorApi {
    engine: SkeletraceEngine,
    exporter: SnapshotExporter,
    base_profile: Option<EngineProfile>,
}

impl std::fmt::Debug for OperatorApi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OperatorApi")
            .field("exporter", &self.exporter)
            .field("engine_stats", &self.engine.stats())
            .field("has_base_profile", &self.base_profile.is_some())
            .finish()
    }
}

impl OperatorApi {
    pub fn new(engine: SkeletraceEngine, exporter: SnapshotExporter) -> Self {
        Self {
            engine,
            exporter,
            base_profile: None,
        }
    }

    pub fn from_profile(
        profile: &EngineProfile,
        exporter: SnapshotExporter,
        now: Timestamp,
    ) -> Result<Self, OperatorError> {
        Ok(Self {
            engine: profile.instantiate(now)?,
            exporter,
            base_profile: Some(profile.clone()),
        })
    }

    #[must_use]
    pub fn engine(&self) -> &SkeletraceEngine {
        &self.engine
    }

    #[must_use]
    pub fn engine_mut(&mut self) -> &mut SkeletraceEngine {
        &mut self.engine
    }

    fn benchmark_replay_workload(
        &self,
        fixture: &WorkloadFixture,
        request: &ReplayBenchmarkRequest,
        now: Timestamp,
    ) -> Result<ReplayBenchmarkReport, OperatorError> {
        fixture.validate()?;
        request.validate()?;
        let profile = self.base_profile.as_ref().ok_or_else(|| {
            OperatorError::Cli("benchmarking requires an operator created from a profile".into())
        })?;

        let started_at = now;
        let mut stats = DurationStats::default();
        let mut total_checkpoints = 0usize;
        let mut total_samples_seen = 0usize;
        let mut total_samples_stored = 0usize;
        let mut last_run = None;

        for _ in 0..request.iterations {
            let mut benchmark_profile = profile.clone();
            benchmark_profile.config.journal_dir = None;
            benchmark_profile.config.warm_store_path = None;
            let mut engine = benchmark_profile.instantiate(now)?;
            let mut harness = fixture.into_harness();
            let started = std::time::Instant::now();
            let report = engine.run_replay_workload(&mut harness, &request.workload)?;
            stats.record(started.elapsed());
            total_checkpoints += report.checkpoints.len();
            total_samples_seen += report
                .checkpoints
                .iter()
                .map(|checkpoint| checkpoint.replay.samples_seen)
                .sum::<usize>();
            total_samples_stored += report
                .checkpoints
                .iter()
                .map(|checkpoint| checkpoint.replay.samples_stored)
                .sum::<usize>();
            last_run = Some(report);
        }

        Ok(ReplayBenchmarkReport {
            label: request.label.clone(),
            iterations: request.iterations,
            started_at,
            finished_at: chrono::Utc::now(),
            stats,
            source_summaries: fixture.source_summaries(),
            total_checkpoints,
            total_samples_seen,
            total_samples_stored,
            last_run,
        })
    }

    pub fn execute(&mut self, request: OperatorRequest) -> Result<OperatorResponse, OperatorError> {
        Ok(match request {
            OperatorRequest::VerifyPackets { request } => {
                OperatorResponse::PacketVerification(verify_packet_request(&request)?)
            }
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
                let result = self.exporter.export(&self.engine, &job, now)?;
                self.engine.record_export_audit(&result, &job, now);
                OperatorResponse::Export(result)
            }
            OperatorRequest::QueryLatest { filter, now } => {
                OperatorResponse::Query(self.engine.query_latest(&filter, now)?)
            }
            OperatorRequest::EvaluateWatchlist { watchlist, now } => {
                OperatorResponse::Watchlist(self.engine.evaluate_watchlist(&watchlist, now)?)
            }
            OperatorRequest::HealthReport { now } => {
                OperatorResponse::HealthReport(self.engine.health_report(now))
            }
            OperatorRequest::RecentEvents { limit } => {
                OperatorResponse::Events(self.engine.recent_events(limit))
            }
            OperatorRequest::TuneMetricRetention {
                metric_id,
                tuning,
                now,
            } => OperatorResponse::RetentionReport(
                self.engine
                    .retune_metric_retention(metric_id, tuning, now)?,
            ),
            OperatorRequest::ProfileView { view, now, config } => OperatorResponse::Perf(
                self.engine
                    .profile_view_materialization(&view, now, config)?,
            ),
            OperatorRequest::RecentAudit { limit } => {
                OperatorResponse::Audit(self.engine.recent_audit_records(limit))
            }
            OperatorRequest::RecentFailures { limit } => {
                OperatorResponse::Failures(self.engine.recent_failures(limit))
            }
            OperatorRequest::SetSourcePolicy { policy } => {
                self.engine.set_source_policy(policy);
                OperatorResponse::SourcePolicy(policy)
            }
            OperatorRequest::SetSourceCapability {
                source_id,
                capability,
            } => {
                self.engine.set_source_capability(source_id, capability)?;
                OperatorResponse::SourceCapability(capability)
            }
            OperatorRequest::WarmStoreReport => {
                OperatorResponse::WarmStoreReport(self.engine.warm_store_maintenance_report()?)
            }
            OperatorRequest::OptimizeWarmStore { vacuum } => {
                OperatorResponse::WarmStoreReport(self.engine.optimize_warm_store(vacuum)?)
            }
            OperatorRequest::RunReplayWorkload { fixture, request } => {
                fixture.validate()?;
                let mut harness = fixture.into_harness();
                OperatorResponse::Workload(self.engine.run_replay_workload(&mut harness, &request)?)
            }
            OperatorRequest::BenchmarkReplayWorkload {
                fixture,
                request,
                now,
            } => OperatorResponse::ReplayBenchmark(
                self.benchmark_replay_workload(&fixture, &request, now)?,
            ),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OperatorRequest {
    VerifyPackets {
        request: PacketVerificationRequest,
    },
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
    QueryLatest {
        filter: QueryFilter,
        now: Timestamp,
    },
    EvaluateWatchlist {
        watchlist: Watchlist,
        now: Timestamp,
    },
    HealthReport {
        now: Timestamp,
    },
    RecentEvents {
        limit: usize,
    },
    TuneMetricRetention {
        metric_id: MetricId,
        tuning: RetentionTuning,
        now: Timestamp,
    },
    ProfileView {
        view: ViewJob,
        now: Timestamp,
        config: PerfProbeConfig,
    },
    RecentAudit {
        limit: usize,
    },
    RecentFailures {
        limit: usize,
    },
    SetSourcePolicy {
        policy: SourcePolicy,
    },
    SetSourceCapability {
        source_id: SourceId,
        capability: SourceCapabilityProfile,
    },
    WarmStoreReport,
    OptimizeWarmStore {
        vacuum: bool,
    },
    RunReplayWorkload {
        fixture: WorkloadFixture,
        request: ReplayWorkloadRequest,
    },
    BenchmarkReplayWorkload {
        fixture: WorkloadFixture,
        request: ReplayBenchmarkRequest,
        now: Timestamp,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OperatorResponse {
    PacketVerification(PacketVerificationReport),
    Tick(TickReport),
    Topology(TopologyViewMaterialization),
    SparseGeo(SparseGeoFeatureCollection),
    DataCard(DataCard),
    Export(SnapshotExportResult),
    Query(QueryResult),
    Watchlist(WatchlistEvaluation),
    HealthReport(EngineHealthReport),
    Events(Vec<EngineEvent>),
    RetentionReport(MetricRetentionReport),
    Perf(PerfProbeReport),
    Audit(Vec<AuditRecord>),
    Failures(Vec<FailureRecord>),
    SourcePolicy(SourcePolicy),
    SourceCapability(SourceCapabilityProfile),
    WarmStoreReport(Option<WarmStoreMaintenanceReport>),
    Workload(WorkloadRunReport),
    ReplayBenchmark(ReplayBenchmarkReport),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliCommand {
    VerifyPackets {
        request_path: PathBuf,
    },
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
    QueryLatest {
        profile_path: PathBuf,
        filter_path: PathBuf,
    },
    EvaluateWatchlist {
        profile_path: PathBuf,
        watchlist_path: PathBuf,
    },
    Health {
        profile_path: PathBuf,
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
            "verify-packets" if values.len() == 3 => Ok(Self::VerifyPackets {
                request_path: PathBuf::from(&values[2]),
            }),
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
            "query-latest" if values.len() == 4 => Ok(Self::QueryLatest {
                profile_path: PathBuf::from(&values[2]),
                filter_path: PathBuf::from(&values[3]),
            }),
            "evaluate-watchlist" if values.len() == 4 => Ok(Self::EvaluateWatchlist {
                profile_path: PathBuf::from(&values[2]),
                watchlist_path: PathBuf::from(&values[3]),
            }),
            "health" if values.len() == 3 => Ok(Self::Health {
                profile_path: PathBuf::from(&values[2]),
            }),
            other => Err(OperatorError::Cli(format!(
                "unsupported or malformed command `{other}`"
            ))),
        }
    }
}

pub fn run_cli_command(command: CliCommand) -> Result<OperatorResponse, OperatorError> {
    let now = Utc::now();
    match command {
        CliCommand::VerifyPackets { request_path } => {
            let request: PacketVerificationRequest = load_json(request_path)?;
            Ok(OperatorResponse::PacketVerification(verify_packet_request(&request)?))
        }
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
        CliCommand::QueryLatest {
            profile_path,
            filter_path,
        } => {
            let profile = EngineProfile::load_json_file(profile_path)?;
            let exporter =
                SnapshotExporter::new(std::env::temp_dir().join("skeletrace-cli"), None)?;
            let mut api = OperatorApi::from_profile(&profile, exporter, now)?;
            let filter: QueryFilter = load_json(filter_path)?;
            api.execute(OperatorRequest::QueryLatest { filter, now })
        }
        CliCommand::EvaluateWatchlist {
            profile_path,
            watchlist_path,
        } => {
            let profile = EngineProfile::load_json_file(profile_path)?;
            let exporter =
                SnapshotExporter::new(std::env::temp_dir().join("skeletrace-cli"), None)?;
            let mut api = OperatorApi::from_profile(&profile, exporter, now)?;
            let watchlist: Watchlist = load_json(watchlist_path)?;
            api.execute(OperatorRequest::EvaluateWatchlist { watchlist, now })
        }
        CliCommand::Health { profile_path } => {
            let profile = EngineProfile::load_json_file(profile_path)?;
            let exporter =
                SnapshotExporter::new(std::env::temp_dir().join("skeletrace-cli"), None)?;
            let mut api = OperatorApi::from_profile(&profile, exporter, now)?;
            api.execute(OperatorRequest::HealthReport { now })
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
