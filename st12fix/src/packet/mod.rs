use serde::{Deserialize, Serialize};

use crate::types::ValidationError;

pub mod event;
pub mod model;
pub mod render;
pub mod stats;
pub mod verify;

pub use event::{Lane as PacketLane, PacketEvent};
pub use model::AppState as PacketLandscapeState;
pub use render::frame_string as render_packet_landscape_frame;
pub use verify::{verify_events as verify_packet_events, LaneSummary as PacketLaneSummary, VerificationReport as PacketVerificationReport};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PacketLandscapeOptions {
    pub width: usize,
    pub tick_ms: u64,
    pub max_alerts: usize,
    pub mode_label: String,
    pub render_frame: bool,
}

impl Default for PacketLandscapeOptions {
    fn default() -> Self {
        Self {
            width: 96,
            tick_ms: 250,
            max_alerts: 16,
            mode_label: "packet-verify".into(),
            render_frame: true,
        }
    }
}

impl PacketLandscapeOptions {
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.width == 0 {
            return Err(ValidationError::ZeroCapacity("packet.width".into()));
        }
        if self.tick_ms == 0 {
            return Err(ValidationError::ZeroCapacity("packet.tick_ms".into()));
        }
        if self.max_alerts == 0 {
            return Err(ValidationError::ZeroCapacity("packet.max_alerts".into()));
        }
        if self.mode_label.trim().is_empty() {
            return Err(ValidationError::EmptyField("packet.mode_label".into()));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PacketVerificationRequest {
    pub events: Vec<PacketEvent>,
    pub options: PacketLandscapeOptions,
}

impl PacketVerificationRequest {
    pub fn validate(&self) -> Result<(), ValidationError> {
        self.options.validate()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PacketVerificationSummary {
    pub ticks: usize,
    pub total_events: u64,
    pub total_bytes: u64,
    pub alerts: Vec<String>,
    pub lanes: Vec<PacketLaneSummaryRecord>,
    pub width: usize,
    pub tick_ms: u64,
    pub mode_label: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PacketLaneSummaryRecord {
    pub lane: PacketLane,
    pub lane_label: String,
    pub total_events: u64,
    pub total_bytes: u64,
    pub anomaly_buckets: u64,
    pub max_score: f64,
    pub max_entropy: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PacketVerificationResponse {
    pub summary: PacketVerificationSummary,
    pub ascii_frame: Option<String>,
}

pub fn analyze_packets(
    request: PacketVerificationRequest,
) -> Result<PacketVerificationResponse, ValidationError> {
    request.validate()?;
    let report = verify::verify_events(
        request.events,
        request.options.width,
        request.options.tick_ms,
        request.options.max_alerts,
    );

    let summary = PacketVerificationSummary {
        ticks: report.ticks,
        total_events: report.total_events,
        total_bytes: report.total_bytes,
        alerts: report.alerts.clone(),
        lanes: report
            .lanes
            .iter()
            .map(|lane| PacketLaneSummaryRecord {
                lane: lane.lane,
                lane_label: lane.lane.label().to_string(),
                total_events: lane.total_events,
                total_bytes: lane.total_bytes,
                anomaly_buckets: lane.anomaly_buckets,
                max_score: lane.max_score,
                max_entropy: lane.max_entropy,
            })
            .collect(),
        width: request.options.width,
        tick_ms: request.options.tick_ms,
        mode_label: request.options.mode_label.clone(),
    };

    let ascii_frame = request
        .options
        .render_frame
        .then(|| render::frame_string(&report.state, &request.options.mode_label));

    Ok(PacketVerificationResponse {
        summary,
        ascii_frame,
    })
}
