use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::event::PacketEvent;
use crate::render::frame_string;
use crate::verify::verify_events;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PacketWorkflowError {
    Io(String),
    Parse(String),
    EmptyInput(String),
}

impl std::fmt::Display for PacketWorkflowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(msg) => write!(f, "packet workflow I/O error: {msg}"),
            Self::Parse(msg) => write!(f, "packet workflow parse error: {msg}"),
            Self::EmptyInput(msg) => write!(f, "packet workflow empty input: {msg}"),
        }
    }
}

impl std::error::Error for PacketWorkflowError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PacketVerificationOptions {
    pub width: usize,
    pub tick_ms: u64,
    pub max_alerts: usize,
    pub include_ascii: bool,
}

impl Default for PacketVerificationOptions {
    fn default() -> Self {
        Self {
            width: 96,
            tick_ms: 200,
            max_alerts: 8,
            include_ascii: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PacketVerificationRequest {
    pub input_path: PathBuf,
    #[serde(default)]
    pub options: PacketVerificationOptions,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PacketRenderSurface {
    AsciiLandscape {
        frame: String,
        width: usize,
        tick_ms: u64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketLaneReport {
    pub lane_label: String,
    pub total_events: u64,
    pub total_bytes: u64,
    pub anomaly_buckets: u64,
    pub max_score: f64,
    pub max_entropy: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketVerificationReport {
    pub input_path: PathBuf,
    pub ticks: usize,
    pub total_events: u64,
    pub total_bytes: u64,
    pub alerts: Vec<String>,
    pub lanes: Vec<PacketLaneReport>,
    pub surfaces: Vec<PacketRenderSurface>,
}

pub fn verify_packet_request(
    request: &PacketVerificationRequest,
) -> Result<PacketVerificationReport, PacketWorkflowError> {
    let events = load_packet_events(&request.input_path)?;
    if events.is_empty() {
        return Err(PacketWorkflowError::EmptyInput(format!(
            "{} produced no packet events",
            request.input_path.display()
        )));
    }

    let report = verify_events(
        events,
        request.options.width,
        request.options.tick_ms,
        request.options.max_alerts,
    );

    let mut surfaces = Vec::new();
    if request.options.include_ascii {
        surfaces.push(PacketRenderSurface::AsciiLandscape {
            frame: frame_string(&report.state, "verify"),
            width: report.state.width,
            tick_ms: report.state.tick_ms,
        });
    }

    Ok(PacketVerificationReport {
        input_path: request.input_path.clone(),
        ticks: report.ticks,
        total_events: report.total_events,
        total_bytes: report.total_bytes,
        alerts: report.alerts,
        lanes: report
            .lanes
            .into_iter()
            .map(|lane| PacketLaneReport {
                lane_label: lane.lane.label().to_string(),
                total_events: lane.total_events,
                total_bytes: lane.total_bytes,
                anomaly_buckets: lane.anomaly_buckets,
                max_score: lane.max_score,
                max_entropy: lane.max_entropy,
            })
            .collect(),
        surfaces,
    })
}

fn load_packet_events(path: &Path) -> Result<Vec<PacketEvent>, PacketWorkflowError> {
    let bytes = fs::read(path).map_err(|err| PacketWorkflowError::Io(err.to_string()))?;
    if bytes.iter().all(u8::is_ascii_whitespace) {
        return Ok(Vec::new());
    }

    let extension = path
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.to_ascii_lowercase());

    match extension.as_deref() {
        Some("jsonl") | Some("ndjson") => parse_jsonl(&bytes),
        Some("json") => parse_json_payload(&bytes),
        Some("csv") => parse_csv_payload(&bytes),
        _ => parse_json_payload(&bytes).or_else(|_| parse_jsonl(&bytes)).or_else(|_| parse_csv_payload(&bytes)),
    }
}

fn parse_json_payload(bytes: &[u8]) -> Result<Vec<PacketEvent>, PacketWorkflowError> {
    if let Ok(events) = serde_json::from_slice::<Vec<PacketEvent>>(bytes) {
        return Ok(events);
    }
    if let Ok(event) = serde_json::from_slice::<PacketEvent>(bytes) {
        return Ok(vec![event]);
    }
    Err(PacketWorkflowError::Parse(
        "input is not a packet-event JSON object or array".into(),
    ))
}

fn parse_jsonl(bytes: &[u8]) -> Result<Vec<PacketEvent>, PacketWorkflowError> {
    let mut events = Vec::new();
    for (idx, line) in String::from_utf8_lossy(bytes).lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let event = serde_json::from_str::<PacketEvent>(trimmed).map_err(|err| {
            PacketWorkflowError::Parse(format!(
                "invalid JSONL packet event on line {}: {}",
                idx + 1,
                err
            ))
        })?;
        events.push(event);
    }
    Ok(events)
}

#[derive(Debug, Deserialize)]
struct CsvPacketEvent {
    ts_ms: Option<u64>,
    len: usize,
    #[serde(default)]
    proto: String,
    #[serde(default)]
    src: Option<String>,
    #[serde(default)]
    dst: Option<String>,
    #[serde(default)]
    sport: Option<u16>,
    #[serde(default)]
    dport: Option<u16>,
    #[serde(default)]
    dir: Option<String>,
}

fn parse_csv_payload(bytes: &[u8]) -> Result<Vec<PacketEvent>, PacketWorkflowError> {
    let mut rdr = csv::ReaderBuilder::new()
        .trim(csv::Trim::All)
        .from_reader(bytes);
    let mut out = Vec::new();
    for row in rdr.deserialize() {
        let row: CsvPacketEvent = row
            .map_err(|err| PacketWorkflowError::Parse(format!("invalid packet CSV row: {err}")))?;
        out.push(PacketEvent {
            ts_ms: row.ts_ms,
            len: row.len,
            proto: row.proto,
            src: row.src,
            dst: row.dst,
            sport: row.sport,
            dport: row.dport,
            dir: row.dir,
        });
    }
    Ok(out)
}
