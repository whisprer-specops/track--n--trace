use crate::event::{Lane, PacketEvent};
use crate::model::AppState;

#[derive(Debug, Clone)]
pub struct LaneSummary {
    pub lane: Lane,
    pub total_events: u64,
    pub total_bytes: u64,
    pub anomaly_buckets: u64,
    pub max_score: f64,
    pub max_entropy: f64,
}

#[derive(Debug)]
pub struct VerificationReport {
    pub ticks: usize,
    pub total_events: u64,
    pub total_bytes: u64,
    pub alerts: Vec<String>,
    pub lanes: Vec<LaneSummary>,
    pub state: AppState,
}

pub fn verify_events<I>(
    events: I,
    width: usize,
    tick_ms: u64,
    max_alerts: usize,
) -> VerificationReport
where
    I: IntoIterator<Item = PacketEvent>,
{
    let tick_ms = tick_ms.max(1);
    let mut state = AppState::new(width, tick_ms, max_alerts);
    let mut lanes = state
        .lanes
        .iter()
        .copied()
        .map(|lane| LaneSummary {
            lane,
            total_events: 0,
            total_bytes: 0,
            anomaly_buckets: 0,
            max_score: 0.0,
            max_entropy: 0.0,
        })
        .collect::<Vec<_>>();

    let mut ticks = 0usize;
    let mut current_bucket: Option<u64> = None;

    for ev in events {
        if let Some(ts_ms) = ev.ts_ms {
            let bucket = ts_ms / tick_ms;
            match current_bucket {
                Some(cur) if bucket != cur => {
                    if state.last_tick_count > 0 {
                        state.finalize_tick();
                        ticks += 1;
                    }
                    current_bucket = Some(bucket);
                }
                None => current_bucket = Some(bucket),
                _ => {}
            }
        }

        let lane = ev.lane();
        let idx = state.lane_index(lane);
        lanes[idx].total_events += 1;
        lanes[idx].total_bytes += ev.len as u64;
        state.ingest(ev);
    }

    if state.last_tick_count > 0 {
        state.finalize_tick();
        ticks += 1;
    }

    for (idx, row) in state.history.iter().enumerate() {
        lanes[idx].anomaly_buckets = row.iter().filter(|cell| cell.anomaly).count() as u64;
        lanes[idx].max_score = row.iter().map(|cell| cell.score).fold(0.0, f64::max);
        lanes[idx].max_entropy = row.iter().map(|cell| cell.entropy).fold(0.0, f64::max);
    }

    let alerts = state.alerts.iter().cloned().collect::<Vec<_>>();

    VerificationReport {
        ticks,
        total_events: state.total_events,
        total_bytes: state.total_bytes,
        alerts,
        lanes,
        state,
    }
}
