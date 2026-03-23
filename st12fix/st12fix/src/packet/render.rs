use crate::packet::model::AppState;

#[must_use]
pub fn frame_string(state: &AppState, mode_label: &str) -> String {
    let bytes_per_sec = if state.uptime_secs() > 0 {
        state.total_bytes / state.uptime_secs()
    } else {
        0
    };
    let events_per_sec = if state.uptime_secs() > 0 {
        state.total_events / state.uptime_secs()
    } else {
        0
    };

    let mut out = String::new();
    out.push_str("[2J[H");
    out.push_str(&format!(
        "Packet Flow Landscape  |  mode={}  |  tick={}ms
",
        mode_label, state.tick_ms
    ));
    out.push_str(&format!(
        "events={}  bytes={}  approx_eps={}  approx_Bps={}  uptime={}s
",
        state.total_events,
        state.total_bytes,
        events_per_sec,
        bytes_per_sec,
        state.uptime_secs()
    ));
    out.push_str(
        "Each cell is one time bucket. Glyph intensity blends load and packet-size entropy. ! = anomalous bucket.

",
    );

    for (i, lane) in state.lanes.iter().enumerate() {
        let row = &state.history[i];
        let mut line = String::with_capacity(row.len());
        for cell in row {
            line.push(cell.glyph());
        }
        let tail = state
            .current_cell(i)
            .map(|c| {
                format!(
                    " count={:<4} bytes={:<6} H={:.2}",
                    c.count, c.bytes, c.entropy
                )
            })
            .unwrap_or_default();
        out.push_str(&format!("{:<6} {}{}
", lane.label(), line, tail));
    }

    out.push_str(
        "
Legend: ' ' quiet  .,:; medium  o x % # @ heavy/structured  ! anomaly

",
    );
    out.push_str("Recent alerts:
");
    if state.alerts.is_empty() {
        out.push_str("  (none yet)
");
    } else {
        for line in state.alerts.iter().take(state.max_alerts) {
            out.push_str(&format!("  - {}
", line));
        }
    }

    out
}
