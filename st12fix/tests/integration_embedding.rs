use skeletrace::{analyze_packets, render_packet_landscape_frame, verify_packet_events, PacketEvent, PacketLandscapeOptions, PacketLane, PacketVerificationRequest};

fn event(
    ts_ms: u64,
    len: usize,
    proto: &str,
    sport: Option<u16>,
    dport: Option<u16>,
) -> PacketEvent {
    PacketEvent {
        ts_ms: Some(ts_ms),
        len,
        proto: proto.to_string(),
        src: Some("10.0.0.2".to_string()),
        dst: Some("93.184.216.34".to_string()),
        sport,
        dport,
        dir: Some("out".to_string()),
    }
}

#[test]
fn lane_classification_prefers_dns_and_web_ports() {
    let dns = event(0, 96, "udp", Some(54000), Some(53));
    let web = event(0, 512, "tcp", Some(51000), Some(443));
    assert_eq!(dns.lane(), PacketLane::Dns);
    assert_eq!(web.lane(), PacketLane::Web);
}

#[test]
fn verify_groups_events_into_ticks_and_preserves_renderability() {
    let report = verify_packet_events(
        vec![
            event(0, 96, "udp", Some(54000), Some(53)),
            event(50, 512, "tcp", Some(51000), Some(443)),
            event(250, 256, "tcp", Some(51001), Some(80)),
        ],
        16,
        100,
        8,
    );

    assert_eq!(report.ticks, 2);
    assert_eq!(report.total_events, 3);
    assert_eq!(report.total_bytes, 864);

    let dns = report
        .lanes
        .iter()
        .find(|lane| lane.lane == PacketLane::Dns)
        .unwrap();
    let web = report
        .lanes
        .iter()
        .find(|lane| lane.lane == PacketLane::Web)
        .unwrap();
    assert_eq!(dns.total_events, 1);
    assert_eq!(web.total_events, 2);

    let frame = render_packet_landscape_frame(&report.state, "verify");
    assert!(frame.contains("WEB"));
    assert!(frame.contains("DNS"));
    assert!(frame.contains("mode=verify"));
}

#[test]
fn verify_flags_a_clear_spike_without_needing_terminal_mode() {
    let mut events = Vec::new();
    for i in 0..6u64 {
        events.push(event(i * 100, 64, "tcp", Some(50000), Some(443)));
    }
    for _ in 0..20 {
        events.push(event(700, 64, "tcp", Some(50000), Some(443)));
    }

    let report = verify_packet_events(events, 24, 100, 8);
    let web = report
        .lanes
        .iter()
        .find(|lane| lane.lane == PacketLane::Web)
        .unwrap();
    assert!(web.anomaly_buckets >= 1);
    assert!(!report.alerts.is_empty());
}


#[test]
fn analyze_packets_returns_optional_ascii_frame() {
    let request = PacketVerificationRequest {
        events: vec![
            event(0, 96, "udp", Some(54000), Some(53)),
            event(100, 512, "tcp", Some(51000), Some(443)),
        ],
        options: PacketLandscapeOptions {
            width: 24,
            tick_ms: 100,
            max_alerts: 8,
            mode_label: "operator".into(),
            render_frame: true,
        },
    };

    let response = analyze_packets(request).unwrap();
    assert_eq!(response.summary.total_events, 2);
    assert_eq!(response.summary.tick_ms, 100);
    assert!(response.ascii_frame.as_ref().is_some_and(|frame| frame.contains("mode=operator")));
}
