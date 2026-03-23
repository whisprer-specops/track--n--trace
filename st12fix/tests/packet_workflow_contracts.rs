use std::fs;

use skeletrace::{run_cli_command, CliCommand, OperatorResponse};
use skeletrace::packet_workflow::{
    PacketRenderSurface, PacketVerificationOptions, PacketVerificationRequest,
};

fn temp_path(name: &str) -> std::path::PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "skeletrace-packet-workflow-{}-{}",
        std::process::id(),
        name
    ));
    path
}

#[test]
fn verify_packets_cli_returns_report_and_ascii_surface() {
    let input_path = temp_path("events.jsonl");
    let request_path = temp_path("request.json");

    fs::write(
        &input_path,
        concat!(
            r#"{"ts_ms":0,"len":60,"proto":"dns","sport":53000,"dport":53}"#,
            "\n",
            r#"{"ts_ms":220,"len":1500,"proto":"tcp","sport":443,"dport":55123}"#,
            "\n",
            r#"{"ts_ms":440,"len":1400,"proto":"tcp","sport":443,"dport":55123}"#,
            "\n"
        ),
    )
    .unwrap();

    let request = PacketVerificationRequest {
        input_path: input_path.clone(),
        options: PacketVerificationOptions {
            width: 24,
            tick_ms: 200,
            max_alerts: 4,
            include_ascii: true,
        },
    };
    fs::write(&request_path, serde_json::to_vec_pretty(&request).unwrap()).unwrap();

    let response = run_cli_command(CliCommand::VerifyPackets {
        request_path: request_path.clone(),
    })
    .unwrap();

    match response {
        OperatorResponse::PacketVerification(report) => {
            assert_eq!(report.total_events, 3);
            assert!(report
                .lanes
                .iter()
                .any(|lane| lane.lane_label == "DNS" && lane.total_events == 1));
            assert!(report
                .lanes
                .iter()
                .any(|lane| lane.lane_label == "WEB" && lane.total_events == 2));
            assert_eq!(report.surfaces.len(), 1);

            match &report.surfaces[0] {
                PacketRenderSurface::AsciiLandscape { frame, width, tick_ms } => {
                    assert_eq!(*width, 24);
                    assert_eq!(*tick_ms, 200);
                    assert!(!frame.trim().is_empty());
                    assert!(frame.lines().count() >= 2);
                    assert!(frame.chars().any(|c| !c.is_whitespace()));
                }
            }
        }
        other => panic!("unexpected response: {other:?}"),
    }

    let _ = fs::remove_file(input_path);
    let _ = fs::remove_file(request_path);
}

#[test]
fn verify_packets_can_skip_ascii_surface() {
    let input_path = temp_path("events.json");
    let request_path = temp_path("request-no-ascii.json");

    fs::write(
        &input_path,
        serde_json::to_vec(&vec![
            serde_json::json!({
                "ts_ms": 0,
                "len": 128,
                "proto": "https",
                "sport": 443,
                "dport": 50000
            }),
            serde_json::json!({
                "ts_ms": 250,
                "len": 64,
                "proto": "dns",
                "sport": 53001,
                "dport": 53
            }),
        ])
        .unwrap(),
    )
    .unwrap();

    let request = PacketVerificationRequest {
        input_path: input_path.clone(),
        options: PacketVerificationOptions {
            width: 16,
            tick_ms: 100,
            max_alerts: 2,
            include_ascii: false,
        },
    };
    fs::write(&request_path, serde_json::to_vec_pretty(&request).unwrap()).unwrap();

    let response = run_cli_command(CliCommand::VerifyPackets {
        request_path: request_path.clone(),
    })
    .unwrap();

    match response {
        OperatorResponse::PacketVerification(report) => {
            assert_eq!(report.total_events, 2);
            assert!(report.surfaces.is_empty());
        }
        other => panic!("unexpected response: {other:?}"),
    }

    let _ = fs::remove_file(input_path);
    let _ = fs::remove_file(request_path);
}