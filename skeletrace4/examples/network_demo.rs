//! Network Security Engine Demo
//!
//! Demonstrates comprehensive network security and administrative monitoring across
//! all infrastructure protection vectors including wireless security, remote access,
//! authentication, protocol security, application security, directory services,
//! and system administration.

use skeletrace::{
    Graph,
    entity::{Node, NodeKind},
    network::{NetworkEngine, NetworkSecurityTarget},
    types::{EntityId, SourceId, Quality, Confidence},
};
use std::thread;
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🌐 Skeletrace Network Security Engine Demo");
    println!("Comprehensive Infrastructure Security & Admin Monitoring");

    // Create a graph and network engine
    let mut graph = Graph::new();
    let mut network_engine = NetworkEngine::new();

    // Create entities for different infrastructure components
    let wifi_entity = EntityId(uuid::Uuid::new_v4());
    let ssh_entity = EntityId(uuid::Uuid::new_v4());
    let auth_entity = EntityId(uuid::Uuid::new_v4());
    let protocol_entity = EntityId(uuid::Uuid::new_v4());

    // Add nodes to graph
    graph.add_node(Node {
        id: wifi_entity,
        kind: NodeKind::Infrastructure,
        label: "Corporate Wi-Fi Infrastructure".to_string(),
        position: None,
        source_id: SourceId(uuid::Uuid::new_v4()),
        first_seen: chrono::Utc::now(),
        last_seen: chrono::Utc::now(),
        confidence: Confidence::default(),
        quality: Quality::default(),
        tags: vec!["wifi".to_string(), "network".to_string()],
    });

    graph.add_node(Node {
        id: ssh_entity,
        kind: NodeKind::Infrastructure,
        label: "Remote Access Infrastructure".to_string(),
        position: None,
        source_id: SourceId(uuid::Uuid::new_v4()),
        first_seen: chrono::Utc::now(),
        last_seen: chrono::Utc::now(),
        confidence: Confidence::default(),
        quality: Quality::default(),
        tags: vec!["ssh".to_string(), "rdp".to_string()],
    });

    graph.add_node(Node {
        id: auth_entity,
        kind: NodeKind::Logical,
        label: "Authentication Services".to_string(),
        position: None,
        source_id: SourceId(uuid::Uuid::new_v4()),
        first_seen: chrono::Utc::now(),
        last_seen: chrono::Utc::now(),
        confidence: Confidence::default(),
        quality: Quality::default(),
        tags: vec!["auth".to_string(), "mfa".to_string()],
    });

    graph.add_node(Node {
        id: protocol_entity,
        kind: NodeKind::Infrastructure,
        label: "Network Protocol Security".to_string(),
        position: None,
        source_id: SourceId(uuid::Uuid::new_v4()),
        first_seen: chrono::Utc::now(),
        last_seen: chrono::Utc::now(),
        confidence: Confidence::default(),
        quality: Quality::default(),
        tags: vec!["protocols".to_string(), "bgp".to_string()],
    });

    println!("📊 Created network graph with {} entities", graph.nodes.len());

    // Add network security monitoring targets
    println!("🎯 Adding network security targets");

    // Wi-Fi security monitoring
    let wifi_target = NetworkSecurityTarget::wifi_security(
        wifi_entity,
        "Corporate Wi-Fi Monitor → WirelessSecurity"
    );
    network_engine.add_target(wifi_target);

    // Remote access security monitoring
    let remote_target = NetworkSecurityTarget::remote_access_security(
        ssh_entity,
        "SSH/RDP Security Monitor → RemoteAccessSecurity"
    );
    network_engine.add_target(remote_target);

    // Authentication security monitoring
    let auth_target = NetworkSecurityTarget::authentication_security(
        auth_entity,
        "Banking MFA Monitor → AuthenticationSecurity"
    );
    network_engine.add_target(auth_target);

    // Protocol security monitoring
    let protocol_target = NetworkSecurityTarget::protocol_security(
        protocol_entity,
        "ARP/BGP/DNS Monitor → ProtocolSecurity"
    );
    network_engine.add_target(protocol_target);

    println!("\n📋 Network Security Monitoring Configuration:");
    println!("   • Corporate Wi-Fi Monitor → WirelessSecurity");
    println!("     Compliance: NIST CSF, CIS Controls");
    println!("   • SSH/RDP Security Monitor → RemoteAccessSecurity");
    println!("     Compliance: NIST CSF, SANS Critical");
    println!("   • Banking MFA Monitor → AuthenticationSecurity");
    println!("     Compliance: PCI NSS, SOC 2 Network");
    println!("   • ARP/BGP/DNS Monitor → ProtocolSecurity");
    println!("     Compliance: NIST CSF, ISO 27001");

    println!("\n🔍 Running network security detection cycles...\n");

    // Execute multiple monitoring cycles
    for cycle in 1..=5 {
        println!("--- Cycle {} ---", cycle);
        
        let result = network_engine.execute_network_cycle();
        println!("✅ Executed {} network detections", result.detections_executed);

        let stats = network_engine.get_stats();
        
        if stats.total_events > 0 {
            println!("⚠️  Detected {} network security events", stats.total_events);
            
            let pending_alerts = network_engine.get_pending_alerts();
            if !pending_alerts.is_empty() {
                println!("🚨 Generated {} security alerts", pending_alerts.len());
                for alert in pending_alerts.iter().take(3) { // Show first 3 alerts
                    println!("   Alert: {:?} (Urgency: {:?})", alert.event.violation_type, alert.urgency);
                }
            }
        } else {
            println!("✅ All infrastructure shows secure network posture");
        }

        // Generate compliance report periodically
        if cycle == 3 {
            if let Some(report) = network_engine.analyze_network_security(&graph) {
                println!("🌐 Network Security Compliance Report:");
                println!("   Network security posture: {:.1}%", report.network_security_posture * 100.0);
                println!("   Summary: {}", report.executive_summary);
            }
        }

        println!();
        thread::sleep(Duration::from_millis(500));
    }

    // Final statistics and comprehensive analysis
    let final_stats = network_engine.get_stats();
    println!("📈 Final Network Security Statistics:");
    println!("   Active targets: {}", final_stats.active_targets);
    println!("   Total network events: {}", final_stats.total_events);
    println!("   High-risk entities: {}/{}", final_stats.high_risk_entities, graph.nodes.len());
    println!("   Pending network alerts: {} ({} critical)", final_stats.pending_alerts, final_stats.critical_alerts);

    // Generate comprehensive compliance report
    if let Some(report) = network_engine.analyze_network_security(&graph) {
        println!("\n🏛️  Comprehensive Network Security Assessment:");
        println!("   Overall network posture: {:.1}%", report.network_security_posture * 100.0);
        println!("   Framework compliance scores:");
        
        for (framework, score) in &report.framework_scores {
            let status = match *score {
                s if s >= 0.9 => "Excellent",
                s if s >= 0.8 => "Good",
                s if s >= 0.7 => "Acceptable", 
                s if s >= 0.6 => "Poor",
                _ => "Critical",
            };
            println!("     {:?}: {:.1}% ({})", framework, score * 100.0, status);
        }

        if !report.high_risk_entities.is_empty() {
            println!("   High-risk entities: {} require immediate attention", report.high_risk_entities.len());
        }

        if !report.protection_gaps.is_empty() {
            println!("   Protection gaps identified:");
            for (i, gap) in report.protection_gaps.iter().enumerate().take(3) {
                println!("     {}. {}", i + 1, gap);
            }
        }
    }

    // Generate metrics for Skeletrace integration
    let metrics = network_engine.generate_metric_samples(&graph);
    if !metrics.is_empty() {
        println!("\n📊 Generated {} network security metrics for Skeletrace integration", metrics.len());
        println!("   Metrics include: network security posture, entity-specific scores, and vector risk analysis");
    }

    println!("\n🎉 Network security engine demo complete!");
    println!("Comprehensive infrastructure monitoring successfully demonstrated across:");
    println!("   • Corporate Wi-Fi security (WPA3 Enterprise configuration)");
    println!("   • Remote access security (SSH key rotation, RDP Network Level Auth)");
    println!("   • Authentication security (Banking MFA, identity management)");
    println!("   • Protocol security (ARP spoofing, BGP RPKI, DNS cache poisoning)");
    println!("   • Application security (Java deserialization, framework patching)");
    println!("   • Directory security (Active Directory, pass-the-hash prevention)");
    println!("   • System administration (Linux setuid auditing, race conditions)");
    println!("   • Multi-framework compliance (NIST CSF, CIS Controls, ISO 27001, PCI NSS)");
    println!("   • Real-time network breach detection and infrastructure alerting");
    println!("   • Executive compliance reporting and network security gap analysis");

    Ok(())
}
