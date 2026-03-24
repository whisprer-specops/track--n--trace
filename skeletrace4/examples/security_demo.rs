//! Security engine demonstration showing multi-vector threat detection.

use std::thread;
use std::time::Duration;

use skeletrace::entity::{Node, NodeKind};
use skeletrace::security::{SecurityEngine, SecurityTarget, MonitoringType};
use skeletrace::spatial::GeoCoord;
use skeletrace::types::{Confidence, EntityId, Quality, SourceId};
use skeletrace::{Graph};

fn main() {
    // Initialize logging
    env_logger::init();
    
    println!("🛡️  Skeletrace Security Engine Demo");
    println!("Multi-Vector Threat Detection and Risk Assessment");
    
    // Create a graph and add some security-monitored entities
    let mut graph = Graph::new();
    
    // Create entities representing different security monitoring points
    let email_gateway = EntityId(uuid::Uuid::new_v4());
    let web_proxy = EntityId(uuid::Uuid::new_v4());
    let file_server = EntityId(uuid::Uuid::new_v4());
    let helpdesk = EntityId(uuid::Uuid::new_v4());
    
    let email_node = Node {
        id: email_gateway,
        kind: NodeKind::Infrastructure,
        label: "Corporate Email Gateway".to_string(),
        position: Some(GeoCoord::new(51.5074, -0.1278)), // London coordinates
        source_id: SourceId(uuid::Uuid::new_v4()),
        first_seen: chrono::Utc::now(),
        last_seen: chrono::Utc::now(),
        confidence: Confidence::new(0.95),
        quality: Quality::new(1.0),
        tags: vec!["email".to_string(), "gateway".to_string(), "security".to_string()],
    };
    
    let web_node = Node {
        id: web_proxy,
        kind: NodeKind::Infrastructure,
        label: "Internet Proxy".to_string(),
        position: Some(GeoCoord::new(40.7128, -74.0060)), // NYC coordinates
        source_id: SourceId(uuid::Uuid::new_v4()),
        first_seen: chrono::Utc::now(),
        last_seen: chrono::Utc::now(),
        confidence: Confidence::new(0.9),
        quality: Quality::new(1.0),
        tags: vec!["web".to_string(), "proxy".to_string(), "security".to_string()],
    };
    
    let file_node = Node {
        id: file_server,
        kind: NodeKind::Infrastructure,
        label: "Software Update Server".to_string(),
        position: Some(GeoCoord::new(37.7749, -122.4194)), // SF coordinates  
        source_id: SourceId(uuid::Uuid::new_v4()),
        first_seen: chrono::Utc::now(),
        last_seen: chrono::Utc::now(),
        confidence: Confidence::new(0.92),
        quality: Quality::new(1.0),
        tags: vec!["file".to_string(), "updates".to_string(), "integrity".to_string()],
    };
    
    let helpdesk_node = Node {
        id: helpdesk,
        kind: NodeKind::Endpoint,
        label: "IT Helpdesk".to_string(),
        position: Some(GeoCoord::new(52.5200, 13.4050)), // Berlin coordinates
        source_id: SourceId(uuid::Uuid::new_v4()),
        first_seen: chrono::Utc::now(),
        last_seen: chrono::Utc::now(),
        confidence: Confidence::new(0.88),
        quality: Quality::new(1.0),
        tags: vec!["helpdesk".to_string(), "identity".to_string(), "verification".to_string()],
    };
    
    graph.add_node(email_node);
    graph.add_node(web_node);
    graph.add_node(file_node);
    graph.add_node(helpdesk_node);
    
    println!("📊 Created security graph with {} entities", graph.node_count());
    
    // Set up security engine
    let mut security_engine = SecurityEngine::new();
    
    // Add security monitoring targets
    let email_target = SecurityTarget::email_gateway(email_gateway, "Email Gateway Monitor");
    let web_target = SecurityTarget::web_proxy(web_proxy, "Web Proxy Monitor");
    
    let mut file_target = SecurityTarget::email_gateway(file_server, "File Integrity Monitor");
    file_target.monitoring_type = MonitoringType::FileIntegrityCheck;
    
    let mut helpdesk_target = SecurityTarget::email_gateway(helpdesk, "Identity Verification Monitor");
    helpdesk_target.monitoring_type = MonitoringType::IdentityVerificationAudit;
    
    security_engine.add_target(email_target);
    security_engine.add_target(web_target);
    security_engine.add_target(file_target);
    security_engine.add_target(helpdesk_target);
    
    println!("🎯 Added {} security targets", security_engine.targets().len());
    
    // Display monitoring configuration
    println!("\n📋 Security Monitoring Configuration:");
    for target in security_engine.targets().values() {
        println!("   • {} → {:?}", target.label, target.monitoring_type);
    }
    
    // Run detection cycles
    println!("\n🔍 Running threat detection cycles...");
    for cycle in 1..=5 {
        println!("\n--- Cycle {} ---", cycle);
        
        let result = security_engine.execute_detection_cycle();
        println!("✅ Executed {} detections", result.detections_executed);
        
        if result.threats_detected > 0 {
            println!("⚠️  Detected {} threats", result.threats_detected);
        }
        
        if result.new_alerts > 0 {
            println!("🚨 Generated {} new alerts", result.new_alerts);
        }
        
        // Show current risk profiles
        let mut has_risks = false;
        for entity_id in [email_gateway, web_proxy, file_server, helpdesk].iter() {
            if let Some(risk) = security_engine.get_entity_risk(entity_id) {
                if risk.overall_risk_score > 0.0 {
                    has_risks = true;
                    let entity_label = match *entity_id {
                        id if id == email_gateway => "Email Gateway",
                        id if id == web_proxy => "Web Proxy",
                        id if id == file_server => "File Server",
                        _ => "IT Helpdesk",
                    };
                    
                    println!(
                        "📈 {}: risk={:.1}%, threats={}, summary={}",
                        entity_label,
                        risk.overall_risk_score * 100.0,
                        risk.sample_count,
                        risk.risk_summary
                    );
                }
            }
        }
        
        if !has_risks && cycle > 1 {
            println!("✅ All entities show minimal risk");
        }
        
        // Show pending alerts
        let pending_alerts = security_engine.get_pending_alerts();
        if !pending_alerts.is_empty() {
            println!("\n🔔 Pending Security Alerts:");
            for alert in pending_alerts.iter().take(3) {
                let urgency_emoji = match alert.urgency {
                    skeletrace::security::AlertUrgency::Critical => "🔴",
                    skeletrace::security::AlertUrgency::High => "🟡",
                    skeletrace::security::AlertUrgency::Medium => "🟠",
                    skeletrace::security::AlertUrgency::Low => "🔵",
                };
                
                println!(
                    "   {} {} (risk: {:.1}%): {}",
                    urgency_emoji,
                    alert.title,
                    alert.risk_score * 100.0,
                    alert.description
                );
            }
            
            if pending_alerts.len() > 3 {
                println!("   ... and {} more alerts", pending_alerts.len() - 3);
            }
        }
        
        // Generate metrics
        let samples = security_engine.generate_metric_samples();
        if !samples.is_empty() {
            println!("📊 Generated {} security metric samples", samples.len());
        }
        
        // Run attack surface analysis (every few cycles)
        if cycle % 2 == 0 {
            if let Some(report) = security_engine.analyze_attack_surface(&graph) {
                println!("🌐 Attack Surface Report:");
                println!("   Security posture: {:.1}%", report.security_posture_score * 100.0);
                
                if !report.high_risk_entities.is_empty() {
                    println!("   High-risk entities: {}", report.high_risk_entities.len());
                }
                
                if !report.attack_patterns.is_empty() {
                    println!("   Attack patterns: {}", report.attack_patterns.len());
                    for pattern in report.attack_patterns.iter().take(2) {
                        println!("     • {}", pattern.description);
                    }
                }
                
                println!("   Summary: {}", report.executive_summary);
            }
        }
        
        // Wait before next cycle
        if cycle < 5 {
            thread::sleep(Duration::from_secs(1));
        }
    }
    
    // Final statistics
    let stats = security_engine.stats();
    println!("\n📈 Final Security Statistics:");
    println!("   Active targets: {}", stats.active_targets);
    println!("   Total threat events: {}", stats.total_threat_events);
    println!("   High-risk entities: {}/{}", stats.high_risk_entities, stats.total_entities);
    println!("   Pending alerts: {} ({} critical)", stats.pending_alerts, stats.critical_alerts);
    
    // Demonstrate alert acknowledgment
    let pending_alert_count = security_engine.get_pending_alerts().len();
    if pending_alert_count > 0 {
        println!("\n🔧 Demonstrating alert management:");
        
        // Get first alert info before borrowing mutably
        let first_alert_info = {
            let alerts = security_engine.get_pending_alerts();
            (alerts[0].id.clone(), alerts[0].title.clone())
        };
        
        println!("   Acknowledging alert: {}", first_alert_info.1);
        
        // Now we can mutably borrow without conflict
        security_engine.acknowledge_alert(&first_alert_info.0, Some("Security Team".to_string()));
        
        println!("   ✅ Alert acknowledged and assigned");
    }
    
    println!("\n🎉 Security engine demo complete!");
    println!("Multi-vector threat detection successfully demonstrated across:");
    println!("   • Email security (phishing, BEC detection)");
    println!("   • Web security (watering holes, fake portals)"); 
    println!("   • File integrity (software authenticity)");
    println!("   • Identity verification (vishing, fraud detection)");
    println!("   • Attack surface analysis and risk assessment");
    println!("   • Real-time alerting and incident management");
}
