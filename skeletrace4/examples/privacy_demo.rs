//! Privacy engine demonstration showing comprehensive data protection and compliance monitoring.

use std::thread;
use std::time::Duration;

use skeletrace::entity::{Node, NodeKind};
use skeletrace::privacy::{
    PrivacyEngine, PrivacyMonitoringType, PrivacyTarget,
};
use skeletrace::spatial::GeoCoord;
use skeletrace::types::{Confidence, EntityId, Quality, SourceId};
use skeletrace::{Graph};

fn main() {
    // Initialize logging
    env_logger::init();
    
    println!("🔒 Skeletrace Privacy Engine Demo");
    println!("Comprehensive Data Protection and Compliance Monitoring");
    
    // Create a graph and add some privacy-monitored entities
    let mut graph = Graph::new();
    
    // Create entities representing different data protection monitoring points
    let customer_db = EntityId(uuid::Uuid::new_v4());
    let main_repo = EntityId(uuid::Uuid::new_v4());
    let api_gateway = EntityId(uuid::Uuid::new_v4());
    let nfc_system = EntityId(uuid::Uuid::new_v4());
    
    let database_node = Node {
        id: customer_db,
        kind: NodeKind::Infrastructure,
        label: "Customer Database (GDPR Protected)".to_string(),
        position: Some(GeoCoord::new(52.5200, 13.4050)), // Berlin coordinates
        source_id: SourceId(uuid::Uuid::new_v4()),
        first_seen: chrono::Utc::now(),
        last_seen: chrono::Utc::now(),
        confidence: Confidence::new(0.95),
        quality: Quality::new(1.0),
        tags: vec!["database".to_string(), "gdpr".to_string(), "encryption".to_string()],
    };
    
    let repository_node = Node {
        id: main_repo,
        kind: NodeKind::Logical,
        label: "Main Application Repository".to_string(),
        position: Some(GeoCoord::new(37.7749, -122.4194)), // SF coordinates
        source_id: SourceId(uuid::Uuid::new_v4()),
        first_seen: chrono::Utc::now(),
        last_seen: chrono::Utc::now(),
        confidence: Confidence::new(0.9),
        quality: Quality::new(1.0),
        tags: vec!["repository".to_string(), "credentials".to_string(), "secrets".to_string()],
    };
    
    let api_node = Node {
        id: api_gateway,
        kind: NodeKind::Logical,
        label: "OAuth API Gateway".to_string(),
        position: Some(GeoCoord::new(40.7128, -74.0060)), // NYC coordinates
        source_id: SourceId(uuid::Uuid::new_v4()),
        first_seen: chrono::Utc::now(),
        last_seen: chrono::Utc::now(),
        confidence: Confidence::new(0.92),
        quality: Quality::new(1.0),
        tags: vec!["api".to_string(), "oauth".to_string(), "tokens".to_string()],
    };
    
    let nfc_node = Node {
        id: nfc_system,
        kind: NodeKind::Endpoint,
        label: "NFC Access Control System".to_string(),
        position: Some(GeoCoord::new(51.5074, -0.1278)), // London coordinates
        source_id: SourceId(uuid::Uuid::new_v4()),
        first_seen: chrono::Utc::now(),
        last_seen: chrono::Utc::now(),
        confidence: Confidence::new(0.88),
        quality: Quality::new(1.0),
        tags: vec!["nfc".to_string(), "hardware".to_string(), "access_control".to_string()],
    };
    
    graph.add_node(database_node);
    graph.add_node(repository_node);
    graph.add_node(api_node);
    graph.add_node(nfc_node);
    
    println!("📊 Created privacy graph with {} entities", graph.node_count());
    
    // Set up privacy engine
    let mut privacy_engine = PrivacyEngine::new();
    
    // Add comprehensive privacy monitoring targets
    let db_target = PrivacyTarget::database_encryption(customer_db, "Customer Database Monitor");
    let repo_target = PrivacyTarget::repository_scanning(main_repo, "Repository Credential Scanner");
    let api_target = PrivacyTarget::api_security(api_gateway, "OAuth API Security Monitor");
    
    let mut nfc_target = PrivacyTarget::hardware_security(nfc_system, "NFC Hardware Security Audit");
    nfc_target.monitoring_type = PrivacyMonitoringType::HardwareSecurityAudit;
    
    privacy_engine.add_target(db_target);
    privacy_engine.add_target(repo_target);
    privacy_engine.add_target(api_target);
    privacy_engine.add_target(nfc_target);
    
    println!("🎯 Added {} privacy targets", privacy_engine.targets().len());
    
    // Display privacy monitoring configuration
    println!("\n📋 Privacy Monitoring Configuration:");
    for target in privacy_engine.targets().values() {
        println!("   • {} → {:?}", target.label, target.monitoring_type);
        
        // Show compliance frameworks being monitored
        if !target.config.compliance_frameworks.is_empty() {
            let frameworks: Vec<String> = target.config.compliance_frameworks
                .iter()
                .map(|f| format!("{:?}", f))
                .collect();
            println!("     Compliance: {}", frameworks.join(", "));
        }
    }
    
    // Run privacy detection cycles
    println!("\n🔍 Running privacy detection cycles...");
    for cycle in 1..=5 {
        println!("\n--- Cycle {} ---", cycle);
        
        let result = privacy_engine.execute_privacy_cycle();
        println!("✅ Executed {} privacy detections", result.detections_executed);
        
        if result.violations_detected > 0 {
            println!("⚠️  Detected {} privacy violations", result.violations_detected);
        }
        
        if result.new_privacy_alerts > 0 {
            println!("🚨 Generated {} new privacy alerts", result.new_privacy_alerts);
        }
        
        // Show current privacy profiles
        let mut has_privacy_risks = false;
        for entity_id in [customer_db, main_repo, api_gateway, nfc_system].iter() {
            if let Some(profile) = privacy_engine.get_entity_privacy_profile(entity_id) {
                if profile.overall_privacy_risk > 0.0 {
                    has_privacy_risks = true;
                    let entity_label = match *entity_id {
                        id if id == customer_db => "Customer Database",
                        id if id == main_repo => "Main Repository",
                        id if id == api_gateway => "API Gateway",
                        _ => "NFC System",
                    };
                    
                    println!(
                        "📈 {}: privacy_risk={:.1}%, violations={}, data_subjects={}, summary={}",
                        entity_label,
                        profile.overall_privacy_risk * 100.0,
                        profile.sample_count,
                        profile.affected_data_subjects,
                        profile.privacy_summary
                    );
                    
                    // Show compliance scores
                    if !profile.compliance_scores.is_empty() {
                        let mut compliance_details = Vec::new();
                        for (framework, &score) in &profile.compliance_scores {
                            compliance_details.push(format!("{:?}: {:.1}%", framework, score * 100.0));
                        }
                        println!("     Compliance: {}", compliance_details.join(", "));
                    }
                }
            }
        }
        
        if !has_privacy_risks && cycle > 1 {
            println!("✅ All entities show compliant privacy posture");
        }
        
        // Show pending privacy alerts
        let pending_alerts = privacy_engine.get_pending_privacy_alerts();
        if !pending_alerts.is_empty() {
            println!("\n🔔 Pending Privacy Alerts:");
            for alert in pending_alerts.iter().take(3) {
                let urgency_emoji = match alert.urgency {
                    skeletrace::privacy::AlertUrgency::Critical => "🔴",
                    skeletrace::privacy::AlertUrgency::High => "🟡",
                    skeletrace::privacy::AlertUrgency::Medium => "🟠",
                    skeletrace::privacy::AlertUrgency::Low => "🔵",
                };
                
                let compliance_impact: Vec<String> = alert.compliance_impact
                    .iter()
                    .map(|f| format!("{:?}", f))
                    .collect();
                
                println!(
                    "   {} {} (risk: {:.1}%, subjects: {}): {}",
                    urgency_emoji,
                    alert.title,
                    alert.privacy_risk_score * 100.0,
                    alert.data_subjects_affected,
                    alert.description
                );
                
                if !compliance_impact.is_empty() {
                    println!("     Compliance Impact: {}", compliance_impact.join(", "));
                }
            }
            
            if pending_alerts.len() > 3 {
                println!("   ... and {} more privacy alerts", pending_alerts.len() - 3);
            }
        }
        
        // Generate privacy compliance metrics
        let samples = privacy_engine.generate_metric_samples();
        if !samples.is_empty() {
            println!("📊 Generated {} privacy metric samples", samples.len());
        }
        
        // Run compliance analysis (every few cycles)
        if cycle % 2 == 0 {
            if let Some(report) = privacy_engine.analyze_compliance(&graph) {
                println!("🌐 Privacy Compliance Report:");
                println!("   Privacy posture: {:.1}%", report.privacy_posture_score * 100.0);
                
                if !report.high_risk_entities.is_empty() {
                    println!("   High-risk entities: {}", report.high_risk_entities.len());
                }
                
                if !report.protection_gaps.is_empty() {
                    println!("   Data protection gaps: {}", report.protection_gaps.len());
                    for gap in report.protection_gaps.iter().take(2) {
                        println!("     • {} (severity: {:?})", gap.description, gap.severity);
                        if let Some(cost) = gap.estimated_cost {
                            println!("       Remediation cost: ${:.0}", cost);
                        }
                    }
                }
                
                // Show compliance framework scores
                if !report.framework_compliance.is_empty() {
                    println!("   Compliance Framework Scores:");
                    for (framework, &score) in &report.framework_compliance {
                        let status = if score >= 0.9 {
                            "✅"
                        } else if score >= 0.8 {
                            "⚠️"
                        } else {
                            "🚨"
                        };
                        println!("     {} {:?}: {:.1}%", status, framework, score * 100.0);
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
    
    // Final privacy statistics
    let stats = privacy_engine.stats();
    println!("\n📈 Final Privacy Statistics:");
    println!("   Active targets: {}", stats.active_targets);
    println!("   Total privacy events: {}", stats.total_privacy_events);
    println!("   High-risk entities: {}/{}", stats.high_risk_entities, stats.total_entities);
    println!("   Pending privacy alerts: {} ({} critical)", stats.pending_privacy_alerts, stats.critical_privacy_alerts);
    println!("   Total data subjects affected: {}", stats.total_data_subjects_affected);
    
    // Demonstrate privacy alert management
    let pending_alerts_count = privacy_engine.get_pending_privacy_alerts().len();
    if pending_alerts_count > 0 {
        println!("\n🔧 Demonstrating privacy alert management:");
        
        // Get the first alert ID before borrowing
        let first_alert_id = privacy_engine.get_pending_privacy_alerts()[0].id.clone();
        let first_alert_title = privacy_engine.get_pending_privacy_alerts()[0].title.clone();
        
        println!("   Acknowledging privacy alert: {}", first_alert_title);
        
        // In a real system, this would be done by a privacy officer
        privacy_engine.acknowledge_privacy_alert(&first_alert_id, Some("Privacy Team".to_string()));
        
        println!("   ✅ Privacy alert acknowledged and assigned to privacy team");
    }
    
    println!("\n🎉 Privacy engine demo complete!");
    println!("Comprehensive data protection monitoring successfully demonstrated across:");
    println!("   • Database encryption at rest (GDPR Article 32 compliance)");
    println!("   • Repository credential scanning (secret exposure prevention)");
    println!("   • OAuth 2.0 token validation (API security assessment)");
    println!("   • NFC access badge configuration (hardware security audit)");
    println!("   • Multi-framework compliance scoring (GDPR, CCPA, HIPAA, PCI-DSS)");
    println!("   • Data subject impact assessment and privacy posture evaluation");
    println!("   • Real-time privacy breach detection and compliance alerting");
    println!("   • Executive compliance reporting and gap analysis");
}
