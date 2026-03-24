//! Simple CLI example demonstrating the probe engine.

use std::thread;
use std::time::Duration;

use skeletrace::entity::{Node, NodeKind};
use skeletrace::probe::{ProbeEngine, ProbeTarget};
use skeletrace::spatial::GeoCoord;
use skeletrace::types::{Confidence, EntityId, Quality, SourceId};
use skeletrace::{Graph};

fn main() {
    // Initialize logging
    env_logger::init();
    
    println!("🚀 Skeletrace Probe Engine Demo");
    
    // Create a graph and add some nodes
    let mut graph = Graph::new();
    
    // Create entities for monitoring
    let api_entity = EntityId(uuid::Uuid::new_v4());
    let dns_entity = EntityId(uuid::Uuid::new_v4());
    
    let api_node = Node {
        id: api_entity,
        kind: NodeKind::Endpoint,
        label: "Example API".to_string(),
        position: Some(GeoCoord::new(40.7128, -74.0060)), // NYC coordinates
        source_id: SourceId(uuid::Uuid::new_v4()),
        first_seen: chrono::Utc::now(),
        last_seen: chrono::Utc::now(),
        confidence: Confidence::new(0.9),
        quality: Quality::new(1.0),
        tags: vec!["api".to_string(), "http".to_string()],
    };
    
    let dns_node = Node {
        id: dns_entity,
        kind: NodeKind::Infrastructure,
        label: "Google DNS".to_string(),
        position: Some(GeoCoord::new(37.7749, -122.4194)), // SF coordinates  
        source_id: SourceId(uuid::Uuid::new_v4()),
        first_seen: chrono::Utc::now(),
        last_seen: chrono::Utc::now(),
        confidence: Confidence::new(0.95),
        quality: Quality::new(1.0),
        tags: vec!["dns".to_string(), "infrastructure".to_string()],
    };
    
    graph.add_node(api_node);
    graph.add_node(dns_node);
    
    println!("📊 Created graph with {} nodes", graph.node_count());
    
    // Set up probe engine
    let mut probe_engine = ProbeEngine::new();
    
    // Add probe targets
    let api_target = ProbeTarget::http_get(
        api_entity,
        "https://httpbin.org/status/200",
        "HTTPBin Status Check"
    );
    
    let dns_target = ProbeTarget::http_get(
        dns_entity,
        "https://dns.google/",
        "Google DNS Landing Page"
    );
    
    probe_engine.add_target(api_target);
    probe_engine.add_target(dns_target);
    
    println!("🎯 Added {} probe targets", probe_engine.targets().len());
    
    // Run probe cycles
    println!("\n🔄 Running probe cycles...");
    for cycle in 1..=3 {
        println!("\n--- Cycle {} ---", cycle);
        
        let probes_executed = probe_engine.execute_probe_cycle();
        println!("✅ Executed {} probes", probes_executed);
        
        // Show current health
        for entity_id in [api_entity, dns_entity].iter() {
            if let Some(health) = probe_engine.get_node_health(entity_id) {
                println!(
                    "📈 Entity {:?}: availability={:.1}%, latency={:.1}ms, status={:?}",
                    entity_id,
                    health.availability * 100.0,
                    health.mean_latency_ms,
                    health.current_status
                );
            }
        }
        
        // Generate metrics
        let samples = probe_engine.generate_metric_samples();
        println!("📊 Generated {} metric samples", samples.len());
        
        // Run topology analysis (if due)
        if let Some(report) = probe_engine.analyze_topology(&graph) {
            println!("🌐 Topology Report:");
            println!("   Overall health: {:.1}%", report.overall_health * 100.0);
            println!("   SPOFs found: {}", report.articulation_points.len());
            println!("   Summary: {}", report.summary);
        }
        
        // Wait before next cycle
        if cycle < 3 {
            thread::sleep(Duration::from_secs(2));
        }
    }
    
    // Final statistics
    let stats = probe_engine.stats();
    println!("\n📈 Final Statistics:");
    println!("   Active targets: {}", stats.active_targets);
    println!("   Total probes executed: {}", stats.total_probes_executed);
    println!("   Healthy nodes: {}/{}", stats.healthy_nodes, stats.total_nodes);
    
    println!("\n🎉 Demo complete! Probe engine successfully demonstrated all resilience patterns.");
}
