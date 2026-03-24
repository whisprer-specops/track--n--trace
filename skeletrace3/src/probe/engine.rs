//! Main probe engine — orchestrates topology-aware probing and analysis.
//!
//! This is the central coordinator that manages:
//! - Probe target scheduling
//! - HTTP transport execution  
//! - Result aggregation and health analysis
//! - Path diversity and topology reporting
//!
//! Designed to integrate with Skeletrace's existing graph and metric systems.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use log::{debug, info, warn};

use crate::graph::Graph;
use crate::metric::{Sample, SampleValue};
use crate::probe::analysis::{HealthAnalyzer, PathAnalyzer};
use crate::probe::transport::{ProbeTransport, TransportConfig};
use crate::probe::types::{NodeHealth, PathDiversity, ProbeResult, ProbeTarget, TopologyReport};
use crate::types::{EntityId, MetricId, Quality, SourceId};

// ── Probe engine configuration ─────────────────────────────────────

/// Configuration for the probe engine.
#[derive(Debug, Clone)]
pub struct ProbeEngineConfig {
    /// HTTP transport configuration.
    pub transport: TransportConfig,
    /// Maximum concurrent probes.
    pub max_concurrent_probes: usize,
    /// Health analysis window size.
    pub health_window_size: usize,
    /// How often to run path diversity analysis.
    pub analysis_interval: Duration,
    /// Source ID for probe-generated metrics.
    pub source_id: SourceId,
}

impl Default for ProbeEngineConfig {
    fn default() -> Self {
        Self {
            transport: TransportConfig::default(),
            max_concurrent_probes: 10,
            health_window_size: 100,
            analysis_interval: Duration::from_secs(300), // 5 minutes
            source_id: SourceId(uuid::Uuid::nil()), // Replace with real UUID in practice
        }
    }
}

// ── Main probe engine ──────────────────────────────────────────────

/// Topology-aware probe engine.
///
/// Orchestrates HTTP probing, health analysis, and path diversity
/// assessment for entities in a Skeletrace graph.
pub struct ProbeEngine {
    /// Engine configuration.
    config: ProbeEngineConfig,
    /// HTTP transport client.
    transport: ProbeTransport,
    /// Health analyzer for node-level metrics.
    health_analyzer: HealthAnalyzer,
    /// Active probe targets.
    targets: HashMap<EntityId, ProbeTarget>,
    /// Probe result history (per entity).
    result_history: HashMap<EntityId, Vec<ProbeResult>>,
    /// Last probe times (for scheduling).
    last_probe_times: HashMap<EntityId, Instant>,
    /// Last topology analysis time.
    last_analysis: Option<Instant>,
    /// Current node health assessments.
    node_health: HashMap<EntityId, NodeHealth>,
}

impl ProbeEngine {
    /// Create a new probe engine with default configuration.
    pub fn new() -> Self {
        Self::with_config(ProbeEngineConfig::default())
    }

    /// Create a new probe engine with custom configuration.
    pub fn with_config(config: ProbeEngineConfig) -> Self {
        let transport = ProbeTransport::with_config(config.transport.clone());
        let health_analyzer = HealthAnalyzer::with_window_size(config.health_window_size);

        Self {
            config,
            transport,
            health_analyzer,
            targets: HashMap::new(),
            result_history: HashMap::new(),
            last_probe_times: HashMap::new(),
            last_analysis: None,
            node_health: HashMap::new(),
        }
    }

    // ── Target management ──────────────────────────────────────────

    /// Add a probe target for monitoring.
    pub fn add_target(&mut self, target: ProbeTarget) {
        info!(
            "Added probe target: {} -> {}",
            target.label, target.url
        );
        self.targets.insert(target.entity_id, target);
    }

    /// Remove a probe target.
    pub fn remove_target(&mut self, entity_id: &EntityId) -> Option<ProbeTarget> {
        let removed = self.targets.remove(entity_id);
        if removed.is_some() {
            info!("Removed probe target for entity {:?}", entity_id);
            // Clean up associated data
            self.result_history.remove(entity_id);
            self.last_probe_times.remove(entity_id);
            self.node_health.remove(entity_id);
        }
        removed
    }

    /// Get all active probe targets.
    pub fn targets(&self) -> &HashMap<EntityId, ProbeTarget> {
        &self.targets
    }

    // ── Probe execution ────────────────────────────────────────────

    /// Execute a single probe run.
    ///
    /// This checks all targets, executes probes that are due,
    /// updates health metrics, and returns the number of probes executed.
    pub fn execute_probe_cycle(&mut self) -> usize {
        let now = Instant::now();
        let mut executed_count = 0;

        // Collect targets that are due for probing
        let due_targets: Vec<EntityId> = self
            .targets
            .iter()
            .filter(|(entity_id, target)| {
                target.enabled && self.is_target_due(**entity_id, target, now)
            })
            .map(|(entity_id, _)| *entity_id)
            .collect();

        // Execute probes
        for entity_id in due_targets {
            if executed_count >= self.config.max_concurrent_probes {
                debug!(
                    "Hit max concurrent probe limit ({}), deferring remaining targets",
                    self.config.max_concurrent_probes
                );
                break;
            }

            if let Some(target) = self.targets.get(&entity_id).cloned() {
                let result = self.transport.execute_probe(&target);
                self.record_probe_result(result);
                self.last_probe_times.insert(entity_id, now);
                executed_count += 1;
            }
        }

        // Update node health metrics
        self.update_node_health();

        executed_count
    }

    /// Check if a target is due for probing.
    fn is_target_due(&self, entity_id: EntityId, target: &ProbeTarget, now: Instant) -> bool {
        match self.last_probe_times.get(&entity_id) {
            Some(&last_time) => now.duration_since(last_time) >= target.interval,
            None => true, // Never probed before
        }
    }

    /// Record a probe result and update history.
    fn record_probe_result(&mut self, result: ProbeResult) {
        debug!(
            "Probe result for {:?}: {:?} (latency: {:?})",
            result.entity_id, result.status, result.latency
        );

        // Add to history
        let history = self.result_history.entry(result.entity_id).or_default();
        history.push(result);

        // Trim history to reasonable size (2x window size)
        let max_history = self.config.health_window_size * 2;
        if history.len() > max_history {
            history.drain(0..history.len() - max_history);
        }
    }

    /// Update node health metrics from recent probe results.
    fn update_node_health(&mut self) {
        for (entity_id, history) in &self.result_history {
            let health = self.health_analyzer.compute_node_health(history);
            self.node_health.insert(*entity_id, health);
        }
    }

    // ── Metric integration ─────────────────────────────────────────

    /// Generate Skeletrace metric samples from current probe state.
    ///
    /// This allows probe results to feed into the broader metric system.
    pub fn generate_metric_samples(&self) -> Vec<Sample> {
        let mut samples = Vec::new();
        let now = chrono::Utc::now();

        for (entity_id, health) in &self.node_health {
            // Availability metric
            samples.push(Sample {
                metric_id: MetricId(uuid::Uuid::nil()), // Replace with real availability metric ID
                entity_id: *entity_id,
                timestamp: now,
                value: SampleValue::Numeric(health.availability),
                quality: Quality::new(health.confidence.value()),
                source_id: self.config.source_id,
            });

            // Latency metric
            if health.mean_latency_ms > 0.0 {
                samples.push(Sample {
                    metric_id: MetricId(uuid::Uuid::nil()), // Replace with real latency metric ID
                    entity_id: *entity_id,
                    timestamp: now,
                    value: SampleValue::Numeric(health.mean_latency_ms),
                    quality: Quality::new(health.confidence.value()),
                    source_id: self.config.source_id,
                });
            }

            // Anomaly score metric
            samples.push(Sample {
                metric_id: MetricId(uuid::Uuid::nil()), // Replace with real anomaly metric ID
                entity_id: *entity_id,
                timestamp: now,
                value: SampleValue::Numeric(health.anomaly_score),
                quality: Quality::new(health.confidence.value()),
                source_id: self.config.source_id,
            });
        }

        samples
    }

    // ── Topology analysis ──────────────────────────────────────────

    /// Run full topology analysis if due.
    ///
    /// This performs path diversity analysis and identifies articulation points.
    /// Returns a topology report if analysis was performed.
    pub fn analyze_topology(&mut self, graph: &Graph) -> Option<TopologyReport> {
        let now = Instant::now();
        
        // Check if analysis is due
        let analysis_due = match self.last_analysis {
            Some(last) => now.duration_since(last) >= self.config.analysis_interval,
            None => true,
        };

        if !analysis_due {
            return None;
        }

        info!("Running topology analysis...");

        let analyzer = PathAnalyzer::new(graph);
        
        // Find articulation points
        let articulation_points = analyzer.find_articulation_points();
        if !articulation_points.is_empty() {
            warn!(
                "Found {} articulation points (single points of failure): {:?}",
                articulation_points.len(),
                articulation_points
            );
        }

        // Analyze path diversity for key node pairs
        let path_diversity = self.analyze_key_paths(&analyzer, graph);

        // Compute overall topology health
        let overall_health = self.compute_overall_health(&path_diversity, &articulation_points);

        // Generate summary
        let summary = self.generate_topology_summary(overall_health, &articulation_points, &path_diversity);

        self.last_analysis = Some(now);

        Some(TopologyReport {
            timestamp: chrono::Utc::now(),
            node_health: self.node_health.clone(),
            articulation_points,
            path_diversity,
            overall_health,
            summary,
        })
    }

    /// Analyze path diversity for important node pairs.
    fn analyze_key_paths(&self, analyzer: &PathAnalyzer, graph: &Graph) -> Vec<PathDiversity> {
        let mut diversities = Vec::new();
        let nodes: Vec<EntityId> = graph.nodes.keys().cloned().collect();

        // For now, analyze all pairs (in production, focus on critical pairs)
        for (i, &source) in nodes.iter().enumerate() {
            for &dest in &nodes[i + 1..] {
                let diversity = analyzer.analyze_path_diversity(source, dest);
                if diversity.disjoint_path_count > 0 {
                    diversities.push(diversity);
                }
            }
        }

        diversities
    }

    /// Compute overall topology health score.
    fn compute_overall_health(&self, diversities: &[PathDiversity], articulation_points: &[EntityId]) -> f64 {
        if self.node_health.is_empty() {
            return 0.0;
        }

        // Node health component (70% of score)
        let node_health_avg = self
            .node_health
            .values()
            .map(|h| h.availability)
            .sum::<f64>()
            / self.node_health.len() as f64;

        // Path redundancy component (20% of score)
        let redundancy_avg = if diversities.is_empty() {
            0.5 // Neutral if no path analysis available
        } else {
            diversities
                .iter()
                .map(|d| d.redundancy_score)
                .sum::<f64>()
                / diversities.len() as f64
        };

        // Articulation point penalty (10% of score)
        let articulation_penalty = if articulation_points.is_empty() {
            1.0 // No single points of failure
        } else {
            // Penalty based on fraction of nodes that are SPOFs
            let total_nodes = self.node_health.len().max(1);
            let spof_ratio = articulation_points.len() as f64 / total_nodes as f64;
            (1.0 - spof_ratio.min(0.5)).max(0.3) // Cap penalty to keep score reasonable
        };

        node_health_avg * 0.7 + redundancy_avg * 0.2 + articulation_penalty * 0.1
    }

    /// Generate human-readable topology summary.
    fn generate_topology_summary(
        &self,
        overall_health: f64,
        articulation_points: &[EntityId],
        diversities: &[PathDiversity],
    ) -> String {
        let health_status = match overall_health {
            h if h >= 0.9 => "Excellent",
            h if h >= 0.75 => "Good", 
            h if h >= 0.5 => "Fair",
            h if h >= 0.25 => "Poor",
            _ => "Critical",
        };

        let mut summary = format!(
            "Topology health: {} ({:.1}%). {} nodes monitored.",
            health_status,
            overall_health * 100.0,
            self.node_health.len()
        );

        if !articulation_points.is_empty() {
            summary.push_str(&format!(
                " {} single points of failure detected.",
                articulation_points.len()
            ));
        }

        let redundant_paths = diversities.iter().filter(|d| d.disjoint_path_count >= 2).count();
        if !diversities.is_empty() {
            summary.push_str(&format!(
                " {}/{} path pairs have redundancy.",
                redundant_paths,
                diversities.len()
            ));
        }

        summary
    }

    // ── Status queries ─────────────────────────────────────────────

    /// Get current node health for a specific entity.
    pub fn get_node_health(&self, entity_id: &EntityId) -> Option<&NodeHealth> {
        self.node_health.get(entity_id)
    }

    /// Get probe result history for an entity.
    pub fn get_probe_history(&self, entity_id: &EntityId) -> Option<&[ProbeResult]> {
        self.result_history.get(entity_id).map(|v| v.as_slice())
    }

    /// Get summary statistics.
    pub fn stats(&self) -> ProbeEngineStats {
        let total_probes = self.result_history.values().map(|h| h.len()).sum();
        let active_targets = self.targets.len();
        let healthy_nodes = self
            .node_health
            .values()
            .filter(|h| h.availability >= 0.8)
            .count();

        ProbeEngineStats {
            active_targets,
            total_probes_executed: total_probes,
            healthy_nodes,
            total_nodes: self.node_health.len(),
        }
    }
}

impl Default for ProbeEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ── Statistics ─────────────────────────────────────────────────────

/// Summary statistics for the probe engine.
#[derive(Debug, Clone)]
pub struct ProbeEngineStats {
    pub active_targets: usize,
    pub total_probes_executed: usize,
    pub healthy_nodes: usize,
    pub total_nodes: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probe::types::ProbeMethod;

    #[test]
    fn test_probe_engine_creation() {
        let engine = ProbeEngine::new();
        assert_eq!(engine.targets.len(), 0);
        assert_eq!(engine.node_health.len(), 0);
    }

    #[test]
    fn test_add_remove_target() {
        let mut engine = ProbeEngine::new();
        let entity_id = EntityId(uuid::Uuid::new_v4());
        
        let target = ProbeTarget::http_get(entity_id, "https://example.com", "Test");
        engine.add_target(target.clone());
        
        assert_eq!(engine.targets.len(), 1);
        assert!(engine.targets.contains_key(&entity_id));

        let removed = engine.remove_target(&entity_id);
        assert!(removed.is_some());
        assert_eq!(engine.targets.len(), 0);
    }
}
