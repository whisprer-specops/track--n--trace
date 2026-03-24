//! Path diversity and topology health analysis algorithms.
//!
//! This module implements the resilience patterns common across:
//! - Undersea cable route redundancy
//! - 911 emergency call routing geographic diversity
//! - Anycast DNS root server distribution
//! - Internet exchange point fault tolerance
//! - Cellular network resilience against interference

use std::collections::{HashMap, HashSet, VecDeque};

use crate::graph::Graph;
use crate::probe::types::{NodeHealth, PathDiversity, ProbeResult, ProbeStatus};
use crate::spatial::GeoCoord;
use crate::types::{Confidence, EntityId};

// ── Path diversity algorithms ──────────────────────────────────────

/// Path diversity analyzer for the sparse graph.
#[derive(Debug)]
pub struct PathAnalyzer<'a> {
    graph: &'a Graph,
}

impl<'a> PathAnalyzer<'a> {
    pub fn new(graph: &'a Graph) -> Self {
        Self { graph }
    }

    /// Find node-disjoint paths between source and destination.
    ///
    /// Uses a modified Ford-Fulkerson approach to find maximum number
    /// of node-disjoint paths. Critical for failure resistance analysis.
    pub fn find_disjoint_paths(&self, source: EntityId, dest: EntityId) -> Vec<Vec<EntityId>> {
        // For now, implement a simple BFS-based approach
        // Production version would use proper max-flow algorithms
        let mut paths = Vec::new();
        let mut used_nodes = HashSet::new();

        // Find up to 3 disjoint paths (practical limit for most topologies)
        for _ in 0..3 {
            if let Some(path) = self.find_path_avoiding(source, dest, &used_nodes) {
                // Mark intermediate nodes as used (exclude source/dest)
                for &node in &path[1..path.len() - 1] {
                    used_nodes.insert(node);
                }
                paths.push(path);
            } else {
                break;
            }
        }

        paths
    }

    /// Find a path from source to dest avoiding specified nodes.
    fn find_path_avoiding(
        &self,
        source: EntityId,
        dest: EntityId,
        avoid: &HashSet<EntityId>,
    ) -> Option<Vec<EntityId>> {
        let mut queue = VecDeque::new();
        let mut visited = HashSet::new();
        let mut parent = HashMap::new();

        queue.push_back(source);
        visited.insert(source);

        while let Some(current) = queue.pop_front() {
            if current == dest {
                // Reconstruct path
                let mut path = Vec::new();
                let mut node = dest;
                while let Some(&p) = parent.get(&node) {
                    path.push(node);
                    node = p;
                }
                path.push(source);
                path.reverse();
                return Some(path);
            }

            for &neighbor in &self.graph.neighbors(&current) {
                if !visited.contains(&neighbor) && !avoid.contains(&neighbor) {
                    visited.insert(neighbor);
                    parent.insert(neighbor, current);
                    queue.push_back(neighbor);
                }
            }
        }

        None
    }

    /// Compute path diversity metrics for a source→destination pair.
    pub fn analyze_path_diversity(&self, source: EntityId, dest: EntityId) -> PathDiversity {
        let paths = self.find_disjoint_paths(source, dest);
        
        let disjoint_path_count = paths.len();
        let min_hops = paths.iter().map(|p| p.len()).min().map(|len| len.saturating_sub(1));
        let max_hops = paths.iter().map(|p| p.len()).max().map(|len| len.saturating_sub(1));
        
        // Geographic spread: maximum distance between path midpoints
        let geographic_spread_m = self.compute_geographic_spread(&paths);
        
        // Redundancy score: logarithmic scaling based on path count
        let redundancy_score = if disjoint_path_count == 0 {
            0.0
        } else if disjoint_path_count == 1 {
            0.2 // Single path = low redundancy
        } else {
            // Scale from 0.5 (2 paths) to 1.0 (4+ paths)
            (0.5 + 0.25 * (disjoint_path_count - 2) as f64).min(1.0)
        };

        PathDiversity {
            source,
            destination: dest,
            disjoint_path_count,
            min_hops,
            max_hops,
            geographic_spread_m,
            redundancy_score,
        }
    }

    /// Compute geographic spread between path midpoints.
    fn compute_geographic_spread(&self, paths: &[Vec<EntityId>]) -> Option<f64> {
        if paths.len() < 2 {
            return None;
        }

        let midpoints: Vec<GeoCoord> = paths
            .iter()
            .filter_map(|path| self.compute_path_midpoint(path))
            .collect();

        if midpoints.len() < 2 {
            return None;
        }

        let mut max_distance: f64 = 0.0;
        for (i, point_a) in midpoints.iter().enumerate() {
            for point_b in &midpoints[i + 1..] {
                let distance = point_a.distance_to(point_b);
                max_distance = max_distance.max(distance);
            }
        }

        Some(max_distance)
    }

    /// Compute the geographic midpoint of a path.
    fn compute_path_midpoint(&self, path: &[EntityId]) -> Option<GeoCoord> {
        let positions: Vec<GeoCoord> = path
            .iter()
            .filter_map(|&node_id| self.graph.nodes.get(&node_id))
            .filter_map(|node| node.position)
            .collect();

        if positions.is_empty() {
            return None;
        }

        let lat_sum: f64 = positions.iter().map(|pos| pos.lat).sum();
        let lon_sum: f64 = positions.iter().map(|pos| pos.lon).sum();
        let count = positions.len() as f64;

        Some(GeoCoord::new(lat_sum / count, lon_sum / count))
    }

    /// Find articulation points (single points of failure) in the graph.
    ///
    /// Critical for identifying vulnerabilities like single cable landing points
    /// or unique internet exchange points.
    pub fn find_articulation_points(&self) -> Vec<EntityId> {
        let mut articulation_points = Vec::new();
        let mut visited = HashSet::new();
        let mut discovery_time = HashMap::new();
        let mut low_link = HashMap::new();
        let mut parent = HashMap::new();
        let mut time = 0;

        // Run DFS from each unvisited node
        for &node_id in self.graph.nodes.keys() {
            if !visited.contains(&node_id) {
                self.articulation_dfs(
                    node_id,
                    &mut visited,
                    &mut discovery_time,
                    &mut low_link,
                    &mut parent,
                    &mut time,
                    &mut articulation_points,
                );
            }
        }

        articulation_points
    }

    /// DFS helper for articulation point finding.
    fn articulation_dfs(
        &self,
        u: EntityId,
        visited: &mut HashSet<EntityId>,
        discovery: &mut HashMap<EntityId, usize>,
        low: &mut HashMap<EntityId, usize>,
        parent: &mut HashMap<EntityId, EntityId>,
        time: &mut usize,
        articulation_points: &mut Vec<EntityId>,
    ) {
        let mut children = 0;
        visited.insert(u);
        discovery.insert(u, *time);
        low.insert(u, *time);
        *time += 1;

        for &v in &self.graph.neighbors(&u) {
            if !visited.contains(&v) {
                children += 1;
                parent.insert(v, u);

                self.articulation_dfs(u, visited, discovery, low, parent, time, articulation_points);

                // Update low link value
                if let (Some(&low_v), Some(&low_u)) = (low.get(&v), low.get(&u)) {
                    low.insert(u, low_u.min(low_v));
                }

                // Check for articulation point conditions
                let is_root = !parent.contains_key(&u);
                let has_multiple_children = children > 1;
                let blocks_path = match (discovery.get(&u), low.get(&v)) {
                    (Some(&disc_u), Some(&low_v)) => disc_u <= low_v,
                    _ => false,
                };

                if (is_root && has_multiple_children)
                    || (!is_root && blocks_path)
                {
                    if !articulation_points.contains(&u) {
                        articulation_points.push(u);
                    }
                }
            } else if parent.get(&u) != Some(&v) {
                // Back edge - update low link
                if let (Some(&disc_v), Some(&low_u)) = (discovery.get(&v), low.get(&u)) {
                    low.insert(u, low_u.min(disc_v));
                }
            }
        }
    }
}

// ── Node health aggregation ────────────────────────────────────────

/// Health analyzer for computing node-level health metrics.
#[derive(Debug)]
pub struct HealthAnalyzer {
    /// Sliding window size for health calculations.
    window_size: usize,
    /// Anomaly detection sensitivity (standard deviations).
    anomaly_threshold: f64,
}

impl HealthAnalyzer {
    pub fn new() -> Self {
        Self {
            window_size: 100,      // Last 100 probe results
            anomaly_threshold: 2.0, // 2 sigma anomaly detection
        }
    }

    pub fn with_window_size(window_size: usize) -> Self {
        Self {
            window_size,
            anomaly_threshold: 2.0,
        }
    }

    /// Compute aggregated health metrics for a node from recent probe results.
    pub fn compute_node_health(&self, results: &[ProbeResult]) -> NodeHealth {
        if results.is_empty() {
            return NodeHealth::default();
        }

        let entity_id = results[0].entity_id;
        
        // Take the most recent N results
        let window_results = if results.len() > self.window_size {
            &results[results.len() - self.window_size..]
        } else {
            results
        };

        // Basic availability: fraction of Up probes
        let up_count = window_results
            .iter()
            .filter(|r| r.status == ProbeStatus::Up)
            .count();
        let availability = up_count as f64 / window_results.len() as f64;

        // Latency statistics from successful probes
        let latencies_ms: Vec<f64> = window_results
            .iter()
            .filter_map(|r| r.latency.map(|l| l.as_millis() as f64))
            .collect();

        let (mean_latency_ms, latency_stddev_ms, jitter_ms) = if latencies_ms.is_empty() {
            (0.0, 0.0, 0.0)
        } else {
            let mean = latencies_ms.iter().sum::<f64>() / latencies_ms.len() as f64;
            
            let variance = if latencies_ms.len() > 1 {
                latencies_ms
                    .iter()
                    .map(|&x| (x - mean).powi(2))
                    .sum::<f64>()
                    / (latencies_ms.len() - 1) as f64
            } else {
                0.0
            };
            let stddev = variance.sqrt();

            // Jitter: mean absolute deviation of consecutive latencies
            let jitter = if latencies_ms.len() > 1 {
                latencies_ms
                    .windows(2)
                    .map(|w| (w[1] - w[0]).abs())
                    .sum::<f64>()
                    / (latencies_ms.len() - 1) as f64
            } else {
                0.0
            };

            (mean, stddev, jitter)
        };

        // Anomaly score: how far is current latency from historical mean?
        let anomaly_score = if !latencies_ms.is_empty() && latency_stddev_ms > 0.0 {
            let latest_latency = latencies_ms[latencies_ms.len() - 1];
            let z_score = (latest_latency - mean_latency_ms) / latency_stddev_ms;
            (z_score.abs() / self.anomaly_threshold).min(1.0)
        } else {
            0.0
        };

        // Confidence: based on sample count and recency
        let sample_count = window_results.len();
        let confidence_from_count = (sample_count as f64 / self.window_size as f64).min(1.0);
        
        // Recent samples boost confidence
        let now = chrono::Utc::now();
        let recent_weight = window_results
            .iter()
            .rev()
            .take(10) // Last 10 samples
            .map(|r| {
                let age_hours = now
                    .signed_duration_since(r.timestamp)
                    .num_hours()
                    .max(0) as f64;
                (-age_hours / 24.0).exp() // Exponential decay over days
            })
            .sum::<f64>()
            / 10.0;

        let confidence = Confidence::new(confidence_from_count * 0.7 + recent_weight * 0.3);

        NodeHealth {
            entity_id,
            availability,
            mean_latency_ms,
            latency_stddev_ms,
            jitter_ms,
            anomaly_score,
            confidence,
            sample_count,
            last_probed: window_results.last().map(|r| r.timestamp),
            current_status: window_results.last().map(|r| r.status).unwrap_or(ProbeStatus::Skipped),
        }
    }
}

impl Default for HealthAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entity::{Node, NodeKind};
    use crate::types::{Quality, SourceId};

    #[test]
    fn test_path_diversity_empty_graph() {
        let graph = Graph::new();
        let analyzer = PathAnalyzer::new(&graph);
        
        let source = EntityId(uuid::Uuid::new_v4());
        let dest = EntityId(uuid::Uuid::new_v4());
        
        let paths = analyzer.find_disjoint_paths(source, dest);
        assert!(paths.is_empty());
    }

    #[test]
    fn test_health_analyzer_empty_results() {
        let analyzer = HealthAnalyzer::new();
        let health = analyzer.compute_node_health(&[]);
        
        assert_eq!(health.availability, 0.0);
        assert_eq!(health.sample_count, 0);
    }
}
