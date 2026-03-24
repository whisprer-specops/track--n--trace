//! Security risk analysis and behavioral monitoring algorithms.
//!
//! This module implements risk assessment patterns from security operations:
//! - Behavioral analysis for anomaly detection and threat pattern recognition
//! - Risk scoring algorithms that aggregate threat indicators across vectors
//! - Attack surface assessment for organizational security posture evaluation
//! - Threat intelligence correlation and pattern matching

use std::collections::HashMap;

use log::{debug, info};

use crate::graph::Graph;
use crate::security::types::{
    AttackPattern, AttackSurfaceReport, EntityRiskProfile, ThreatEvent, 
    ThreatSeverity, ThreatVector, ThreatType,
};
use crate::types::{Confidence, EntityId};

// ── Risk scoring algorithms ────────────────────────────────────────

/// Risk analyzer for computing entity-level security metrics.
#[derive(Debug)]
pub struct SecurityAnalyzer {
    /// Time window for risk assessment (in hours).
    risk_window_hours: u32,
    /// Threat decay factor for older events.
    threat_decay_factor: f64,
    /// Minimum sample size for confident risk assessment.
    min_sample_size: usize,
}

impl SecurityAnalyzer {
    pub fn new() -> Self {
        Self {
            risk_window_hours: 168, // 1 week
            threat_decay_factor: 0.95, // 5% decay per day
            min_sample_size: 5,
        }
    }

    pub fn with_window_hours(window_hours: u32) -> Self {
        Self {
            risk_window_hours: window_hours,
            threat_decay_factor: 0.95,
            min_sample_size: 5,
        }
    }

    /// Compute risk profile for an entity from threat events.
    pub fn compute_entity_risk(&self, events: &[ThreatEvent]) -> EntityRiskProfile {
        if events.is_empty() {
            return EntityRiskProfile::default();
        }

        let entity_id = events[0].entity_id;
        let now = chrono::Utc::now();
        
        // Filter to events within the risk window
        let recent_events: Vec<&ThreatEvent> = events
            .iter()
            .filter(|event| {
                let age_hours = now
                    .signed_duration_since(event.timestamp)
                    .num_hours()
                    .max(0) as u32;
                age_hours <= self.risk_window_hours
            })
            .collect();

        if recent_events.is_empty() {
            return EntityRiskProfile::default_for_entity(entity_id);
        }

        // Calculate overall risk score with time decay
        let mut weighted_risk_sum = 0.0;
        let mut weight_sum = 0.0;
        let mut vector_scores: HashMap<ThreatVector, Vec<f64>> = HashMap::new();
        let mut threat_counts: HashMap<ThreatSeverity, u32> = HashMap::new();

        for event in &recent_events {
            let age_days = now
                .signed_duration_since(event.timestamp)
                .num_days()
                .max(0) as u32;
            
            let decay_factor = self.threat_decay_factor.powi(age_days as i32);
            let weighted_score = event.risk_score * decay_factor * event.confidence.value();
            
            weighted_risk_sum += weighted_score;
            weight_sum += decay_factor * event.confidence.value();

            // Track scores by vector
            vector_scores
                .entry(event.threat_vector)
                .or_default()
                .push(weighted_score);

            // Count threats by severity
            *threat_counts.entry(event.severity).or_insert(0) += 1;
        }

        let overall_risk_score = if weight_sum > 0.0 {
            weighted_risk_sum / weight_sum
        } else {
            0.0
        };

        // Compute vector-specific risk scores
        let vector_risk_scores: HashMap<ThreatVector, f64> = vector_scores
            .into_iter()
            .map(|(vector, scores)| {
                let avg_score = scores.iter().sum::<f64>() / scores.len() as f64;
                (vector, avg_score)
            })
            .collect();

        // Calculate risk trend (simple linear regression over time)
        let risk_trend = self.calculate_risk_trend(&recent_events);

        // Confidence based on sample size and recency
        let confidence = self.calculate_confidence(&recent_events);

        // Generate risk summary
        let risk_summary = self.generate_risk_summary(overall_risk_score, &threat_counts, &vector_risk_scores);

        EntityRiskProfile {
            entity_id,
            overall_risk_score,
            vector_scores: vector_risk_scores,
            threat_counts,
            risk_trend,
            confidence,
            sample_count: recent_events.len(),
            last_threat_detected: recent_events.iter().map(|e| e.timestamp).max(),
            risk_summary,
        }
    }

    /// Calculate risk trend over time using simple linear regression.
    fn calculate_risk_trend(&self, events: &[&ThreatEvent]) -> f64 {
        if events.len() < 3 {
            return 0.0; // Need at least 3 points for trend
        }

        let now = chrono::Utc::now();
        let mut points: Vec<(f64, f64)> = events
            .iter()
            .map(|event| {
                let hours_ago = now.signed_duration_since(event.timestamp).num_hours() as f64;
                (hours_ago, event.risk_score)
            })
            .collect();

        // Sort by time (oldest first)
        points.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap());

        // Simple linear regression
        let n = points.len() as f64;
        let sum_x: f64 = points.iter().map(|(x, _)| x).sum();
        let sum_y: f64 = points.iter().map(|(_, y)| y).sum();
        let sum_xy: f64 = points.iter().map(|(x, y)| x * y).sum();
        let sum_x2: f64 = points.iter().map(|(x, _)| x * x).sum();

        let denominator = n * sum_x2 - sum_x * sum_x;
        if denominator.abs() < 1e-10 {
            return 0.0;
        }

        let slope = (n * sum_xy - sum_x * sum_y) / denominator;
        
        // Normalize slope to [-1, 1] range
        slope.clamp(-1.0, 1.0)
    }

    /// Calculate confidence in risk assessment based on data quality.
    fn calculate_confidence(&self, events: &[&ThreatEvent]) -> Confidence {
        let sample_size_factor = (events.len() as f64 / self.min_sample_size as f64).min(1.0);
        
        // Average confidence of individual events
        let avg_event_confidence = if !events.is_empty() {
            events.iter().map(|e| e.confidence.value()).sum::<f64>() / events.len() as f64
        } else {
            0.0
        };

        // Recency factor (more recent events = higher confidence)
        let now = chrono::Utc::now();
        let recency_factor = if !events.is_empty() {
            let avg_age_hours = events
                .iter()
                .map(|e| now.signed_duration_since(e.timestamp).num_hours().max(0) as f64)
                .sum::<f64>() / events.len() as f64;
            
            (-avg_age_hours / (24.0 * 7.0)).exp() // Exponential decay over weeks
        } else {
            0.0
        };

        let combined_confidence = sample_size_factor * 0.4 + avg_event_confidence * 0.4 + recency_factor * 0.2;
        
        Confidence::new(combined_confidence)
    }

    /// Generate human-readable risk summary.
    fn generate_risk_summary(
        &self,
        overall_risk: f64,
        threat_counts: &HashMap<ThreatSeverity, u32>,
        vector_scores: &HashMap<ThreatVector, f64>,
    ) -> String {
        let risk_level = match overall_risk {
            r if r >= 0.8 => "Critical",
            r if r >= 0.6 => "High",
            r if r >= 0.4 => "Medium",
            r if r >= 0.2 => "Low",
            _ => "Minimal",
        };

        let total_threats: u32 = threat_counts.values().sum();
        let critical_threats = threat_counts.get(&ThreatSeverity::Critical).unwrap_or(&0);
        let high_threats = threat_counts.get(&ThreatSeverity::High).unwrap_or(&0);

        let mut summary = format!(
            "{} risk level ({:.1}%). {} threats detected",
            risk_level,
            overall_risk * 100.0,
            total_threats
        );

        if critical_threats > &0 || high_threats > &0 {
            summary.push_str(&format!(
                " ({} critical, {} high severity)",
                critical_threats, high_threats
            ));
        }

        // Add highest risk vector
        if let Some((vector, &score)) = vector_scores
            .iter()
            .max_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap())
        {
            if score > 0.3 {
                summary.push_str(&format!(". Primary threat vector: {:?}", vector));
            }
        }

        summary
    }

    /// Detect attack patterns across multiple entities.
    pub fn detect_attack_patterns(&self, events: &[ThreatEvent]) -> Vec<AttackPattern> {
        let mut patterns = Vec::new();

        // Group events by threat type and time windows
        let mut threat_groups: HashMap<ThreatType, Vec<&ThreatEvent>> = HashMap::new();
        
        for event in events {
            threat_groups.entry(event.threat_type).or_default().push(event);
        }

        for (threat_type, group_events) in threat_groups {
            if group_events.len() >= 3 {
                // Look for patterns in this threat type
                let pattern = self.analyze_threat_pattern(threat_type, &group_events);
                if pattern.frequency >= 3 {
                    patterns.push(pattern);
                }
            }
        }

        // Sort patterns by frequency and recency
        patterns.sort_by(|a, b| {
            b.frequency.cmp(&a.frequency)
                .then_with(|| b.last_seen.cmp(&a.last_seen))
        });

        patterns
    }

    /// Analyze a group of similar threats for attack patterns.
    fn analyze_threat_pattern(
        &self,
        threat_type: ThreatType,
        events: &[&ThreatEvent],
    ) -> AttackPattern {
        let affected_entities: Vec<EntityId> = events
            .iter()
            .map(|e| e.entity_id)
            .collect();

        let first_seen = events.iter().map(|e| e.timestamp).min().unwrap();
        let last_seen = events.iter().map(|e| e.timestamp).max().unwrap();

        // Calculate success rate (events with high confidence and risk score)
        let successful_attacks = events
            .iter()
            .filter(|e| e.risk_score > 0.6 && e.confidence.value() > 0.7)
            .count();
        
        let success_rate = successful_attacks as f64 / events.len() as f64;

        let description = self.generate_pattern_description(threat_type, events.len(), success_rate);

        AttackPattern {
            pattern_id: format!("{:?}-{}", threat_type, first_seen.timestamp()),
            threat_types: vec![threat_type],
            affected_entities,
            first_seen,
            last_seen,
            frequency: events.len() as u32,
            success_rate,
            description,
        }
    }

    fn generate_pattern_description(
        &self,
        threat_type: ThreatType,
        frequency: usize,
        success_rate: f64,
    ) -> String {
        let success_desc = match success_rate {
            s if s >= 0.8 => "highly successful",
            s if s >= 0.5 => "moderately successful",
            s if s >= 0.2 => "partially successful",
            _ => "largely unsuccessful",
        };

        format!(
            "{:?} campaign: {} attempts, {} ({}% success rate)",
            threat_type,
            frequency,
            success_desc,
            (success_rate * 100.0) as u32
        )
    }
}

impl Default for SecurityAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ── Attack surface analysis ────────────────────────────────────────

/// Attack surface analyzer for organizational security assessment.
#[derive(Debug)]
pub struct AttackSurfaceAnalyzer<'a> {
    graph: &'a Graph,
}

impl<'a> AttackSurfaceAnalyzer<'a> {
    pub fn new(graph: &'a Graph) -> Self {
        Self { graph }
    }

    /// Generate comprehensive attack surface report.
    pub fn generate_attack_surface_report(
        &self,
        entity_risks: HashMap<EntityId, EntityRiskProfile>,
        threat_events: &[ThreatEvent],
        security_analyzer: &SecurityAnalyzer,
    ) -> AttackSurfaceReport {
        let timestamp = chrono::Utc::now();

        // Calculate threat vector exposure levels
        let vector_exposure = self.calculate_vector_exposure(&entity_risks);

        // Identify high-risk entities
        let high_risk_entities = self.identify_high_risk_entities(&entity_risks);

        // Detect attack patterns
        let attack_patterns = security_analyzer.detect_attack_patterns(threat_events);

        // Calculate overall security posture
        let security_posture_score = self.calculate_security_posture(&entity_risks, &vector_exposure);

        // Generate executive summary
        let executive_summary = self.generate_executive_summary(
            security_posture_score,
            &high_risk_entities,
            &attack_patterns,
            &vector_exposure,
        );

        AttackSurfaceReport {
            timestamp,
            entity_risks,
            vector_exposure,
            high_risk_entities,
            attack_patterns,
            security_posture_score,
            executive_summary,
        }
    }

    /// Calculate exposure levels for each threat vector.
    fn calculate_vector_exposure(
        &self,
        entity_risks: &HashMap<EntityId, EntityRiskProfile>,
    ) -> HashMap<ThreatVector, f64> {
        let mut vector_totals: HashMap<ThreatVector, Vec<f64>> = HashMap::new();

        // Collect all vector scores across entities
        for risk_profile in entity_risks.values() {
            for (vector, &score) in &risk_profile.vector_scores {
                vector_totals.entry(*vector).or_default().push(score);
            }
        }

        // Calculate average exposure for each vector
        vector_totals
            .into_iter()
            .map(|(vector, scores)| {
                let avg_score = if !scores.is_empty() {
                    scores.iter().sum::<f64>() / scores.len() as f64
                } else {
                    0.0
                };
                (vector, avg_score)
            })
            .collect()
    }

    /// Identify entities with high risk scores requiring attention.
    fn identify_high_risk_entities(
        &self,
        entity_risks: &HashMap<EntityId, EntityRiskProfile>,
    ) -> Vec<EntityId> {
        let mut high_risk: Vec<(EntityId, f64)> = entity_risks
            .iter()
            .filter(|(_, profile)| profile.overall_risk_score >= 0.6)
            .map(|(id, profile)| (*id, profile.overall_risk_score))
            .collect();

        // Sort by risk score (highest first)
        high_risk.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());

        // Return top 10 or all if fewer than 10
        high_risk
            .into_iter()
            .take(10)
            .map(|(id, _)| id)
            .collect()
    }

    /// Calculate overall organizational security posture score.
    fn calculate_security_posture(
        &self,
        entity_risks: &HashMap<EntityId, EntityRiskProfile>,
        vector_exposure: &HashMap<ThreatVector, f64>,
    ) -> f64 {
        if entity_risks.is_empty() {
            return 0.0;
        }

        // Entity health component (60% weight)
        let avg_entity_risk: f64 = entity_risks
            .values()
            .map(|profile| profile.overall_risk_score)
            .sum::<f64>() / entity_risks.len() as f64;
        
        let entity_health = (1.0 - avg_entity_risk).max(0.0);

        // Vector diversity component (20% weight)
        // Lower exposure across multiple vectors is better
        let max_vector_exposure = vector_exposure
            .values()
            .max_by(|a, b| a.partial_cmp(b).unwrap())
            .unwrap_or(&0.0);
        
        let vector_health = (1.0 - max_vector_exposure).max(0.0);

        // Coverage component (20% weight)
        // Having monitoring across all vectors is good
        let monitored_vectors = vector_exposure.len() as f64;
        let total_vectors = 8.0; // Total number of ThreatVector variants
        let coverage_score = monitored_vectors / total_vectors;

        // Combine components
        entity_health * 0.6 + vector_health * 0.2 + coverage_score * 0.2
    }

    /// Generate executive summary of security posture.
    fn generate_executive_summary(
        &self,
        security_posture: f64,
        high_risk_entities: &[EntityId],
        attack_patterns: &[AttackPattern],
        vector_exposure: &HashMap<ThreatVector, f64>,
    ) -> String {
        let posture_level = match security_posture {
            s if s >= 0.8 => "Excellent",
            s if s >= 0.6 => "Good",
            s if s >= 0.4 => "Fair",
            s if s >= 0.2 => "Poor",
            _ => "Critical",
        };

        let mut summary = format!(
            "Security posture: {} ({:.1}%). ",
            posture_level,
            security_posture * 100.0
        );

        if !high_risk_entities.is_empty() {
            summary.push_str(&format!(
                "{} entities require immediate attention. ",
                high_risk_entities.len()
            ));
        }

        if !attack_patterns.is_empty() {
            let active_campaigns = attack_patterns
                .iter()
                .filter(|p| {
                    chrono::Utc::now()
                        .signed_duration_since(p.last_seen)
                        .num_hours() < 48
                })
                .count();
            
            if active_campaigns > 0 {
                summary.push_str(&format!(
                    "{} active attack campaigns detected. ",
                    active_campaigns
                ));
            }
        }

        // Highlight most exposed threat vector
        if let Some((vector, &exposure)) = vector_exposure
            .iter()
            .max_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap())
        {
            if exposure > 0.4 {
                summary.push_str(&format!(
                    "Primary threat vector: {:?} ({:.1}% exposure).",
                    vector,
                    exposure * 100.0
                ));
            }
        }

        summary
    }
}

// ── Default implementation for EntityRiskProfile ───────────────────

impl EntityRiskProfile {
    fn default_for_entity(entity_id: EntityId) -> Self {
        Self {
            entity_id,
            overall_risk_score: 0.0,
            vector_scores: HashMap::new(),
            threat_counts: HashMap::new(),
            risk_trend: 0.0,
            confidence: Confidence::new(0.0),
            sample_count: 0,
            last_threat_detected: None,
            risk_summary: "No threats detected".to_string(),
        }
    }
}

impl Default for EntityRiskProfile {
    fn default() -> Self {
        Self::default_for_entity(EntityId(uuid::Uuid::nil()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::types::{ThreatIndicators, ThreatEvent};

    #[test]
    fn test_security_analyzer_creation() {
        let analyzer = SecurityAnalyzer::new();
        assert_eq!(analyzer.risk_window_hours, 168);
        assert!(analyzer.threat_decay_factor > 0.0);
    }

    #[test]
    fn test_risk_calculation_empty_events() {
        let analyzer = SecurityAnalyzer::new();
        let risk_profile = analyzer.compute_entity_risk(&[]);
        assert_eq!(risk_profile.overall_risk_score, 0.0);
        assert_eq!(risk_profile.sample_count, 0);
    }

    #[test]
    fn test_attack_pattern_detection() {
        let analyzer = SecurityAnalyzer::new();
        
        // Create test events
        let mut events = Vec::new();
        let entity_id = EntityId(uuid::Uuid::new_v4());
        
        for i in 0..5 {
            let event = ThreatEvent {
                id: format!("test-{}", i),
                entity_id,
                timestamp: chrono::Utc::now(),
                threat_vector: ThreatVector::Email,
                threat_type: ThreatType::Phishing,
                severity: ThreatSeverity::Medium,
                risk_score: 0.7,
                confidence: Confidence::new(0.8),
                description: "Test event".to_string(),
                detection_source: "test".to_string(),
                indicators: ThreatIndicators {
                    email: None,
                    voice: None,
                    sms: None,
                    web: None,
                    file: None,
                    social: None,
                    identity: None,
                    network: None,
                },
                investigated: false,
                notes: String::new(),
            };
            events.push(event);
        }
        
        let patterns = analyzer.detect_attack_patterns(&events);
        assert_eq!(patterns.len(), 1);
        assert_eq!(patterns[0].threat_types, vec![ThreatType::Phishing]);
        assert_eq!(patterns[0].frequency, 5);
    }
}
