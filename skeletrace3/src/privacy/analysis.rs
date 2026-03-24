//! Privacy risk analysis and compliance assessment algorithms.
//!
//! This module implements privacy risk assessment patterns from data protection regulations:
//! - Data subject impact assessment (DSIA) for GDPR Article 35 compliance
//! - Privacy by design and by default assessment frameworks
//! - Compliance scoring for multiple regulatory frameworks (GDPR, CCPA, HIPAA, PCI-DSS)
//! - Data protection gap analysis and remediation prioritization
//! - Privacy posture evaluation for organizational risk management

use std::collections::HashMap;

use log::{debug, info, warn};

use crate::graph::Graph;
use crate::privacy::types::{
    ComplianceFramework, ComplianceViolation, DataCategory, DataSubject,
    EntityPrivacyProfile, PrivacyComplianceReport, PrivacyEvent, ProtectionGap,
    ProtectionVector, ViolationSeverity,
};
use crate::types::{Confidence, EntityId};

// ── Privacy risk assessment ────────────────────────────────────────

/// Privacy risk analyzer for computing entity-level compliance metrics.
#[derive(Debug)]
pub struct PrivacyAnalyzer {
    /// Time window for risk assessment (in hours).
    assessment_window_hours: u32,
    /// Privacy risk decay factor for older events.
    privacy_decay_factor: f64,
    /// Minimum sample size for confident assessment.
    min_sample_size: usize,
    /// Compliance framework weights.
    framework_weights: HashMap<ComplianceFramework, f64>,
}

impl PrivacyAnalyzer {
    pub fn new() -> Self {
        Self {
            assessment_window_hours: 168 * 4, // 4 weeks
            privacy_decay_factor: 0.98, // 2% decay per day
            min_sample_size: 3,
            framework_weights: Self::default_framework_weights(),
        }
    }

    pub fn with_window_hours(window_hours: u32) -> Self {
        Self {
            assessment_window_hours: window_hours,
            privacy_decay_factor: 0.98,
            min_sample_size: 3,
            framework_weights: Self::default_framework_weights(),
        }
    }

    /// Compute comprehensive privacy profile for an entity from violation events.
    pub fn compute_entity_privacy_profile(&self, events: &[PrivacyEvent]) -> EntityPrivacyProfile {
        if events.is_empty() {
            return EntityPrivacyProfile::default();
        }

        let entity_id = events[0].entity_id;
        let now = chrono::Utc::now();
        
        // Filter to events within the assessment window
        let recent_events: Vec<&PrivacyEvent> = events
            .iter()
            .filter(|event| {
                let age_hours = now
                    .signed_duration_since(event.timestamp)
                    .num_hours()
                    .max(0) as u32;
                age_hours <= self.assessment_window_hours
            })
            .collect();

        if recent_events.is_empty() {
            return EntityPrivacyProfile::default_for_entity(entity_id);
        }

        // Calculate overall privacy risk with time decay
        let mut weighted_risk_sum = 0.0;
        let mut weight_sum = 0.0;
        let mut vector_scores: HashMap<ProtectionVector, Vec<f64>> = HashMap::new();
        let mut violation_counts: HashMap<ViolationSeverity, u32> = HashMap::new();

        for event in &recent_events {
            let age_days = now
                .signed_duration_since(event.timestamp)
                .num_days()
                .max(0) as u32;
            
            let decay_factor = self.privacy_decay_factor.powi(age_days as i32);
            let weighted_score = event.privacy_risk_score * decay_factor * event.confidence.value();
            
            weighted_risk_sum += weighted_score;
            weight_sum += decay_factor * event.confidence.value();

            // Track scores by protection vector
            vector_scores
                .entry(event.protection_vector)
                .or_default()
                .push(weighted_score);

            // Count violations by severity
            *violation_counts.entry(event.severity).or_insert(0) += 1;
        }

        let overall_privacy_risk = if weight_sum > 0.0 {
            weighted_risk_sum / weight_sum
        } else {
            0.0
        };

        // Compute vector-specific risk scores
        let vector_risk_scores: HashMap<ProtectionVector, f64> = vector_scores
            .into_iter()
            .map(|(vector, scores)| {
                let avg_score = scores.iter().sum::<f64>() / scores.len() as f64;
                (vector, avg_score)
            })
            .collect();

        // Calculate compliance scores for each framework
        let compliance_scores = self.calculate_compliance_scores(&recent_events);

        // Calculate privacy risk trend
        let risk_trend = self.calculate_privacy_trend(&recent_events);

        // Calculate affected data subjects
        let affected_data_subjects = self.calculate_affected_data_subjects(&recent_events);

        // Confidence based on sample size, recency, and data quality
        let confidence = self.calculate_privacy_confidence(&recent_events);

        // Generate privacy summary
        let privacy_summary = self.generate_privacy_summary(
            overall_privacy_risk, 
            &violation_counts, 
            &compliance_scores,
            affected_data_subjects,
        );

        EntityPrivacyProfile {
            entity_id,
            overall_privacy_risk,
            vector_scores: vector_risk_scores,
            violation_counts,
            compliance_scores,
            risk_trend,
            confidence,
            sample_count: recent_events.len(),
            last_violation_detected: recent_events.iter().map(|e| e.timestamp).max(),
            affected_data_subjects,
            privacy_summary,
        }
    }

    /// Calculate compliance scores for different regulatory frameworks.
    fn calculate_compliance_scores(
        &self,
        events: &[&PrivacyEvent],
    ) -> HashMap<ComplianceFramework, f64> {
        let mut framework_violations: HashMap<ComplianceFramework, Vec<f64>> = HashMap::new();

        // Collect violation scores by framework
        for event in events {
            for compliance_violation in &event.compliance_violations {
                framework_violations
                    .entry(compliance_violation.framework)
                    .or_default()
                    .push(event.privacy_risk_score);
            }
        }

        // Calculate compliance scores (1.0 = fully compliant, 0.0 = major violations)
        let mut compliance_scores = HashMap::new();
        
        // Start with perfect compliance for all frameworks
        for &framework in self.framework_weights.keys() {
            compliance_scores.insert(framework, 1.0);
        }

        // Reduce scores based on violations
        for (framework, violation_scores) in framework_violations {
            if !violation_scores.is_empty() {
                let avg_violation = violation_scores.iter().sum::<f64>() / violation_scores.len() as f64;
                let weight = self.framework_weights.get(&framework).unwrap_or(&1.0);
                
                // Compliance score decreases with severity and frequency of violations
                let frequency_penalty = (violation_scores.len() as f64).sqrt() * 0.1;
                let severity_penalty = avg_violation * weight;
                let total_penalty = (frequency_penalty + severity_penalty).min(1.0);
                
                compliance_scores.insert(framework, (1.0 - total_penalty).max(0.0));
            }
        }

        compliance_scores
    }

    /// Calculate privacy risk trend over time using regression analysis.
    fn calculate_privacy_trend(&self, events: &[&PrivacyEvent]) -> f64 {
        if events.len() < 3 {
            return 0.0; // Need at least 3 points for trend
        }

        let now = chrono::Utc::now();
        let mut points: Vec<(f64, f64)> = events
            .iter()
            .map(|event| {
                let hours_ago = now.signed_duration_since(event.timestamp).num_hours() as f64;
                (hours_ago, event.privacy_risk_score)
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
        
        // Normalize slope to [-1, 1] range for interpretation
        // Negative slope = improving privacy (risk decreasing over time)
        // Positive slope = degrading privacy (risk increasing over time)
        (-slope).clamp(-1.0, 1.0)
    }

    /// Calculate total number of affected data subjects.
    fn calculate_affected_data_subjects(&self, events: &[&PrivacyEvent]) -> u32 {
        let mut total_subjects = 0;

        for event in events {
            for data_subject in &event.data_subjects {
                if let Some(count) = data_subject.estimated_count {
                    total_subjects += count;
                }
            }
        }

        total_subjects
    }

    /// Calculate confidence in the privacy assessment.
    fn calculate_privacy_confidence(&self, events: &[&PrivacyEvent]) -> Confidence {
        let sample_size_factor = (events.len() as f64 / self.min_sample_size as f64).min(1.0);
        
        // Average confidence of individual events
        let avg_event_confidence = if !events.is_empty() {
            events.iter().map(|e| e.confidence.value()).sum::<f64>() / events.len() as f64
        } else {
            0.0
        };

        // Data quality factor (events with compliance violations have higher confidence)
        let data_quality_factor = events
            .iter()
            .filter(|e| !e.compliance_violations.is_empty())
            .count() as f64 / events.len() as f64;

        // Temporal coverage factor (events spread over time = better assessment)
        let temporal_coverage = if events.len() > 1 {
            let time_span = events
                .iter()
                .map(|e| e.timestamp)
                .max()
                .unwrap()
                .signed_duration_since(
                    events.iter().map(|e| e.timestamp).min().unwrap()
                )
                .num_hours() as f64;
            
            (time_span / (24.0 * 7.0)).min(1.0) // Normalize to weeks
        } else {
            0.5
        };

        let combined_confidence = sample_size_factor * 0.3 
            + avg_event_confidence * 0.4 
            + data_quality_factor * 0.2 
            + temporal_coverage * 0.1;
        
        Confidence::new(combined_confidence)
    }

    /// Generate human-readable privacy summary.
    fn generate_privacy_summary(
        &self,
        overall_risk: f64,
        violation_counts: &HashMap<ViolationSeverity, u32>,
        compliance_scores: &HashMap<ComplianceFramework, f64>,
        affected_subjects: u32,
    ) -> String {
        let risk_level = match overall_risk {
            r if r >= 0.8 => "High Privacy Risk",
            r if r >= 0.6 => "Medium Privacy Risk", 
            r if r >= 0.4 => "Low Privacy Risk",
            r if r >= 0.2 => "Minimal Privacy Risk",
            _ => "Privacy Compliant",
        };

        let total_violations: u32 = violation_counts.values().sum();
        let critical_violations = violation_counts.get(&ViolationSeverity::Critical).unwrap_or(&0);
        let high_violations = violation_counts.get(&ViolationSeverity::High).unwrap_or(&0);

        let mut summary = format!(
            "{} ({:.1}%). {} violations detected",
            risk_level,
            overall_risk * 100.0,
            total_violations
        );

        if critical_violations > &0 || high_violations > &0 {
            summary.push_str(&format!(
                " ({} critical, {} high severity)",
                critical_violations, high_violations
            ));
        }

        if affected_subjects > 0 {
            summary.push_str(&format!(". {} data subjects affected", affected_subjects));
        }

        // Add compliance framework with lowest score
        if let Some((framework, &score)) = compliance_scores
            .iter()
            .min_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap())
        {
            if score < 0.8 {
                summary.push_str(&format!(
                    ". {:?} compliance: {:.1}%",
                    framework,
                    score * 100.0
                ));
            }
        }

        summary
    }

    /// Detect privacy protection gaps across multiple entities.
    pub fn detect_protection_gaps(&self, events: &[PrivacyEvent]) -> Vec<ProtectionGap> {
        let mut gaps = Vec::new();

        // Group events by protection vector
        let mut vector_events: HashMap<ProtectionVector, Vec<&PrivacyEvent>> = HashMap::new();
        
        for event in events {
            vector_events.entry(event.protection_vector).or_default().push(event);
        }

        // Analyze each protection vector for systemic issues
        for (vector, vector_event_list) in vector_events {
            if vector_event_list.len() >= 3 {
                // Multiple violations in same vector indicate a gap
                let gap = self.analyze_protection_vector_gap(vector, &vector_event_list);
                gaps.push(gap);
            }
        }

        // Sort gaps by severity and affected entity count
        gaps.sort_by(|a, b| {
            b.severity.cmp(&a.severity)
                .then_with(|| b.affected_entities.len().cmp(&a.affected_entities.len()))
        });

        gaps
    }

    /// Analyze a specific protection vector for systemic gaps.
    fn analyze_protection_vector_gap(
        &self,
        vector: ProtectionVector,
        events: &[&PrivacyEvent],
    ) -> ProtectionGap {
        let affected_entities: Vec<EntityId> = events
            .iter()
            .map(|e| e.entity_id)
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        // Calculate average severity
        let avg_risk = events.iter().map(|e| e.privacy_risk_score).sum::<f64>() / events.len() as f64;
        let severity = match avg_risk {
            r if r >= 0.8 => ViolationSeverity::Critical,
            r if r >= 0.6 => ViolationSeverity::High,
            r if r >= 0.4 => ViolationSeverity::Medium,
            r if r >= 0.2 => ViolationSeverity::Low,
            _ => ViolationSeverity::Info,
        };

        // Collect affected compliance frameworks
        let compliance_impact: Vec<ComplianceFramework> = events
            .iter()
            .flat_map(|e| e.compliance_violations.iter().map(|v| v.framework))
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        let (description, remediation_steps, estimated_cost) = self.generate_gap_details(vector, events.len(), &severity);

        ProtectionGap {
            gap_id: format!("{:?}-gap-{}", vector, chrono::Utc::now().timestamp()),
            vector,
            affected_entities,
            severity,
            description,
            remediation_steps,
            estimated_cost,
            compliance_impact,
        }
    }

    fn generate_gap_details(
        &self,
        vector: ProtectionVector,
        violation_count: usize,
        severity: &ViolationSeverity,
    ) -> (String, Vec<String>, Option<f64>) {
        let description = match vector {
            ProtectionVector::Database => {
                format!("Database encryption gaps detected across {} systems", violation_count)
            }
            ProtectionVector::Repository => {
                format!("Credential exposure vulnerabilities in {} repositories", violation_count)
            }
            ProtectionVector::Api => {
                format!("API security weaknesses affecting {} endpoints", violation_count)
            }
            ProtectionVector::Hardware => {
                format!("Hardware security configuration issues on {} devices", violation_count)
            }
            ProtectionVector::SideChannel => {
                format!("Side-channel vulnerabilities detected in {} components", violation_count)
            }
            ProtectionVector::Credential => {
                format!("Credential storage security gaps in {} systems", violation_count)
            }
            ProtectionVector::Network => {
                format!("Network security monitoring gaps across {} segments", violation_count)
            }
            ProtectionVector::Access => {
                format!("Access control policy violations on {} endpoints", violation_count)
            }
        };

        let remediation_steps = match vector {
            ProtectionVector::Database => vec![
                "Implement database encryption at rest".to_string(),
                "Enable automatic key rotation".to_string(),
                "Deploy database activity monitoring".to_string(),
                "Conduct encryption key audit".to_string(),
            ],
            ProtectionVector::Repository => vec![
                "Deploy automated secret scanning".to_string(),
                "Implement pre-commit hooks".to_string(),
                "Rotate all exposed credentials".to_string(),
                "Train developers on secure coding".to_string(),
            ],
            ProtectionVector::Api => vec![
                "Implement OAuth 2.0 with short-lived tokens".to_string(),
                "Enable API rate limiting".to_string(),
                "Deploy API security monitoring".to_string(),
                "Conduct API security assessment".to_string(),
            ],
            ProtectionVector::Hardware => vec![
                "Audit NFC badge configurations".to_string(),
                "Implement USB whitelisting policies".to_string(),
                "Deploy hardware security modules".to_string(),
                "Enable device encryption".to_string(),
            ],
            _ => vec![
                "Conduct security assessment".to_string(),
                "Implement monitoring controls".to_string(),
                "Deploy remediation measures".to_string(),
                "Establish ongoing compliance".to_string(),
            ],
        };

        let estimated_cost = match severity {
            ViolationSeverity::Critical => Some(50_000.0),
            ViolationSeverity::High => Some(25_000.0),
            ViolationSeverity::Medium => Some(10_000.0),
            ViolationSeverity::Low => Some(5_000.0),
            ViolationSeverity::Info => Some(1_000.0),
        };

        (description, remediation_steps, estimated_cost)
    }

    fn default_framework_weights() -> HashMap<ComplianceFramework, f64> {
        let mut weights = HashMap::new();
        weights.insert(ComplianceFramework::Gdpr, 1.2); // Higher weight for GDPR
        weights.insert(ComplianceFramework::Ccpa, 1.0);
        weights.insert(ComplianceFramework::Hipaa, 1.1);
        weights.insert(ComplianceFramework::PciDss, 1.0);
        weights.insert(ComplianceFramework::Soc2, 0.8);
        weights.insert(ComplianceFramework::Iso27001, 0.9);
        weights.insert(ComplianceFramework::NistCsf, 0.7);
        weights
    }
}

impl Default for PrivacyAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ── Privacy compliance assessment ──────────────────────────────────

/// Privacy compliance analyzer for organizational assessment.
#[derive(Debug)]
pub struct ComplianceAnalyzer<'a> {
    graph: &'a Graph,
}

impl<'a> ComplianceAnalyzer<'a> {
    pub fn new(graph: &'a Graph) -> Self {
        Self { graph }
    }

    /// Generate comprehensive privacy compliance report.
    pub fn generate_compliance_report(
        &self,
        entity_profiles: HashMap<EntityId, EntityPrivacyProfile>,
        privacy_events: &[PrivacyEvent],
        privacy_analyzer: &PrivacyAnalyzer,
    ) -> PrivacyComplianceReport {
        let timestamp = chrono::Utc::now();

        // Calculate protection vector coverage
        let vector_coverage = self.calculate_vector_coverage(&entity_profiles);

        // Identify high-risk entities
        let high_risk_entities = self.identify_high_risk_entities(&entity_profiles);

        // Detect protection gaps
        let protection_gaps = privacy_analyzer.detect_protection_gaps(privacy_events);

        // Calculate overall privacy posture
        let privacy_posture_score = self.calculate_privacy_posture(&entity_profiles, &vector_coverage);

        // Calculate framework-specific compliance scores
        let framework_compliance = self.calculate_framework_compliance(&entity_profiles);

        // Generate executive summary
        let executive_summary = self.generate_executive_summary(
            privacy_posture_score,
            &high_risk_entities,
            &protection_gaps,
            &framework_compliance,
        );

        PrivacyComplianceReport {
            timestamp,
            entity_profiles,
            vector_coverage,
            high_risk_entities,
            protection_gaps,
            privacy_posture_score,
            framework_compliance,
            executive_summary,
        }
    }

    /// Calculate coverage levels for each protection vector.
    fn calculate_vector_coverage(
        &self,
        entity_profiles: &HashMap<EntityId, EntityPrivacyProfile>,
    ) -> HashMap<ProtectionVector, f64> {
        let mut vector_totals: HashMap<ProtectionVector, Vec<f64>> = HashMap::new();

        // Collect coverage scores across entities
        for profile in entity_profiles.values() {
            for (vector, &score) in &profile.vector_scores {
                // Convert risk score to coverage score (1.0 - risk = coverage)
                let coverage_score = (1.0 - score).max(0.0);
                vector_totals.entry(*vector).or_default().push(coverage_score);
            }
        }

        // Calculate average coverage for each vector
        vector_totals
            .into_iter()
            .map(|(vector, scores)| {
                let avg_coverage = if !scores.is_empty() {
                    scores.iter().sum::<f64>() / scores.len() as f64
                } else {
                    0.0
                };
                (vector, avg_coverage)
            })
            .collect()
    }

    /// Identify entities with high privacy risk requiring attention.
    fn identify_high_risk_entities(
        &self,
        entity_profiles: &HashMap<EntityId, EntityPrivacyProfile>,
    ) -> Vec<EntityId> {
        let mut high_risk: Vec<(EntityId, f64)> = entity_profiles
            .iter()
            .filter(|(_, profile)| profile.overall_privacy_risk >= 0.6)
            .map(|(id, profile)| (*id, profile.overall_privacy_risk))
            .collect();

        // Sort by privacy risk (highest first)
        high_risk.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());

        // Return top 15 or all if fewer than 15
        high_risk
            .into_iter()
            .take(15)
            .map(|(id, _)| id)
            .collect()
    }

    /// Calculate overall organizational privacy posture score.
    fn calculate_privacy_posture(
        &self,
        entity_profiles: &HashMap<EntityId, EntityPrivacyProfile>,
        vector_coverage: &HashMap<ProtectionVector, f64>,
    ) -> f64 {
        if entity_profiles.is_empty() {
            return 0.0;
        }

        // Entity privacy health component (70% weight)
        let avg_entity_risk: f64 = entity_profiles
            .values()
            .map(|profile| profile.overall_privacy_risk)
            .sum::<f64>() / entity_profiles.len() as f64;
        
        let entity_privacy_health = (1.0 - avg_entity_risk).max(0.0);

        // Vector coverage component (20% weight)
        let avg_vector_coverage: f64 = vector_coverage
            .values()
            .sum::<f64>() / vector_coverage.len().max(1) as f64;

        // Compliance coverage component (10% weight)
        let compliance_coverage = self.calculate_compliance_coverage(entity_profiles);

        // Combine components
        entity_privacy_health * 0.7 + avg_vector_coverage * 0.2 + compliance_coverage * 0.1
    }

    fn calculate_compliance_coverage(&self, entity_profiles: &HashMap<EntityId, EntityPrivacyProfile>) -> f64 {
        if entity_profiles.is_empty() {
            return 0.0;
        }

        let total_compliance_score: f64 = entity_profiles
            .values()
            .flat_map(|profile| profile.compliance_scores.values())
            .sum();
        
        let total_compliance_count = entity_profiles
            .values()
            .map(|profile| profile.compliance_scores.len())
            .sum::<usize>()
            .max(1);

        total_compliance_score / total_compliance_count as f64
    }

    /// Calculate framework-specific compliance scores.
    fn calculate_framework_compliance(
        &self,
        entity_profiles: &HashMap<EntityId, EntityPrivacyProfile>,
    ) -> HashMap<ComplianceFramework, f64> {
        let mut framework_scores: HashMap<ComplianceFramework, Vec<f64>> = HashMap::new();

        // Collect scores by framework across all entities
        for profile in entity_profiles.values() {
            for (framework, &score) in &profile.compliance_scores {
                framework_scores.entry(*framework).or_default().push(score);
            }
        }

        // Calculate average scores for each framework
        framework_scores
            .into_iter()
            .map(|(framework, scores)| {
                let avg_score = if !scores.is_empty() {
                    scores.iter().sum::<f64>() / scores.len() as f64
                } else {
                    0.0
                };
                (framework, avg_score)
            })
            .collect()
    }

    /// Generate executive summary for compliance reporting.
    fn generate_executive_summary(
        &self,
        privacy_posture: f64,
        high_risk_entities: &[EntityId],
        protection_gaps: &[ProtectionGap],
        framework_compliance: &HashMap<ComplianceFramework, f64>,
    ) -> String {
        let posture_level = match privacy_posture {
            s if s >= 0.9 => "Excellent",
            s if s >= 0.8 => "Good",
            s if s >= 0.7 => "Satisfactory",
            s if s >= 0.6 => "Needs Improvement",
            s if s >= 0.4 => "Poor",
            _ => "Critical",
        };

        let mut summary = format!(
            "Privacy posture: {} ({:.1}%). ",
            posture_level,
            privacy_posture * 100.0
        );

        if !high_risk_entities.is_empty() {
            summary.push_str(&format!(
                "{} entities require immediate privacy attention. ",
                high_risk_entities.len()
            ));
        }

        // Highlight critical protection gaps
        let critical_gaps = protection_gaps
            .iter()
            .filter(|gap| gap.severity == ViolationSeverity::Critical)
            .count();
        
        if critical_gaps > 0 {
            summary.push_str(&format!(
                "{} critical data protection gaps identified. ",
                critical_gaps
            ));
        }

        // Highlight lowest compliance framework
        if let Some((framework, &score)) = framework_compliance
            .iter()
            .min_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap())
        {
            if score < 0.8 {
                summary.push_str(&format!(
                    "Lowest compliance: {:?} ({:.1}%). ",
                    framework,
                    score * 100.0
                ));
            }
        }

        summary.push_str("Implement recommended controls to improve privacy posture.");

        summary
    }
}

// ── Default implementation for EntityPrivacyProfile ───────────────

impl EntityPrivacyProfile {
    fn default_for_entity(entity_id: EntityId) -> Self {
        Self {
            entity_id,
            overall_privacy_risk: 0.0,
            vector_scores: HashMap::new(),
            violation_counts: HashMap::new(),
            compliance_scores: HashMap::new(),
            risk_trend: 0.0,
            confidence: Confidence::new(0.0),
            sample_count: 0,
            last_violation_detected: None,
            affected_data_subjects: 0,
            privacy_summary: "No privacy violations detected".to_string(),
        }
    }
}

impl Default for EntityPrivacyProfile {
    fn default() -> Self {
        Self::default_for_entity(EntityId(uuid::Uuid::nil()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::privacy::types::{PrivacyIndicators, ProtectionVector, PrivacyViolationType};

    #[test]
    fn test_privacy_analyzer_creation() {
        let analyzer = PrivacyAnalyzer::new();
        assert_eq!(analyzer.assessment_window_hours, 168 * 4);
        assert!(analyzer.privacy_decay_factor > 0.0);
        assert!(!analyzer.framework_weights.is_empty());
    }

    #[test]
    fn test_privacy_profile_calculation_empty_events() {
        let analyzer = PrivacyAnalyzer::new();
        let profile = analyzer.compute_entity_privacy_profile(&[]);
        assert_eq!(profile.overall_privacy_risk, 0.0);
        assert_eq!(profile.sample_count, 0);
    }

    #[test]
    fn test_compliance_score_calculation() {
        let analyzer = PrivacyAnalyzer::new();
        let entity_id = EntityId(uuid::Uuid::new_v4());
        
        // Create test events with compliance violations
        let mut events = Vec::new();
        let event = PrivacyEvent {
            id: "test-1".to_string(),
            entity_id,
            timestamp: chrono::Utc::now(),
            protection_vector: ProtectionVector::Database,
            violation_type: PrivacyViolationType::UnencryptedDatabase,
            severity: ViolationSeverity::High,
            privacy_risk_score: 0.8,
            confidence: Confidence::new(0.9),
            description: "Test violation".to_string(),
            detection_source: "test".to_string(),
            indicators: PrivacyIndicators {
                database: None,
                repository: None,
                api: None,
                hardware: None,
                side_channel: None,
                credential: None,
                network: None,
                access: None,
            },
            data_subjects: vec![],
            compliance_violations: vec![ComplianceViolation {
                framework: ComplianceFramework::Gdpr,
                article: "Article 32".to_string(),
                requirement: "Encryption".to_string(),
                violation_description: "No encryption".to_string(),
                potential_fine: Some(1000.0),
                remediation_deadline: Some(Duration::from_secs(3600)),
            }],
            investigated: false,
            notes: String::new(),
        };
        events.push(event);
        
        let profile = analyzer.compute_entity_privacy_profile(&events);
        assert_eq!(profile.sample_count, 1);
        assert!(profile.overall_privacy_risk > 0.0);
        assert!(profile.compliance_scores.contains_key(&ComplianceFramework::Gdpr));
    }
}
