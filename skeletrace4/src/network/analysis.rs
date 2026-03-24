//! Network security analysis and compliance assessment for comprehensive infrastructure evaluation.
//!
//! This module provides strategic analysis capabilities for network security posture assessment:
//! - Organizational network security scoring across all infrastructure domains
//! - Compliance framework assessment for NIST CSF, CIS Controls, ISO 27001, and industry standards
//! - Network attack surface analysis with risk prioritization and remediation guidance
//! - Infrastructure security posture trending and executive reporting capabilities
//! - Multi-vector network security correlation for systemic vulnerability identification

use std::collections::HashMap;
use std::time::Duration;

use crate::entity::{Edge, Node};
use crate::graph::Graph;
use crate::metric::Sample;
use crate::network::types::{
    EntityNetworkProfile, NetworkAsset, AssetCriticality,
    NetworkComplianceReport, NetworkSecurityEvent, NetworkSecurityFramework,
    NetworkSecurityVector, NetworkViolationSeverity, NetworkViolationType,
};
use crate::types::{EntityId, Timestamp, MetricId, SourceId};
use crate::metric::SampleValue;
use crate::types::Quality;

// ── Network security posture analyzer ─────────────────────────────

/// Network security posture analysis engine for comprehensive infrastructure assessment.
#[derive(Debug)]
pub struct NetworkSecurityAnalyzer<'a> {
    graph: &'a Graph,
    /// Network security events for analysis.
    events: Vec<NetworkSecurityEvent>,
    /// Network asset inventory for impact assessment.
    assets: HashMap<EntityId, Vec<NetworkAsset>>,
    /// Framework-specific compliance thresholds.
    compliance_thresholds: HashMap<NetworkSecurityFramework, f64>,
}

impl<'a> NetworkSecurityAnalyzer<'a> {
    /// Create a new network security analyzer.
    pub fn new(graph: &'a Graph) -> Self {
        let mut compliance_thresholds = HashMap::new();
        
        // Set compliance thresholds for different frameworks
        compliance_thresholds.insert(NetworkSecurityFramework::NistCsf, 0.8);
        compliance_thresholds.insert(NetworkSecurityFramework::CisControls, 0.85);
        compliance_thresholds.insert(NetworkSecurityFramework::Iso27001, 0.9);
        compliance_thresholds.insert(NetworkSecurityFramework::SansCritical, 0.8);
        compliance_thresholds.insert(NetworkSecurityFramework::Fisma, 0.9);
        compliance_thresholds.insert(NetworkSecurityFramework::PciNss, 0.95);
        compliance_thresholds.insert(NetworkSecurityFramework::Soc2Network, 0.85);

        Self {
            graph,
            events: Vec::new(),
            assets: HashMap::new(),
            compliance_thresholds,
        }
    }

    /// Add network security events for analysis.
    pub fn add_events(&mut self, events: Vec<NetworkSecurityEvent>) {
        self.events.extend(events);
    }

    /// Add network assets for impact assessment.
    pub fn add_assets(&mut self, entity_id: EntityId, assets: Vec<NetworkAsset>) {
        self.assets.insert(entity_id, assets);
    }

    /// Calculate network security posture for a specific entity.
    pub fn calculate_entity_posture(&self, entity_id: EntityId) -> f64 {
        let entity_events: Vec<&NetworkSecurityEvent> = self.events
            .iter()
            .filter(|event| event.entity_id == entity_id)
            .collect();

        if entity_events.is_empty() {
            return 1.0; // Perfect score if no violations
        }

        // Calculate weighted risk score based on severity and recency
        let mut total_risk = 0.0;
        let mut weight_sum = 0.0;
        let now = chrono::Utc::now();

        for event in entity_events {
            let age_hours = (now.timestamp() - event.timestamp.timestamp()) / 3600;
            let recency_weight = (-age_hours as f64 / 168.0).exp(); // Exponential decay over 1 week
            let severity_weight = event.severity.score();
            let confidence_weight = event.confidence.value();
            
            let event_weight = recency_weight * confidence_weight;
            total_risk += event.risk_score * severity_weight * event_weight;
            weight_sum += event_weight;
        }

        let average_risk = if weight_sum > 0.0 {
            total_risk / weight_sum
        } else {
            0.0
        };

        // Convert risk to posture score (higher is better)
        (1.0 - average_risk).max(0.0)
    }

    /// Analyze network security posture across all entities.
    pub fn analyze_network_security_posture(&self) -> NetworkSecurityPostureReport {
        let mut entity_scores = HashMap::new();
        let mut vector_analysis = HashMap::new();
        let mut high_risk_entities = Vec::new();

        // Collect all entities from the graph
        for (entity_id, _node) in &self.graph.nodes {
            let posture_score = self.calculate_entity_posture(*entity_id);
            entity_scores.insert(*entity_id, posture_score);

            if posture_score < 0.6 {
                high_risk_entities.push(*entity_id);
            }
        }

        // Analyze by security vector
        for vector in [
            NetworkSecurityVector::Wireless,
            NetworkSecurityVector::RemoteAccess,
            NetworkSecurityVector::Authentication,
            NetworkSecurityVector::Protocol,
            NetworkSecurityVector::Application,
            NetworkSecurityVector::Directory,
            NetworkSecurityVector::SystemAdmin,
        ] {
            let vector_events: Vec<&NetworkSecurityEvent> = self.events
                .iter()
                .filter(|event| event.security_vector == vector)
                .collect();

            let vector_risk = self.calculate_vector_risk(&vector_events);
            vector_analysis.insert(vector, vector_risk);
        }

        // Calculate overall network security posture
        let overall_posture = if entity_scores.is_empty() {
            1.0
        } else {
            entity_scores.values().sum::<f64>() / entity_scores.len() as f64
        };

        NetworkSecurityPostureReport {
            overall_posture,
            entity_scores,
            vector_analysis,
            high_risk_entities,
            total_events: self.events.len(),
            critical_events: self.events.iter()
                .filter(|e| e.severity == NetworkViolationSeverity::Critical)
                .count(),
            generated_at: chrono::Utc::now(),
        }
    }

    /// Calculate risk score for a specific security vector.
    fn calculate_vector_risk(&self, events: &[&NetworkSecurityEvent]) -> f64 {
        if events.is_empty() {
            return 0.0;
        }

        let total_risk: f64 = events.iter()
            .map(|event| event.risk_score * event.severity.score())
            .sum();

        total_risk / events.len() as f64
    }

    /// Generate network security metrics for Skeletrace.
    pub fn generate_network_metrics(&self) -> Vec<Sample> {
        let mut samples = Vec::new();
        let now = chrono::Utc::now();

        // Overall network security posture metric
        let posture_report = self.analyze_network_security_posture();
        samples.push(Sample {
            metric_id: MetricId(uuid::Uuid::new_v4()),
            entity_id: EntityId(uuid::Uuid::new_v4()), // Global metric placeholder
            timestamp: now,
            value: SampleValue::Numeric(posture_report.overall_posture),
            quality: Quality::default(),
            source_id: SourceId(uuid::Uuid::new_v4()),
        });

        // Per-entity network security metrics
        for (entity_id, score) in posture_report.entity_scores {
            samples.push(Sample {
                metric_id: MetricId(uuid::Uuid::new_v4()),
                entity_id,
                timestamp: now,
                value: SampleValue::Numeric(score),
                quality: Quality::default(),
                source_id: SourceId(uuid::Uuid::new_v4()),
            });
        }

        // Per-vector risk metrics
        for (vector, risk) in posture_report.vector_analysis {
            samples.push(Sample {
                metric_id: MetricId(uuid::Uuid::new_v4()),
                entity_id: EntityId(uuid::Uuid::new_v4()), // Global vector metric
                timestamp: now,
                value: SampleValue::Numeric(risk),
                quality: Quality::default(),
                source_id: SourceId(uuid::Uuid::new_v4()),
            });
        }

        samples
    }

    /// Identify network security protection gaps.
    pub fn identify_protection_gaps(&self) -> Vec<NetworkProtectionGap> {
        let mut gaps = Vec::new();

        // Analyze coverage gaps by security vector
        let vector_coverage = self.analyze_vector_coverage();
        for (vector, coverage) in vector_coverage {
            if coverage < 0.7 {
                gaps.push(NetworkProtectionGap {
                    gap_type: NetworkGapType::VectorUndercoverage,
                    description: format!("{:?} security vector has insufficient coverage", vector),
                    affected_vector: Some(vector),
                    risk_level: self.calculate_gap_risk(coverage),
                    remediation_priority: if coverage < 0.3 { 1 } else { 2 },
                    estimated_remediation_time: Duration::from_secs(7 * 24 * 3600), // 1 week
                });
            }
        }

        // Analyze asset protection gaps
        let asset_gaps = self.analyze_asset_protection_gaps();
        gaps.extend(asset_gaps);

        // Analyze compliance gaps
        let compliance_gaps = self.analyze_compliance_gaps();
        gaps.extend(compliance_gaps);

        // Sort by priority and risk level
        gaps.sort_by(|a, b| {
            a.remediation_priority.cmp(&b.remediation_priority)
                .then(b.risk_level.partial_cmp(&a.risk_level).unwrap_or(std::cmp::Ordering::Equal))
        });

        gaps
    }

    /// Analyze security vector coverage.
    fn analyze_vector_coverage(&self) -> HashMap<NetworkSecurityVector, f64> {
        let mut coverage = HashMap::new();
        let total_entities = self.graph.nodes.len() as f64;

        if total_entities == 0.0 {
            return coverage;
        }

        for vector in [
            NetworkSecurityVector::Wireless,
            NetworkSecurityVector::RemoteAccess,
            NetworkSecurityVector::Authentication,
            NetworkSecurityVector::Protocol,
            NetworkSecurityVector::Application,
            NetworkSecurityVector::Directory,
            NetworkSecurityVector::SystemAdmin,
        ] {
            let monitored_entities = self.events.iter()
                .filter(|event| event.security_vector == vector)
                .map(|event| event.entity_id)
                .collect::<std::collections::HashSet<_>>()
                .len() as f64;

            let coverage_ratio = monitored_entities / total_entities;
            coverage.insert(vector, coverage_ratio);
        }

        coverage
    }

    /// Analyze asset protection gaps.
    fn analyze_asset_protection_gaps(&self) -> Vec<NetworkProtectionGap> {
        let mut gaps = Vec::new();

        for (entity_id, assets) in &self.assets {
            for asset in assets {
                if asset.criticality == AssetCriticality::Critical || asset.criticality == AssetCriticality::High {
                    let asset_events = self.events.iter()
                        .filter(|event| event.entity_id == *entity_id)
                        .count();

                    if asset_events == 0 {
                        gaps.push(NetworkProtectionGap {
                            gap_type: NetworkGapType::UnmonitoredCriticalAsset,
                            description: format!("Critical asset {} lacks network security monitoring", asset.id),
                            affected_vector: None,
                            risk_level: asset.criticality.impact_multiplier(),
                            remediation_priority: 1,
                            estimated_remediation_time: Duration::from_secs(3 * 24 * 3600), // 3 days
                        });
                    }
                }
            }
        }

        gaps
    }

    /// Analyze compliance framework gaps.
    fn analyze_compliance_gaps(&self) -> Vec<NetworkProtectionGap> {
        let mut gaps = Vec::new();
        let compliance_scores = self.calculate_compliance_scores();

        for (framework, score) in compliance_scores {
            if let Some(&threshold) = self.compliance_thresholds.get(&framework) {
                if score < threshold {
                    gaps.push(NetworkProtectionGap {
                        gap_type: NetworkGapType::ComplianceDeficiency,
                        description: format!("{:?} compliance score ({:.1}%) below threshold ({:.1}%)",
                                           framework, score * 100.0, threshold * 100.0),
                        affected_vector: None,
                        risk_level: (threshold - score) * 10.0, // Scale to 0-10
                        remediation_priority: if score < 0.5 { 1 } else { 2 },
                        estimated_remediation_time: Duration::from_secs(14 * 24 * 3600), // 2 weeks
                    });
                }
            }
        }

        gaps
    }

    /// Calculate compliance scores for all frameworks.
    fn calculate_compliance_scores(&self) -> HashMap<NetworkSecurityFramework, f64> {
        let mut scores = HashMap::new();

        for &framework in &[
            NetworkSecurityFramework::NistCsf,
            NetworkSecurityFramework::CisControls,
            NetworkSecurityFramework::Iso27001,
            NetworkSecurityFramework::SansCritical,
            NetworkSecurityFramework::Fisma,
            NetworkSecurityFramework::PciNss,
            NetworkSecurityFramework::Soc2Network,
        ] {
            let framework_events: Vec<&NetworkSecurityEvent> = self.events.iter()
                .filter(|event| {
                    event.compliance_violations.iter()
                        .any(|violation| violation.framework == framework)
                })
                .collect();

            let compliance_score = if framework_events.is_empty() {
                1.0 // Perfect compliance if no violations
            } else {
                let violation_impact: f64 = framework_events.iter()
                    .map(|event| event.risk_score * event.severity.score())
                    .sum();
                let max_possible_impact = framework_events.len() as f64;
                
                (max_possible_impact - violation_impact) / max_possible_impact
            };

            scores.insert(framework, compliance_score.max(0.0));
        }

        scores
    }

    /// Calculate risk level for a protection gap.
    fn calculate_gap_risk(&self, coverage: f64) -> f64 {
        // Higher risk for lower coverage
        (1.0 - coverage) * 10.0
    }
}

/// Network security posture assessment report.
#[derive(Debug)]
pub struct NetworkSecurityPostureReport {
    /// Overall network security posture score (0.0-1.0).
    pub overall_posture: f64,
    /// Per-entity posture scores.
    pub entity_scores: HashMap<EntityId, f64>,
    /// Risk analysis by security vector.
    pub vector_analysis: HashMap<NetworkSecurityVector, f64>,
    /// Entities with high security risk.
    pub high_risk_entities: Vec<EntityId>,
    /// Total number of security events.
    pub total_events: usize,
    /// Number of critical security events.
    pub critical_events: usize,
    /// Report generation timestamp.
    pub generated_at: Timestamp,
}

/// Network protection gap analysis.
#[derive(Debug)]
pub struct NetworkProtectionGap {
    /// Type of protection gap.
    pub gap_type: NetworkGapType,
    /// Detailed gap description.
    pub description: String,
    /// Affected security vector (if applicable).
    pub affected_vector: Option<NetworkSecurityVector>,
    /// Risk level (0.0-10.0).
    pub risk_level: f64,
    /// Remediation priority (1=urgent, 2=high, 3=medium, 4=low).
    pub remediation_priority: u8,
    /// Estimated time to remediate.
    pub estimated_remediation_time: Duration,
}

/// Types of network protection gaps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkGapType {
    /// Security vector has insufficient monitoring coverage.
    VectorUndercoverage,
    /// Critical assets lack security monitoring.
    UnmonitoredCriticalAsset,
    /// Compliance framework requirements not met.
    ComplianceDeficiency,
    /// Security policy enforcement gaps.
    PolicyEnforcementGap,
    /// Incident response capability gaps.
    IncidentResponseGap,
}

// ── Network compliance analyzer ───────────────────────────────────

/// Network security compliance assessment engine for regulatory frameworks.
#[derive(Debug)]
pub struct NetworkComplianceAnalyzer<'a> {
    graph: &'a Graph,
    /// Security events for compliance analysis.
    events: Vec<NetworkSecurityEvent>,
    /// Framework-specific requirements mapping.
    framework_requirements: HashMap<NetworkSecurityFramework, Vec<String>>,
}

impl<'a> NetworkComplianceAnalyzer<'a> {
    /// Create a new network compliance analyzer.
    pub fn new(graph: &'a Graph) -> Self {
        let mut framework_requirements = HashMap::new();

        // NIST Cybersecurity Framework requirements
        framework_requirements.insert(
            NetworkSecurityFramework::NistCsf,
            vec![
                "PR.DS-1: Data-in-transit is protected".to_string(),
                "PR.DS-2: Data-in-transit is protected".to_string(),
                "PR.AC-7: Users and devices are authenticated".to_string(),
                "DE.CM-1: The network is monitored to detect potential cybersecurity events".to_string(),
                "PR.IP-12: A vulnerability management plan is developed and implemented".to_string(),
            ]
        );

        // CIS Controls requirements
        framework_requirements.insert(
            NetworkSecurityFramework::CisControls,
            vec![
                "CIS Control 3: Continuous Vulnerability Management".to_string(),
                "CIS Control 4: Controlled Use of Administrative Privileges".to_string(),
                "CIS Control 12: Boundary Defense".to_string(),
                "CIS Control 15: Wireless Access Control".to_string(),
                "CIS Control 16: Account Monitoring and Control".to_string(),
            ]
        );

        Self {
            graph,
            events: Vec::new(),
            framework_requirements,
        }
    }

    /// Add security events for compliance analysis.
    pub fn add_events(&mut self, events: Vec<NetworkSecurityEvent>) {
        self.events.extend(events);
    }

    /// Generate comprehensive compliance report.
    pub fn generate_compliance_report(&self) -> NetworkComplianceReport {
        let framework_scores = self.calculate_all_framework_scores();
        let high_risk_entities = self.identify_high_risk_entities();
        let protection_gaps = self.analyze_protection_gaps();
        
        let network_security_posture = framework_scores.values().sum::<f64>() / framework_scores.len() as f64;

        NetworkComplianceReport {
            network_security_posture,
            framework_scores: framework_scores.clone(),
            high_risk_entities,
            protection_gaps,
            executive_summary: self.generate_executive_summary(&framework_scores),
            generated_at: chrono::Utc::now(),
        }
    }

    /// Calculate compliance scores for all frameworks.
    fn calculate_all_framework_scores(&self) -> HashMap<NetworkSecurityFramework, f64> {
        let mut scores = HashMap::new();

        for &framework in &[
            NetworkSecurityFramework::NistCsf,
            NetworkSecurityFramework::CisControls,
            NetworkSecurityFramework::Iso27001,
            NetworkSecurityFramework::SansCritical,
            NetworkSecurityFramework::Fisma,
            NetworkSecurityFramework::PciNss,
            NetworkSecurityFramework::Soc2Network,
        ] {
            let score = self.calculate_framework_compliance(framework);
            scores.insert(framework, score);
        }

        scores
    }

    /// Calculate compliance score for a specific framework.
    fn calculate_framework_compliance(&self, framework: NetworkSecurityFramework) -> f64 {
        let framework_violations: Vec<&NetworkSecurityEvent> = self.events.iter()
            .filter(|event| {
                event.compliance_violations.iter()
                    .any(|violation| violation.framework == framework)
            })
            .collect();

        if framework_violations.is_empty() {
            return 1.0; // Perfect compliance
        }

        // Calculate weighted compliance score
        let total_violation_weight: f64 = framework_violations.iter()
            .map(|event| {
                let severity_weight = event.severity.score();
                let confidence_weight = event.confidence.value();
                let risk_weight = event.risk_score;
                severity_weight * confidence_weight * risk_weight
            })
            .sum();

        let max_possible_weight = framework_violations.len() as f64;
        let compliance_score = (max_possible_weight - total_violation_weight) / max_possible_weight;

        compliance_score.max(0.0).min(1.0)
    }

    /// Identify entities with high compliance risk.
    fn identify_high_risk_entities(&self) -> Vec<EntityId> {
        let mut entity_risk_scores: HashMap<EntityId, f64> = HashMap::new();

        for event in &self.events {
            let current_risk = entity_risk_scores.get(&event.entity_id).unwrap_or(&0.0);
            let event_risk = event.risk_score * event.severity.score();
            entity_risk_scores.insert(event.entity_id, current_risk + event_risk);
        }

        // Return entities with risk score above threshold
        entity_risk_scores.iter()
            .filter(|(_, &risk)| risk > 2.0) // Threshold for high risk
            .map(|(&entity_id, _)| entity_id)
            .collect()
    }

    /// Analyze protection gaps for compliance.
    fn analyze_protection_gaps(&self) -> Vec<String> {
        let mut gaps = Vec::new();

        // Analyze gaps by violation type frequency
        let mut violation_counts: HashMap<NetworkViolationType, usize> = HashMap::new();
        for event in &self.events {
            *violation_counts.entry(event.violation_type).or_insert(0) += 1;
        }

        for (violation_type, count) in violation_counts {
            if count >= 3 { // Threshold for systemic issue
                gaps.push(format!("Systemic issue: {:?} violations detected {} times", violation_type, count));
            }
        }

        // Analyze vector coverage gaps
        let vector_counts: HashMap<NetworkSecurityVector, usize> = self.events.iter()
            .fold(HashMap::new(), |mut acc, event| {
                *acc.entry(event.security_vector).or_insert(0) += 1;
                acc
            });

        let expected_vectors = 7; // Total number of security vectors
        if vector_counts.len() < expected_vectors {
            gaps.push(format!("Coverage gap: Only {}/{} security vectors have monitoring", vector_counts.len(), expected_vectors));
        }

        gaps
    }

    /// Generate executive summary for compliance report.
    fn generate_executive_summary(&self, framework_scores: &HashMap<NetworkSecurityFramework, f64>) -> String {
        let avg_score = framework_scores.values().sum::<f64>() / framework_scores.len() as f64;
        let critical_events = self.events.iter()
            .filter(|e| e.severity == NetworkViolationSeverity::Critical)
            .count();

        let status = match avg_score {
            s if s >= 0.9 => "Excellent",
            s if s >= 0.8 => "Good", 
            s if s >= 0.7 => "Acceptable",
            s if s >= 0.6 => "Poor",
            _ => "Critical",
        };

        format!("Network security compliance: {} ({:.1}%). {} total violations, {} critical. \
                Immediate attention required for: {}",
                status,
                avg_score * 100.0,
                self.events.len(),
                critical_events,
                if critical_events > 0 { "critical vulnerabilities" } else { "compliance gaps" })
    }
}
