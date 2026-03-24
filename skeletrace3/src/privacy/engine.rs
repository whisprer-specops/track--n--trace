//! Main privacy engine — orchestrates comprehensive data protection and compliance monitoring.
//!
//! This is the central coordinator that manages:
//! - Data protection target monitoring across multiple privacy vectors
//! - Privacy violation detection using specialized analyzers
//! - Compliance assessment and regulatory framework scoring
//! - Data protection gap analysis and remediation prioritization
//! - Integration with Skeletrace's graph and metric systems for privacy posture evaluation
//!
//! Designed to implement data protection patterns from all major regulatory frameworks while
//! providing unified privacy monitoring and compliance reporting.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use log::{debug, info, warn};

use crate::graph::Graph;
use crate::metric::{Sample, SampleValue};
use crate::privacy::analysis::{ComplianceAnalyzer, PrivacyAnalyzer};
use crate::privacy::detection::{
    ApiDetector, ApiRequestData, DatabaseConfig, DatabaseDetector, HardwareData, HardwareDetector, RepositoryData, RepositoryDetector,
};
use crate::privacy::types::{
    ComplianceFramework, EntityPrivacyProfile, PrivacyComplianceReport, PrivacyEvent,
    PrivacyMonitoringType, PrivacyTarget, PrivacyViolationType, ProtectionVector,
    ViolationSeverity,
};
use crate::types::{EntityId, MetricId, Quality, SourceId};

// ── Privacy engine configuration ───────────────────────────────────

/// Configuration for the privacy monitoring engine.
#[derive(Debug, Clone)]
pub struct PrivacyEngineConfig {
    /// Maximum privacy events to store per entity.
    pub max_events_per_entity: usize,
    /// Privacy assessment window size (number of events).
    pub privacy_window_size: usize,
    /// How often to run compliance analysis.
    pub compliance_analysis_interval: Duration,
    /// Privacy risk threshold for alerting.
    pub alert_risk_threshold: f64,
    /// Minimum compliance score threshold.
    pub min_compliance_threshold: f64,
    /// Source ID for privacy-generated metrics.
    pub source_id: SourceId,
}

impl Default for PrivacyEngineConfig {
    fn default() -> Self {
        Self {
            max_events_per_entity: 500,
            privacy_window_size: 100,
            compliance_analysis_interval: Duration::from_secs(3600), // 1 hour
            alert_risk_threshold: 0.7,
            min_compliance_threshold: 0.8,
            source_id: SourceId(uuid::Uuid::nil()), // Replace with real UUID
        }
    }
}

// ── Main privacy engine ────────────────────────────────────────────

/// Comprehensive data protection and privacy compliance monitoring engine.
///
/// Orchestrates privacy violation detection, risk analysis, and compliance
/// assessment for entities in a Skeletrace graph.
pub struct PrivacyEngine {
    /// Engine configuration.
    config: PrivacyEngineConfig,
    /// Privacy detection components.
    database_detector: DatabaseDetector,
    repository_detector: RepositoryDetector,
    api_detector: ApiDetector,
    hardware_detector: HardwareDetector,
    /// Privacy analysis components.
    privacy_analyzer: PrivacyAnalyzer,
    /// Active privacy targets.
    targets: HashMap<EntityId, PrivacyTarget>,
    /// Privacy event history (per entity).
    privacy_events: HashMap<EntityId, Vec<PrivacyEvent>>,
    /// Last monitoring times (for scheduling).
    last_monitor_times: HashMap<EntityId, Instant>,
    /// Last compliance analysis time.
    last_compliance_analysis: Option<Instant>,
    /// Current entity privacy profiles.
    entity_profiles: HashMap<EntityId, EntityPrivacyProfile>,
    /// High-priority privacy alerts pending investigation.
    pending_privacy_alerts: Vec<PrivacyAlert>,
}

impl PrivacyEngine {
    /// Create a new privacy engine with default configuration.
    pub fn new() -> Self {
        Self::with_config(PrivacyEngineConfig::default())
    }

    /// Create a new privacy engine with custom configuration.
    pub fn with_config(config: PrivacyEngineConfig) -> Self {
        let privacy_analyzer = PrivacyAnalyzer::with_window_hours(
            (config.compliance_analysis_interval.as_secs() / 3600) as u32
        );

        Self {
            config,
            database_detector: DatabaseDetector::new(),
            repository_detector: RepositoryDetector::new(),
            api_detector: ApiDetector::new(),
            hardware_detector: HardwareDetector::new(),
            privacy_analyzer,
            targets: HashMap::new(),
            privacy_events: HashMap::new(),
            last_monitor_times: HashMap::new(),
            last_compliance_analysis: None,
            entity_profiles: HashMap::new(),
            pending_privacy_alerts: Vec::new(),
        }
    }

    // ── Target management ──────────────────────────────────────────

    /// Add a privacy target for monitoring.
    pub fn add_target(&mut self, target: PrivacyTarget) {
        info!(
            "Added privacy target: {} -> {:?}",
            target.label, target.monitoring_type
        );
        self.targets.insert(target.entity_id, target);
    }

    /// Remove a privacy target.
    pub fn remove_target(&mut self, entity_id: &EntityId) -> Option<PrivacyTarget> {
        let removed = self.targets.remove(entity_id);
        if removed.is_some() {
            info!("Removed privacy target for entity {:?}", entity_id);
            // Clean up associated data
            self.privacy_events.remove(entity_id);
            self.last_monitor_times.remove(entity_id);
            self.entity_profiles.remove(entity_id);
        }
        removed
    }

    /// Get all active privacy targets.
    pub fn targets(&self) -> &HashMap<EntityId, PrivacyTarget> {
        &self.targets
    }

    // ── Privacy violation detection ────────────────────────────────

    /// Execute privacy violation detection across all targets.
    ///
    /// This checks all targets, executes privacy monitoring that is due,
    /// updates risk assessments, and returns the number of detections executed.
    pub fn execute_privacy_cycle(&mut self) -> PrivacyCycleResult {
        let now = Instant::now();
        let mut detections_executed = 0;
        let mut violations_detected = 0;
        let mut new_privacy_alerts = 0;

        // Collect targets that are due for monitoring
        let due_targets: Vec<EntityId> = self
            .targets
            .iter()
            .filter(|(entity_id, target)| {
                target.enabled && self.is_target_due(**entity_id, target, now)
            })
            .map(|(entity_id, _)| *entity_id)
            .collect();

        // Execute privacy monitoring for due targets
        for entity_id in due_targets {
            if let Some(target) = self.targets.get(&entity_id).cloned() {
                if let Some(privacy_event) = self.execute_target_privacy_monitoring(&target) {
                    self.record_privacy_event(privacy_event.clone());
                    violations_detected += 1;

                    // Check if this generates a new privacy alert
                    if privacy_event.privacy_risk_score >= self.config.alert_risk_threshold {
                        let alert = self.create_privacy_alert(&privacy_event);
                        self.pending_privacy_alerts.push(alert);
                        new_privacy_alerts += 1;
                    }
                }
                self.last_monitor_times.insert(entity_id, now);
                detections_executed += 1;
            }
        }

        // Update entity privacy profiles
        self.update_entity_privacy_profiles();

        PrivacyCycleResult {
            detections_executed,
            violations_detected,
            new_privacy_alerts,
        }
    }

    /// Check if a target is due for privacy monitoring.
    fn is_target_due(&self, entity_id: EntityId, target: &PrivacyTarget, now: Instant) -> bool {
        match self.last_monitor_times.get(&entity_id) {
            Some(&last_time) => now.duration_since(last_time) >= target.config.check_interval,
            None => true, // Never monitored before
        }
    }

    /// Execute privacy monitoring for a specific target.
    fn execute_target_privacy_monitoring(&mut self, target: &PrivacyTarget) -> Option<PrivacyEvent> {
        debug!(
            "Executing privacy monitoring for {:?}: {:?}",
            target.entity_id, target.monitoring_type
        );

        match target.monitoring_type {
            PrivacyMonitoringType::DatabaseEncryption => {
                // In a real implementation, this would connect to database and check configuration
                if let Some(database_config) = self.simulate_database_config(target) {
                    self.database_detector.analyze_database(target.entity_id, &database_config)
                } else {
                    None
                }
            }
            PrivacyMonitoringType::RepositoryScanning => {
                // In a real implementation, this would clone and scan repository
                if let Some(repository_data) = self.simulate_repository_data(target) {
                    self.repository_detector.analyze_repository(target.entity_id, &repository_data)
                } else {
                    None
                }
            }
            PrivacyMonitoringType::ApiTokenValidation => {
                // OAuth token validation monitoring
                if let Some(api_data) = self.simulate_api_data(target) {
                    self.api_detector.analyze_api_request(target.entity_id, &api_data)
                } else {
                    None
                }
            }
            PrivacyMonitoringType::HardwareSecurityAudit => {
                // Hardware security audit
                if let Some(hardware_data) = self.simulate_hardware_data(target) {
                    self.hardware_detector.analyze_hardware(target.entity_id, &hardware_data)
                } else {
                    None
                }
            }
            _ => {
                // Other monitoring types would be implemented here
                debug!("Privacy monitoring type {:?} not yet implemented", target.monitoring_type);
                None
            }
        }
    }

    /// Record a privacy event and update history.
    fn record_privacy_event(&mut self, event: PrivacyEvent) {
        debug!(
            "Recording privacy event: {:?} for {:?}",
            event.violation_type, event.entity_id
        );

        // Add to history
        let history = self.privacy_events.entry(event.entity_id).or_default();
        history.push(event);

        // Trim history to reasonable size
        if history.len() > self.config.max_events_per_entity {
            history.drain(0..history.len() - self.config.max_events_per_entity);
        }
    }

    /// Update entity privacy profiles from recent privacy events.
    fn update_entity_privacy_profiles(&mut self) {
        for (entity_id, events) in &self.privacy_events {
            let privacy_profile = self.privacy_analyzer.compute_entity_privacy_profile(events);
            self.entity_profiles.insert(*entity_id, privacy_profile);
        }
    }

    /// Create a privacy alert from a privacy event.
    fn create_privacy_alert(&self, event: &PrivacyEvent) -> PrivacyAlert {
        let urgency = match event.severity {
            ViolationSeverity::Critical => AlertUrgency::Critical,
            ViolationSeverity::High => AlertUrgency::High,
            ViolationSeverity::Medium => AlertUrgency::Medium,
            _ => AlertUrgency::Low,
        };

        let mut compliance_impact = Vec::new();
        for violation in &event.compliance_violations {
            compliance_impact.push(violation.framework);
        }

        PrivacyAlert {
            id: event.id.clone(),
            entity_id: event.entity_id,
            urgency,
            title: format!("{:?} detected", event.violation_type),
            description: event.description.clone(),
            privacy_risk_score: event.privacy_risk_score,
            compliance_impact,
            data_subjects_affected: event.data_subjects.iter()
                .map(|ds| ds.estimated_count.unwrap_or(0))
                .sum(),
            created_at: event.timestamp,
            acknowledged: false,
            assigned_to: None,
        }
    }

    // ── Compliance analysis ────────────────────────────────────────

    /// Run full compliance analysis if due.
    ///
    /// This performs comprehensive privacy assessment and generates
    /// a compliance report. Returns a report if analysis was performed.
    pub fn analyze_compliance(&mut self, graph: &Graph) -> Option<PrivacyComplianceReport> {
        let now = Instant::now();

        // Check if compliance analysis is due
        let analysis_due = match self.last_compliance_analysis {
            Some(last) => now.duration_since(last) >= self.config.compliance_analysis_interval,
            None => true,
        };

        if !analysis_due {
            return None;
        }

        info!("Running privacy compliance analysis...");

        let compliance_analyzer = ComplianceAnalyzer::new(graph);

        // Collect all privacy events for gap analysis
        let all_events: Vec<PrivacyEvent> = self
            .privacy_events
            .values()
            .flat_map(|events| events.iter())
            .cloned()
            .collect();

        // Generate comprehensive compliance report
        let report = compliance_analyzer.generate_compliance_report(
            self.entity_profiles.clone(),
            &all_events,
            &self.privacy_analyzer,
        );

        // Log key findings
        info!(
            "Privacy compliance analysis complete: {:.1}% privacy posture, {} high-risk entities",
            report.privacy_posture_score * 100.0,
            report.high_risk_entities.len()
        );

        if !report.protection_gaps.is_empty() {
            warn!(
                "Identified {} data protection gaps: {:?}",
                report.protection_gaps.len(),
                report
                    .protection_gaps
                    .iter()
                    .map(|g| &g.gap_id)
                    .collect::<Vec<_>>()
            );
        }

        // Check compliance framework scores
        for (framework, &score) in &report.framework_compliance {
            if score < self.config.min_compliance_threshold {
                warn!(
                    "{:?} compliance below threshold: {:.1}% (target: {:.1}%)",
                    framework,
                    score * 100.0,
                    self.config.min_compliance_threshold * 100.0
                );
            }
        }

        self.last_compliance_analysis = Some(now);
        Some(report)
    }

    // ── Metric integration ─────────────────────────────────────────

    /// Generate Skeletrace metric samples from current privacy state.
    ///
    /// This allows privacy results to feed into the broader metric system.
    pub fn generate_metric_samples(&self) -> Vec<Sample> {
        let mut samples = Vec::new();
        let now = chrono::Utc::now();

        for (entity_id, privacy_profile) in &self.entity_profiles {
            // Overall privacy risk score metric
            samples.push(Sample {
                metric_id: MetricId(uuid::Uuid::nil()), // Replace with real privacy risk metric ID
                entity_id: *entity_id,
                timestamp: now,
                value: SampleValue::Numeric(privacy_profile.overall_privacy_risk),
                quality: Quality::new(privacy_profile.confidence.value()),
                source_id: self.config.source_id,
            });

            // Data subjects affected metric
            samples.push(Sample {
                metric_id: MetricId(uuid::Uuid::nil()), // Replace with real data subjects metric ID
                entity_id: *entity_id,
                timestamp: now,
                value: SampleValue::Numeric(privacy_profile.affected_data_subjects as f64),
                quality: Quality::new(privacy_profile.confidence.value()),
                source_id: self.config.source_id,
            });

            // Privacy trend metric
            samples.push(Sample {
                metric_id: MetricId(uuid::Uuid::nil()), // Replace with real trend metric ID
                entity_id: *entity_id,
                timestamp: now,
                value: SampleValue::Numeric(privacy_profile.risk_trend),
                quality: Quality::new(privacy_profile.confidence.value()),
                source_id: self.config.source_id,
            });

            // Compliance scores for major frameworks
            for (framework, &score) in &privacy_profile.compliance_scores {
                if matches!(framework, ComplianceFramework::Gdpr | ComplianceFramework::Ccpa | ComplianceFramework::Hipaa) {
                    samples.push(Sample {
                        metric_id: MetricId(uuid::Uuid::nil()), // Replace with framework-specific metric ID
                        entity_id: *entity_id,
                        timestamp: now,
                        value: SampleValue::Numeric(score),
                        quality: Quality::new(privacy_profile.confidence.value()),
                        source_id: self.config.source_id,
                    });
                }
            }
        }

        samples
    }

    // ── Alert management ───────────────────────────────────────────

    /// Get all pending privacy alerts.
    pub fn get_pending_privacy_alerts(&self) -> &[PrivacyAlert] {
        &self.pending_privacy_alerts
    }

    /// Acknowledge a privacy alert.
    pub fn acknowledge_privacy_alert(&mut self, alert_id: &str, assigned_to: Option<String>) {
        if let Some(alert) = self.pending_privacy_alerts.iter_mut().find(|a| a.id == alert_id) {
            alert.acknowledged = true;
            alert.assigned_to = assigned_to;
            info!("Acknowledged privacy alert: {}", alert_id);
        }
    }

    /// Remove acknowledged alerts older than specified duration.
    pub fn cleanup_old_privacy_alerts(&mut self, max_age: Duration) {
        let cutoff = chrono::Utc::now() - chrono::Duration::from_std(max_age).unwrap();
        
        let initial_count = self.pending_privacy_alerts.len();
        self.pending_privacy_alerts.retain(|alert| {
            !alert.acknowledged || alert.created_at > cutoff
        });
        
        let removed_count = initial_count - self.pending_privacy_alerts.len();
        if removed_count > 0 {
            debug!("Cleaned up {} old acknowledged privacy alerts", removed_count);
        }
    }

    // ── Status queries ─────────────────────────────────────────────

    /// Get current privacy profile for a specific entity.
    pub fn get_entity_privacy_profile(&self, entity_id: &EntityId) -> Option<&EntityPrivacyProfile> {
        self.entity_profiles.get(entity_id)
    }

    /// Get privacy event history for an entity.
    pub fn get_privacy_history(&self, entity_id: &EntityId) -> Option<&[PrivacyEvent]> {
        self.privacy_events.get(entity_id).map(|v| v.as_slice())
    }

    /// Get summary statistics.
    pub fn stats(&self) -> PrivacyEngineStats {
        let total_events = self.privacy_events.values().map(|h| h.len()).sum();
        let active_targets = self.targets.len();
        let high_risk_entities = self
            .entity_profiles
            .values()
            .filter(|p| p.overall_privacy_risk >= 0.6)
            .count();
        
        let critical_privacy_alerts = self
            .pending_privacy_alerts
            .iter()
            .filter(|a| a.urgency == AlertUrgency::Critical && !a.acknowledged)
            .count();

        let total_data_subjects_affected = self
            .entity_profiles
            .values()
            .map(|p| p.affected_data_subjects)
            .sum();

        PrivacyEngineStats {
            active_targets,
            total_privacy_events: total_events,
            high_risk_entities,
            total_entities: self.entity_profiles.len(),
            pending_privacy_alerts: self.pending_privacy_alerts.iter().filter(|a| !a.acknowledged).count(),
            critical_privacy_alerts,
            total_data_subjects_affected,
        }
    }

    // ── Simulation helpers (for demo purposes) ─────────────────────

    /// Simulate database configuration for demonstration purposes.
    fn simulate_database_config(&self, _target: &PrivacyTarget) -> Option<DatabaseConfig> {
        // Occasionally simulate database configuration issues
        if rand::random::<f64>() < 0.15 {
            Some(DatabaseConfig {
                database_type: "PostgreSQL".to_string(),
                connection_string: Some("postgresql://user:pass@localhost/db".to_string()),
                encryption_enabled: false, // Violation!
                encryption_algorithm: None,
                key_rotation_enabled: false,
                key_age_days: Some(500), // Too old
                key_storage_method: Some("filesystem".to_string()), // Not secure
                compliance_requirements: vec!["GDPR".to_string(), "PCI-DSS".to_string()],
                audit_logging_enabled: false, // Violation!
                access_controls: vec!["basic_auth".to_string()],
                plaintext_fields: 3, // Personal data stored in plaintext
                certificate_expired: Some(true),
            })
        } else {
            None
        }
    }

    /// Simulate repository data for demonstration.
    fn simulate_repository_data(&self, _target: &PrivacyTarget) -> Option<RepositoryData> {
        // Occasionally simulate repository with exposed credentials
        if rand::random::<f64>() < 0.1 {
            use crate::privacy::detection::{RepositoryData, RepositoryFile, CommitInfo};
            
            Some(RepositoryData {
                url: "https://github.com/company/webapp".to_string(),
                repo_type: "git".to_string(),
                branch: "main".to_string(),
                latest_commit_hash: Some("abc123def456".to_string()),
                files: vec![
                    RepositoryFile {
                        path: "config/database.yml".to_string(),
                        content: "password: supersecretpassword123\napi_key: AKIA1234567890ABCDEF\n".to_string(),
                        last_modified: Some(chrono::Utc::now()),
                    }
                ],
                recent_commits: vec![
                    CommitInfo {
                        hash: "def456abc789".to_string(),
                        message: "Added API key for production".to_string(),
                        timestamp: chrono::Utc::now(),
                        author: "developer@company.com".to_string(),
                    }
                ],
                hardcoded_secrets: vec!["database_password".to_string()],
                scan_duration_ms: 1250,
            })
        } else {
            None
        }
    }

    /// Simulate API data for demonstration.
    fn simulate_api_data(&self, _target: &PrivacyTarget) -> Option<ApiRequestData> {
        // Occasionally simulate API requests with OAuth token violations
        if rand::random::<f64>() < 0.08 {
            use crate::privacy::detection::{ApiRequestData, OAuthTokenData};
            
            Some(ApiRequestData {
                endpoint: "/api/user/profile".to_string(),
                method: "GET".to_string(),
                version: Some("v2".to_string()),
                oauth_token: Some(OAuthTokenData {
                    token_type: "Bearer".to_string(),
                    scopes: vec!["read:user".to_string()],
                    issued_at: Some(chrono::Utc::now() - chrono::Duration::hours(2)),
                    expires_at: Some(chrono::Utc::now() + chrono::Duration::hours(1)),
                    issuer: Some("https://auth.company.com".to_string()),
                    signature_valid: false, // Security violation!
                    expired: false,
                }),
                https_used: false, // Security violation!
                auth_header_present: true,
                rate_limiting_applied: false,
            })
        } else {
            None
        }
    }

    /// Simulate hardware data for demonstration.
    fn simulate_hardware_data(&self, _target: &PrivacyTarget) -> Option<HardwareData> {
        // Occasionally simulate hardware security issues
        if rand::random::<f64>() < 0.05 {
            use crate::privacy::detection::{HardwareData, HardwareDeviceType};
            
            Some(HardwareData {
                device_type: HardwareDeviceType::NfcBadge,
                device_id: Some("badge-001".to_string()),
                manufacturer: Some("SecureAccess Corp".to_string()),
                firmware_version: Some("v1.2.3".to_string()),
                nfc_encryption_type: Some("DES".to_string()), // Weak encryption!
                access_level: Some("Level 3".to_string()),
                encryption_strength: Some(64), // Weak!
                usb_vendor_product: None,
                whitelisted: true,
                device_class: Some("access_control".to_string()),
                wallet_type: None,
                secure_element_present: false, // Security issue!
                fault_injection_protection: false, // Vulnerability!
                side_channel_protection: false,
            })
        } else {
            None
        }
    }
}

impl Default for PrivacyEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ── Supporting types ───────────────────────────────────────────────

/// Result of a privacy detection cycle.
#[derive(Debug, Clone)]
pub struct PrivacyCycleResult {
    pub detections_executed: usize,
    pub violations_detected: usize,
    pub new_privacy_alerts: usize,
}

/// Privacy alert for high-priority data protection violations.
#[derive(Debug, Clone)]
pub struct PrivacyAlert {
    pub id: String,
    pub entity_id: EntityId,
    pub urgency: AlertUrgency,
    pub title: String,
    pub description: String,
    pub privacy_risk_score: f64,
    pub compliance_impact: Vec<ComplianceFramework>,
    pub data_subjects_affected: u32,
    pub created_at: crate::types::Timestamp,
    pub acknowledged: bool,
    pub assigned_to: Option<String>,
}

/// Alert urgency levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertUrgency {
    Low,
    Medium,
    High,
    Critical,
}

/// Summary statistics for the privacy engine.
#[derive(Debug, Clone)]
pub struct PrivacyEngineStats {
    pub active_targets: usize,
    pub total_privacy_events: usize,
    pub high_risk_entities: usize,
    pub total_entities: usize,
    pub pending_privacy_alerts: usize,
    pub critical_privacy_alerts: usize,
    pub total_data_subjects_affected: u32,
}

// ── Simple random number generation ────────────────────────────────

mod rand {
    /// Simple PRNG for simulation purposes.
    static mut SEED: u64 = 12345;

    pub fn random<T>() -> T
    where
        T: From<f64>,
    {
        unsafe {
            SEED = SEED.wrapping_mul(1103515245).wrapping_add(12345);
            let normalized = (SEED % 1000000) as f64 / 1000000.0;
            T::from(normalized)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_privacy_engine_creation() {
        let engine = PrivacyEngine::new();
        assert_eq!(engine.targets.len(), 0);
        assert_eq!(engine.entity_profiles.len(), 0);
        assert_eq!(engine.pending_privacy_alerts.len(), 0);
    }

    #[test]
    fn test_add_remove_privacy_target() {
        let mut engine = PrivacyEngine::new();
        let entity_id = EntityId(uuid::Uuid::new_v4());

        let target = PrivacyTarget::database_encryption(entity_id, "Test Database");
        engine.add_target(target.clone());

        assert_eq!(engine.targets.len(), 1);
        assert!(engine.targets.contains_key(&entity_id));

        let removed = engine.remove_target(&entity_id);
        assert!(removed.is_some());
        assert_eq!(engine.targets.len(), 0);
    }

    #[test]
    fn test_privacy_detection_cycle() {
        let mut engine = PrivacyEngine::new();
        let entity_id = EntityId(uuid::Uuid::new_v4());

        let target = PrivacyTarget::database_encryption(entity_id, "Test Database");
        engine.add_target(target);

        let result = engine.execute_privacy_cycle();
        assert!(result.detections_executed > 0);
    }
}
