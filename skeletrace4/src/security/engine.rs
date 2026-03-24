//! Main security engine — orchestrates multi-vector threat detection and analysis.
//!
//! This is the central coordinator that manages:
//! - Security target monitoring across multiple threat vectors
//! - Threat detection execution using specialized analyzers
//! - Risk assessment and behavioral analysis
//! - Attack surface monitoring and reporting
//! - Integration with Skeletrace's graph and metric systems
//!
//! Designed to implement security patterns from all major domains while
//! providing a unified monitoring and alerting interface.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use log::{debug, info, warn};

use crate::graph::Graph;
use crate::metric::{Sample, SampleValue};
use crate::security::analysis::{AttackSurfaceAnalyzer, SecurityAnalyzer};
use crate::security::detection::{
    EmailData, EmailDetector, FileData, FileDetector, WebDetector, WebRequestData,
};
use crate::security::types::{
    AttackSurfaceReport, EntityRiskProfile, MonitoringType, SecurityTarget,
    ThreatEvent, ThreatVector,
};
use crate::types::{EntityId, MetricId, Quality, SourceId};

// ── Security engine configuration ──────────────────────────────────

/// Configuration for the security engine.
#[derive(Debug, Clone)]
pub struct SecurityEngineConfig {
    /// Maximum threat events to store per entity.
    pub max_events_per_entity: usize,
    /// Risk assessment window size (number of events).
    pub risk_window_size: usize,
    /// How often to run attack surface analysis.
    pub analysis_interval: Duration,
    /// Risk threshold for alerting.
    pub alert_risk_threshold: f64,
    /// Source ID for security-generated metrics.
    pub source_id: SourceId,
}

impl Default for SecurityEngineConfig {
    fn default() -> Self {
        Self {
            max_events_per_entity: 1000,
            risk_window_size: 200,
            analysis_interval: Duration::from_secs(900), // 15 minutes
            alert_risk_threshold: 0.6,
            source_id: SourceId(uuid::Uuid::nil()), // Replace with real UUID
        }
    }
}

// ── Main security engine ───────────────────────────────────────────

/// Multi-vector security threat monitoring engine.
///
/// Orchestrates threat detection, risk analysis, and attack surface
/// assessment for entities in a Skeletrace graph.
pub struct SecurityEngine {
    /// Engine configuration.
    config: SecurityEngineConfig,
    /// Threat detection components.
    email_detector: EmailDetector,
    web_detector: WebDetector,
    file_detector: FileDetector,
    /// Risk analysis components.
    security_analyzer: SecurityAnalyzer,
    /// Active security targets.
    targets: HashMap<EntityId, SecurityTarget>,
    /// Threat event history (per entity).
    threat_events: HashMap<EntityId, Vec<ThreatEvent>>,
    /// Last monitoring times (for scheduling).
    last_monitor_times: HashMap<EntityId, Instant>,
    /// Last attack surface analysis time.
    last_analysis: Option<Instant>,
    /// Current entity risk profiles.
    entity_risks: HashMap<EntityId, EntityRiskProfile>,
    /// High-priority alerts pending investigation.
    pending_alerts: Vec<SecurityAlert>,
}

impl SecurityEngine {
    /// Create a new security engine with default configuration.
    pub fn new() -> Self {
        Self::with_config(SecurityEngineConfig::default())
    }

    /// Create a new security engine with custom configuration.
    pub fn with_config(config: SecurityEngineConfig) -> Self {
        let security_analyzer = SecurityAnalyzer::with_window_hours(
            (config.analysis_interval.as_secs() / 3600) as u32
        );

        Self {
            config,
            email_detector: EmailDetector::new(),
            web_detector: WebDetector::new(),
            file_detector: FileDetector::new(),
            security_analyzer,
            targets: HashMap::new(),
            threat_events: HashMap::new(),
            last_monitor_times: HashMap::new(),
            last_analysis: None,
            entity_risks: HashMap::new(),
            pending_alerts: Vec::new(),
        }
    }

    // ── Target management ──────────────────────────────────────────

    /// Add a security target for monitoring.
    pub fn add_target(&mut self, target: SecurityTarget) {
        info!(
            "Added security target: {} -> {:?}",
            target.label, target.monitoring_type
        );
        self.targets.insert(target.entity_id, target);
    }

    /// Remove a security target.
    pub fn remove_target(&mut self, entity_id: &EntityId) -> Option<SecurityTarget> {
        let removed = self.targets.remove(entity_id);
        if removed.is_some() {
            info!("Removed security target for entity {:?}", entity_id);
            // Clean up associated data
            self.threat_events.remove(entity_id);
            self.last_monitor_times.remove(entity_id);
            self.entity_risks.remove(entity_id);
        }
        removed
    }

    /// Get all active security targets.
    pub fn targets(&self) -> &HashMap<EntityId, SecurityTarget> {
        &self.targets
    }

    // ── Threat detection execution ─────────────────────────────────

    /// Execute threat detection across all targets.
    ///
    /// This checks all targets, executes threat detection that is due,
    /// updates risk assessments, and returns the number of detections executed.
    pub fn execute_detection_cycle(&mut self) -> SecurityCycleResult {
        let now = Instant::now();
        let mut detections_executed = 0;
        let mut threats_detected = 0;
        let mut new_alerts = 0;

        // Collect targets that are due for monitoring
        let due_targets: Vec<EntityId> = self
            .targets
            .iter()
            .filter(|(entity_id, target)| {
                target.enabled && self.is_target_due(**entity_id, target, now)
            })
            .map(|(entity_id, _)| *entity_id)
            .collect();

        // Execute threat detection for due targets
        for entity_id in due_targets {
            if let Some(target) = self.targets.get(&entity_id).cloned() {
                if let Some(threat_event) = self.execute_target_detection(&target) {
                    self.record_threat_event(threat_event.clone());
                    threats_detected += 1;

                    // Check if this generates a new alert
                    if threat_event.risk_score >= self.config.alert_risk_threshold {
                        let alert = self.create_security_alert(&threat_event);
                        self.pending_alerts.push(alert);
                        new_alerts += 1;
                    }
                }
                self.last_monitor_times.insert(entity_id, now);
                detections_executed += 1;
            }
        }

        // Update entity risk profiles
        self.update_entity_risks();

        SecurityCycleResult {
            detections_executed,
            threats_detected,
            new_alerts,
        }
    }

    /// Check if a target is due for monitoring.
    fn is_target_due(&self, entity_id: EntityId, target: &SecurityTarget, now: Instant) -> bool {
        match self.last_monitor_times.get(&entity_id) {
            Some(&last_time) => now.duration_since(last_time) >= target.config.check_interval,
            None => true, // Never monitored before
        }
    }

    /// Execute threat detection for a specific target.
    fn execute_target_detection(&mut self, target: &SecurityTarget) -> Option<ThreatEvent> {
        debug!(
            "Executing threat detection for {:?}: {:?}",
            target.entity_id, target.monitoring_type
        );

        match target.monitoring_type {
            MonitoringType::EmailGateway => {
                // In a real implementation, this would fetch email data from the gateway
                // For now, simulate with dummy data
                if let Some(email_data) = self.simulate_email_data(target) {
                    self.email_detector.analyze_email(target.entity_id, &email_data)
                } else {
                    None
                }
            }
            MonitoringType::WebProxy => {
                // Simulate web request data
                if let Some(web_data) = self.simulate_web_data(target) {
                    self.web_detector.analyze_web_request(target.entity_id, &web_data)
                } else {
                    None
                }
            }
            MonitoringType::FileIntegrityCheck => {
                // Simulate file integrity check data
                if let Some(file_data) = self.simulate_file_data(target) {
                    self.file_detector.analyze_file(target.entity_id, &file_data)
                } else {
                    None
                }
            }
            _ => {
                // Other monitoring types would be implemented here
                debug!("Monitoring type {:?} not yet implemented", target.monitoring_type);
                None
            }
        }
    }

    /// Record a threat event and update history.
    fn record_threat_event(&mut self, event: ThreatEvent) {
        debug!(
            "Recording threat event: {:?} for {:?}",
            event.threat_type, event.entity_id
        );

        // Add to history
        let history = self.threat_events.entry(event.entity_id).or_default();
        history.push(event);

        // Trim history to reasonable size
        if history.len() > self.config.max_events_per_entity {
            history.drain(0..history.len() - self.config.max_events_per_entity);
        }
    }

    /// Update entity risk profiles from recent threat events.
    fn update_entity_risks(&mut self) {
        for (entity_id, events) in &self.threat_events {
            let risk_profile = self.security_analyzer.compute_entity_risk(events);
            self.entity_risks.insert(*entity_id, risk_profile);
        }
    }

    /// Create a security alert from a threat event.
    fn create_security_alert(&self, event: &ThreatEvent) -> SecurityAlert {
        let urgency = match event.severity {
            crate::security::types::ThreatSeverity::Critical => AlertUrgency::Critical,
            crate::security::types::ThreatSeverity::High => AlertUrgency::High,
            crate::security::types::ThreatSeverity::Medium => AlertUrgency::Medium,
            _ => AlertUrgency::Low,
        };

        SecurityAlert {
            id: event.id.clone(),
            entity_id: event.entity_id,
            urgency,
            title: format!("{:?} detected", event.threat_type),
            description: event.description.clone(),
            risk_score: event.risk_score,
            created_at: event.timestamp,
            acknowledged: false,
            assigned_to: None,
        }
    }

    // ── Attack surface analysis ────────────────────────────────────

    /// Run full attack surface analysis if due.
    ///
    /// This performs comprehensive risk assessment and generates
    /// an attack surface report. Returns a report if analysis was performed.
    pub fn analyze_attack_surface(&mut self, graph: &Graph) -> Option<AttackSurfaceReport> {
        let now = Instant::now();

        // Check if analysis is due
        let analysis_due = match self.last_analysis {
            Some(last) => now.duration_since(last) >= self.config.analysis_interval,
            None => true,
        };

        if !analysis_due {
            return None;
        }

        info!("Running attack surface analysis...");

        let surface_analyzer = AttackSurfaceAnalyzer::new(graph);

        // Collect all threat events for pattern detection
        let all_events: Vec<ThreatEvent> = self
            .threat_events
            .values()
            .flat_map(|events| events.iter())
            .cloned()
            .collect();

        // Generate comprehensive report
        let report = surface_analyzer.generate_attack_surface_report(
            self.entity_risks.clone(),
            &all_events,
            &self.security_analyzer,
        );

        // Log key findings
        info!(
            "Attack surface analysis complete: {:.1}% security posture, {} high-risk entities",
            report.security_posture_score * 100.0,
            report.high_risk_entities.len()
        );

        if !report.attack_patterns.is_empty() {
            warn!(
                "Detected {} attack patterns: {:?}",
                report.attack_patterns.len(),
                report
                    .attack_patterns
                    .iter()
                    .map(|p| &p.pattern_id)
                    .collect::<Vec<_>>()
            );
        }

        self.last_analysis = Some(now);
        Some(report)
    }

    // ── Metric integration ─────────────────────────────────────────

    /// Generate Skeletrace metric samples from current security state.
    ///
    /// This allows security results to feed into the broader metric system.
    pub fn generate_metric_samples(&self) -> Vec<Sample> {
        let mut samples = Vec::new();
        let now = chrono::Utc::now();

        for (entity_id, risk_profile) in &self.entity_risks {
            // Overall risk score metric
            samples.push(Sample {
                metric_id: MetricId(uuid::Uuid::nil()), // Replace with real risk metric ID
                entity_id: *entity_id,
                timestamp: now,
                value: SampleValue::Numeric(risk_profile.overall_risk_score),
                quality: Quality::new(risk_profile.confidence.value()),
                source_id: self.config.source_id,
            });

            // Threat count metric
            let total_threats: u32 = risk_profile.threat_counts.values().sum();
            samples.push(Sample {
                metric_id: MetricId(uuid::Uuid::nil()), // Replace with real threat count metric ID
                entity_id: *entity_id,
                timestamp: now,
                value: SampleValue::Numeric(total_threats as f64),
                quality: Quality::new(risk_profile.confidence.value()),
                source_id: self.config.source_id,
            });

            // Risk trend metric
            samples.push(Sample {
                metric_id: MetricId(uuid::Uuid::nil()), // Replace with real trend metric ID
                entity_id: *entity_id,
                timestamp: now,
                value: SampleValue::Numeric(risk_profile.risk_trend),
                quality: Quality::new(risk_profile.confidence.value()),
                source_id: self.config.source_id,
            });
        }

        samples
    }

    // ── Alert management ───────────────────────────────────────────

    /// Get all pending security alerts.
    pub fn get_pending_alerts(&self) -> &[SecurityAlert] {
        &self.pending_alerts
    }

    /// Acknowledge a security alert.
    pub fn acknowledge_alert(&mut self, alert_id: &str, assigned_to: Option<String>) {
        if let Some(alert) = self.pending_alerts.iter_mut().find(|a| a.id == alert_id) {
            alert.acknowledged = true;
            alert.assigned_to = assigned_to;
            info!("Acknowledged security alert: {}", alert_id);
        }
    }

    /// Remove acknowledged alerts older than specified duration.
    pub fn cleanup_old_alerts(&mut self, max_age: Duration) {
        let cutoff = chrono::Utc::now() - chrono::Duration::from_std(max_age).unwrap();
        
        let initial_count = self.pending_alerts.len();
        self.pending_alerts.retain(|alert| {
            !alert.acknowledged || alert.created_at > cutoff
        });
        
        let removed_count = initial_count - self.pending_alerts.len();
        if removed_count > 0 {
            debug!("Cleaned up {} old acknowledged alerts", removed_count);
        }
    }

    // ── Status queries ─────────────────────────────────────────────

    /// Get current risk profile for a specific entity.
    pub fn get_entity_risk(&self, entity_id: &EntityId) -> Option<&EntityRiskProfile> {
        self.entity_risks.get(entity_id)
    }

    /// Get threat event history for an entity.
    pub fn get_threat_history(&self, entity_id: &EntityId) -> Option<&[ThreatEvent]> {
        self.threat_events.get(entity_id).map(|v| v.as_slice())
    }

    /// Get summary statistics.
    pub fn stats(&self) -> SecurityEngineStats {
        let total_events = self.threat_events.values().map(|h| h.len()).sum();
        let active_targets = self.targets.len();
        let high_risk_entities = self
            .entity_risks
            .values()
            .filter(|r| r.overall_risk_score >= 0.6)
            .count();
        
        let critical_alerts = self
            .pending_alerts
            .iter()
            .filter(|a| a.urgency == AlertUrgency::Critical && !a.acknowledged)
            .count();

        SecurityEngineStats {
            active_targets,
            total_threat_events: total_events,
            high_risk_entities,
            total_entities: self.entity_risks.len(),
            pending_alerts: self.pending_alerts.iter().filter(|a| !a.acknowledged).count(),
            critical_alerts,
        }
    }

    // ── Simulation helpers (for demo purposes) ─────────────────────

    /// Simulate email data for demonstration purposes.
    fn simulate_email_data(&self, _target: &SecurityTarget) -> Option<EmailData> {
        // In a real implementation, this would fetch from email gateway API
        // For now, occasionally simulate suspicious emails
        if rand::random::<f64>() < 0.1 {
            Some(EmailData {
                from_address: "suspicious@fake-bank.tk".to_string(),
                display_name: Some("Your Bank".to_string()),
                from_domain: "fake-bank.tk".to_string(),
                subject: "URGENT: Verify your account now!".to_string(),
                content: "Click here to verify: http://phishing-site.ga/login".to_string(),
                headers: [
                    ("Authentication-Results".to_string(), "spf=fail".to_string()),
                    ("Return-Path".to_string(), "suspicious@fake-bank.tk".to_string()),
                ].iter().cloned().collect(),
                attachments: vec![],
                spf_pass: Some(false),
                dkim_pass: Some(false),
                dmarc_pass: Some(false),
            })
        } else {
            None
        }
    }

    /// Simulate web request data for demonstration.
    fn simulate_web_data(&self, _target: &SecurityTarget) -> Option<WebRequestData> {
        // Occasionally simulate suspicious web requests
        if rand::random::<f64>() < 0.05 {
            Some(WebRequestData {
                domain: "paypal-secure.tk".to_string(),
                path: "/login".to_string(),
                ssl_info: Some(crate::security::detection::SslInfo {
                    valid: false,
                    issuer: Some("Unknown CA".to_string()),
                    age_days: Some(2),
                }),
                user_agent: Some("Mozilla/5.0 (Windows NT 10.0)".to_string()),
                referer: None,
            })
        } else {
            None
        }
    }

    /// Simulate file integrity data for demonstration.
    fn simulate_file_data(&self, _target: &SecurityTarget) -> Option<FileData> {
        // Occasionally simulate file integrity issues
        if rand::random::<f64>() < 0.02 {
            Some(FileData {
                filename: "system-update.exe".to_string(),
                file_size: 2048000,
                file_type: "executable".to_string(),
                mime_type: "application/octet-stream".to_string(),
                expected_hash: Some("abc123def456".to_string()),
                actual_hash: Some("different_hash".to_string()),
                hash_algorithm: Some("SHA256".to_string()),
                signature_info: None,
                virus_total_score: Some(3),
                malware_scan_score: Some(0.7),
                entropy: Some(7.8),
            })
        } else {
            None
        }
    }
}

impl Default for SecurityEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ── Supporting types ───────────────────────────────────────────────

/// Result of a security detection cycle.
#[derive(Debug, Clone)]
pub struct SecurityCycleResult {
    pub detections_executed: usize,
    pub threats_detected: usize,
    pub new_alerts: usize,
}

/// Security alert for high-priority threats.
#[derive(Debug, Clone)]
pub struct SecurityAlert {
    pub id: String,
    pub entity_id: EntityId,
    pub urgency: AlertUrgency,
    pub title: String,
    pub description: String,
    pub risk_score: f64,
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

/// Summary statistics for the security engine.
#[derive(Debug, Clone)]
pub struct SecurityEngineStats {
    pub active_targets: usize,
    pub total_threat_events: usize,
    pub high_risk_entities: usize,
    pub total_entities: usize,
    pub pending_alerts: usize,
    pub critical_alerts: usize,
}

// ── Simple random number generation ────────────────────────────────

mod rand {
    /// Simple PRNG for simulation purposes.
    static mut SEED: u64 = 1;

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
    fn test_security_engine_creation() {
        let engine = SecurityEngine::new();
        assert_eq!(engine.targets.len(), 0);
        assert_eq!(engine.entity_risks.len(), 0);
        assert_eq!(engine.pending_alerts.len(), 0);
    }

    #[test]
    fn test_add_remove_target() {
        let mut engine = SecurityEngine::new();
        let entity_id = EntityId(uuid::Uuid::new_v4());

        let target = SecurityTarget::email_gateway(entity_id, "Test Gateway");
        engine.add_target(target.clone());

        assert_eq!(engine.targets.len(), 1);
        assert!(engine.targets.contains_key(&entity_id));

        let removed = engine.remove_target(&entity_id);
        assert!(removed.is_some());
        assert_eq!(engine.targets.len(), 0);
    }

    #[test]
    fn test_detection_cycle() {
        let mut engine = SecurityEngine::new();
        let entity_id = EntityId(uuid::Uuid::new_v4());

        let target = SecurityTarget::email_gateway(entity_id, "Test Gateway");
        engine.add_target(target);

        let result = engine.execute_detection_cycle();
        assert!(result.detections_executed > 0);
    }
}
