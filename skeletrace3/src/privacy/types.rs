//! Data protection and privacy breach monitoring types for the Skeletrace privacy engine.
//!
//! These types implement data protection patterns from multiple security domains:
//! - Database encryption at rest with proper key management policies
//! - Code repository credential exposure scanning and detection
//! - REST API security using OAuth 2.0 tokens with short-lived access grants
//! - Constant-time comparison functions to prevent side-channel timing attacks
//! - Browser credential storage security using hardware-backed keystores
//! - NFC access badge configuration auditing for proper encryption settings
//! - Rogue base station detection using signal analysis on mobile equipment
//! - Hardware wallet private key protection from fault injection attacks
//! - USB device whitelisting policies to prevent unauthorized data access
//! - Clipboard access permission auditing across installed applications

use std::collections::HashMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::types::{Confidence, EntityId, Timestamp};

// ── Data protection categories ─────────────────────────────────────

/// Primary data protection vector categories for privacy monitoring.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProtectionVector {
    /// Database and storage protection (encryption at rest, key management).
    Database,
    /// Source code and repository protection (credential scanning, secret detection).
    Repository,
    /// API and service protection (OAuth tokens, authentication).
    Api,
    /// Hardware-based protection (NFC badges, USB policies, hardware wallets).
    Hardware,
    /// Side-channel and timing attack protection.
    SideChannel,
    /// Browser and application credential storage protection.
    Credential,
    /// Network and communication protection (rogue base stations, signal analysis).
    Network,
    /// System access and permission protection (clipboard, device access).
    Access,
}

/// Specific data protection violation types within each vector category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PrivacyViolationType {
    // Database protection violations
    UnencryptedDatabase,
    WeakKeyManagement,
    ExpiredEncryptionKeys,
    PlaintextStorage,
    
    // Repository protection violations
    ExposedCredentials,
    HardcodedSecrets,
    ApiKeyLeakage,
    PrivateKeyExposure,
    
    // API protection violations
    InvalidOAuthToken,
    ExpiredAccessToken,
    WeakApiAuthentication,
    UnauthorizedApiAccess,
    
    // Hardware protection violations
    WeakNfcEncryption,
    UnauthorizedUsbAccess,
    HardwareWalletVulnerability,
    FaultInjectionAttempt,
    
    // Side-channel attack indicators
    TimingAttackAttempt,
    PowerAnalysisAttempt,
    ElectromagneticLeakage,
    AcousticSideChannel,
    
    // Credential storage violations
    UnprotectedBrowserCredentials,
    WeakKeystoreConfiguration,
    CredentialCacheViolation,
    SessionTokenExposure,
    
    // Network protection violations
    RogueBaseStationDetected,
    SignalInterceptionAttempt,
    ManInTheMiddleAttack,
    NetworkEavesdropping,
    
    // Access control violations
    UnauthorizedClipboardAccess,
    DeviceWhitelistViolation,
    PermissionEscalation,
    DataExfiltrationAttempt,
}

/// Severity level for privacy violations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ViolationSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl ViolationSeverity {
    pub fn score(&self) -> f64 {
        match self {
            Self::Info => 0.1,
            Self::Low => 0.3,
            Self::Medium => 0.5,
            Self::High => 0.8,
            Self::Critical => 1.0,
        }
    }
}

/// Compliance framework for privacy assessment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ComplianceFramework {
    /// General Data Protection Regulation (EU).
    Gdpr,
    /// California Consumer Privacy Act.
    Ccpa,
    /// Health Insurance Portability and Accountability Act.
    Hipaa,
    /// Payment Card Industry Data Security Standard.
    PciDss,
    /// System and Organization Controls.
    Soc2,
    /// International Organization for Standardization.
    Iso27001,
    /// NIST Cybersecurity Framework.
    NistCsf,
}

// ── Privacy breach events ──────────────────────────────────────────

/// A detected privacy violation or data protection breach.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyEvent {
    /// Unique identifier for this event.
    pub id: String,
    /// Entity (node) where the violation was detected.
    pub entity_id: EntityId,
    /// When the violation was detected.
    pub timestamp: Timestamp,
    /// Data protection classification.
    pub protection_vector: ProtectionVector,
    pub violation_type: PrivacyViolationType,
    pub severity: ViolationSeverity,
    /// Privacy risk score (0.0 = no risk, 1.0 = maximum privacy violation).
    pub privacy_risk_score: f64,
    /// Confidence in the violation detection.
    pub confidence: Confidence,
    /// Human-readable description.
    pub description: String,
    /// Source of the violation detection (scanner, audit, monitor, etc.).
    pub detection_source: String,
    /// Detailed indicators and metadata.
    pub indicators: PrivacyIndicators,
    /// Affected data types or subjects.
    pub data_subjects: Vec<DataSubject>,
    /// Compliance framework violations.
    pub compliance_violations: Vec<ComplianceViolation>,
    /// Whether this event has been investigated.
    pub investigated: bool,
    /// Investigation notes and remediation steps.
    pub notes: String,
}

/// Privacy violation indicators and metadata for different protection vectors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyIndicators {
    /// Database and storage indicators.
    pub database: Option<DatabaseIndicators>,
    /// Code repository indicators.
    pub repository: Option<RepositoryIndicators>,
    /// API security indicators.
    pub api: Option<ApiIndicators>,
    /// Hardware security indicators.
    pub hardware: Option<HardwareIndicators>,
    /// Side-channel attack indicators.
    pub side_channel: Option<SideChannelIndicators>,
    /// Credential storage indicators.
    pub credential: Option<CredentialIndicators>,
    /// Network security indicators.
    pub network: Option<NetworkIndicators>,
    /// Access control indicators.
    pub access: Option<AccessIndicators>,
}

// ── Indicator types ────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseIndicators {
    /// Database connection and configuration.
    pub database_type: String,
    pub connection_string: Option<String>,
    pub encryption_algorithm: Option<String>,
    pub encryption_enabled: bool,
    /// Key management information.
    pub key_rotation_enabled: bool,
    pub key_age_days: Option<u32>,
    pub key_storage_method: Option<String>,
    /// Compliance indicators.
    pub compliance_requirements: Vec<String>,
    pub audit_logging_enabled: bool,
    pub access_controls: Vec<String>,
    /// Risk factors.
    pub plaintext_detected: bool,
    pub weak_encryption: bool,
    pub expired_certificates: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepositoryIndicators {
    /// Repository information.
    pub repository_url: String,
    pub repository_type: String,
    pub branch: String,
    pub commit_hash: Option<String>,
    /// Detected exposures.
    pub exposed_credentials: Vec<ExposedCredential>,
    pub hardcoded_secrets: Vec<String>,
    pub api_keys_detected: u32,
    pub private_keys_detected: u32,
    /// Scan metadata.
    pub files_scanned: u32,
    pub scan_duration_ms: u32,
    pub false_positive_likelihood: f64,
    /// Remediation information.
    pub auto_remediation_available: bool,
    pub remediation_steps: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExposedCredential {
    pub credential_type: String,
    pub file_path: String,
    pub line_number: u32,
    pub entropy_score: f64,
    pub commit_date: Option<Timestamp>,
    pub still_active: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiIndicators {
    /// API endpoint information.
    pub endpoint_url: String,
    pub method: String,
    pub api_version: Option<String>,
    /// OAuth and token information.
    pub token_type: Option<String>,
    pub token_age_seconds: Option<u32>,
    pub token_scope: Vec<String>,
    pub token_issuer: Option<String>,
    /// Security analysis.
    pub authentication_method: String,
    pub authorization_header_present: bool,
    pub https_enabled: bool,
    pub rate_limiting_enabled: bool,
    /// Risk factors.
    pub expired_token: bool,
    pub insufficient_scope: bool,
    pub weak_signature: bool,
    pub replay_attack_possible: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareIndicators {
    /// Device information.
    pub device_type: String,
    pub device_id: Option<String>,
    pub manufacturer: Option<String>,
    pub firmware_version: Option<String>,
    /// NFC badge indicators.
    pub nfc_encryption_type: Option<String>,
    pub badge_access_level: Option<String>,
    pub encryption_strength: Option<u32>,
    /// USB device indicators.
    pub usb_vendor_id: Option<String>,
    pub usb_product_id: Option<String>,
    pub whitelisted: bool,
    pub device_class: Option<String>,
    /// Hardware wallet indicators.
    pub wallet_type: Option<String>,
    pub secure_element_present: bool,
    pub fault_injection_protection: bool,
    pub side_channel_protection: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SideChannelIndicators {
    /// Attack type and characteristics.
    pub attack_vector: String,
    pub measurement_type: String,
    pub sample_rate_hz: Option<f64>,
    pub measurement_duration_ms: u32,
    /// Timing analysis.
    pub timing_variance_ns: Option<f64>,
    pub constant_time_violated: bool,
    pub statistical_significance: f64,
    /// Power/electromagnetic analysis.
    pub power_consumption_anomaly: bool,
    pub em_emission_detected: bool,
    pub frequency_analysis: Vec<f64>,
    /// Acoustic analysis.
    pub acoustic_leakage: bool,
    pub sound_frequency_hz: Option<f64>,
    pub audio_correlation: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialIndicators {
    /// Storage mechanism.
    pub storage_type: String,
    pub encryption_method: Option<String>,
    pub hardware_backed: bool,
    pub keystore_provider: Option<String>,
    /// Browser credential information.
    pub browser_type: Option<String>,
    pub credential_count: u32,
    pub master_password_protected: bool,
    pub sync_enabled: bool,
    /// Security assessment.
    pub encryption_strength: Option<u32>,
    pub access_control_enabled: bool,
    pub biometric_protection: bool,
    pub session_timeout_configured: bool,
    /// Risk factors.
    pub plaintext_storage: bool,
    pub weak_master_password: bool,
    pub credential_sharing: bool,
    pub unauthorized_access: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkIndicators {
    /// Network environment.
    pub network_type: String,
    pub signal_strength_dbm: Option<f64>,
    pub base_station_id: Option<String>,
    pub frequency_mhz: Option<f64>,
    /// Rogue base station detection.
    pub legitimate_operator: Option<String>,
    pub operator_mismatch: bool,
    pub signal_anomaly_score: f64,
    pub location_area_code: Option<u32>,
    /// Signal analysis.
    pub encryption_type: Option<String>,
    pub cipher_suite: Option<String>,
    pub authentication_protocol: Option<String>,
    pub downgrade_attack_detected: bool,
    /// Traffic analysis.
    pub traffic_interception: bool,
    pub man_in_the_middle: bool,
    pub certificate_pinning_bypassed: bool,
    pub dns_hijacking: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessIndicators {
    /// System and application information.
    pub application_name: String,
    pub process_id: Option<u32>,
    pub user_context: Option<String>,
    pub permission_level: String,
    /// Clipboard access.
    pub clipboard_read_count: u32,
    pub clipboard_write_count: u32,
    pub sensitive_data_detected: bool,
    pub data_types: Vec<String>,
    /// Device access.
    pub device_access_attempts: u32,
    pub unauthorized_devices: Vec<String>,
    pub whitelist_violations: u32,
    pub policy_compliance: bool,
    /// Permission analysis.
    pub excessive_permissions: bool,
    pub privilege_escalation: bool,
    pub sandboxing_bypassed: bool,
    pub data_exfiltration_risk: f64,
}

// ── Data subject and compliance ────────────────────────────────────

/// Type of data subject affected by a privacy violation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataSubject {
    /// Type of data subject (individual, employee, customer, etc.).
    pub subject_type: String,
    /// Data categories affected.
    pub data_categories: Vec<DataCategory>,
    /// Estimated number of affected subjects.
    pub estimated_count: Option<u32>,
    /// Geographic jurisdiction.
    pub jurisdiction: Vec<String>,
}

/// Category of personal data affected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DataCategory {
    /// Basic personal information.
    Personal,
    /// Financial information.
    Financial,
    /// Health information.
    Health,
    /// Biometric data.
    Biometric,
    /// Location data.
    Location,
    /// Communication records.
    Communication,
    /// Behavioral data.
    Behavioral,
    /// Authentication credentials.
    Authentication,
}

/// Specific compliance framework violation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceViolation {
    pub framework: ComplianceFramework,
    pub article: String,
    pub requirement: String,
    pub violation_description: String,
    pub potential_fine: Option<f64>,
    pub remediation_deadline: Option<Duration>,
}

// ── Risk assessment ────────────────────────────────────────────────

/// Aggregated privacy risk profile for an entity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityPrivacyProfile {
    pub entity_id: EntityId,
    /// Overall privacy risk score (0.0 = compliant, 1.0 = major violations).
    pub overall_privacy_risk: f64,
    /// Risk scores by protection vector.
    pub vector_scores: HashMap<ProtectionVector, f64>,
    /// Violation counts by severity.
    pub violation_counts: HashMap<ViolationSeverity, u32>,
    /// Compliance scores by framework.
    pub compliance_scores: HashMap<ComplianceFramework, f64>,
    /// Privacy risk trend over time.
    pub risk_trend: f64,
    /// Confidence in the privacy assessment.
    pub confidence: Confidence,
    /// Number of events in the assessment window.
    pub sample_count: usize,
    /// Timestamp of the most recent violation.
    pub last_violation_detected: Option<Timestamp>,
    /// Data subjects potentially affected.
    pub affected_data_subjects: u32,
    /// Human-readable privacy summary.
    pub privacy_summary: String,
}

/// Comprehensive privacy compliance report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyComplianceReport {
    pub timestamp: Timestamp,
    /// Entity privacy profiles.
    pub entity_profiles: HashMap<EntityId, EntityPrivacyProfile>,
    /// Protection vector coverage assessment.
    pub vector_coverage: HashMap<ProtectionVector, f64>,
    /// High-risk entities requiring immediate attention.
    pub high_risk_entities: Vec<EntityId>,
    /// Data protection gaps and recommendations.
    pub protection_gaps: Vec<ProtectionGap>,
    /// Overall organizational privacy posture.
    pub privacy_posture_score: f64,
    /// Compliance framework scores.
    pub framework_compliance: HashMap<ComplianceFramework, f64>,
    /// Executive summary for compliance reporting.
    pub executive_summary: String,
}

/// Identified gap in data protection coverage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectionGap {
    /// Gap identifier.
    pub gap_id: String,
    /// Protection vector with insufficient coverage.
    pub vector: ProtectionVector,
    /// Entities affected by this gap.
    pub affected_entities: Vec<EntityId>,
    /// Severity of the protection gap.
    pub severity: ViolationSeverity,
    /// Description of the gap.
    pub description: String,
    /// Recommended remediation steps.
    pub remediation_steps: Vec<String>,
    /// Estimated remediation cost.
    pub estimated_cost: Option<f64>,
    /// Compliance frameworks affected.
    pub compliance_impact: Vec<ComplianceFramework>,
}

// ── Configuration and targets ──────────────────────────────────────

/// Configuration for monitoring a specific data protection endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyTarget {
    /// The graph entity this target monitors.
    pub entity_id: EntityId,
    /// Type of privacy monitoring to perform.
    pub monitoring_type: PrivacyMonitoringType,
    /// Target-specific configuration.
    pub config: PrivacyTargetConfig,
    /// Human-readable label.
    pub label: String,
    /// Whether monitoring is enabled.
    pub enabled: bool,
}

/// Type of privacy monitoring to perform.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PrivacyMonitoringType {
    DatabaseEncryption,
    RepositoryScanning,
    ApiTokenValidation,
    HardwareSecurityAudit,
    SideChannelDetection,
    CredentialStorageAudit,
    NetworkSecurityMonitoring,
    AccessControlAudit,
}

/// Privacy target configuration parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyTargetConfig {
    /// Monitoring interval.
    #[serde(with = "serde_duration_seconds")]
    pub check_interval: Duration,
    /// Privacy risk threshold for alerting.
    pub alert_threshold: f64,
    /// Confidence threshold for violation detection.
    pub confidence_threshold: f64,
    /// Compliance frameworks to assess.
    pub compliance_frameworks: Vec<ComplianceFramework>,
    /// Target-specific parameters.
    pub parameters: HashMap<String, String>,
}

impl PrivacyTarget {
    /// Create a new database encryption monitoring target.
    pub fn database_encryption(entity_id: EntityId, label: impl Into<String>) -> Self {
        Self {
            entity_id,
            monitoring_type: PrivacyMonitoringType::DatabaseEncryption,
            config: PrivacyTargetConfig {
                check_interval: Duration::from_secs(3600), // 1 hour
                alert_threshold: 0.6,
                confidence_threshold: 0.8,
                compliance_frameworks: vec![ComplianceFramework::Gdpr, ComplianceFramework::PciDss],
                parameters: HashMap::new(),
            },
            label: label.into(),
            enabled: true,
        }
    }

    /// Create a new repository credential scanning target.
    pub fn repository_scanning(entity_id: EntityId, label: impl Into<String>) -> Self {
        let mut target = Self::database_encryption(entity_id, label);
        target.monitoring_type = PrivacyMonitoringType::RepositoryScanning;
        target.config.check_interval = Duration::from_secs(1800); // 30 minutes
        target.config.alert_threshold = 0.4; // Lower threshold for credential exposure
        target
    }

    /// Create a new API security monitoring target.
    pub fn api_security(entity_id: EntityId, label: impl Into<String>) -> Self {
        let mut target = Self::database_encryption(entity_id, label);
        target.monitoring_type = PrivacyMonitoringType::ApiTokenValidation;
        target.config.check_interval = Duration::from_secs(300); // 5 minutes
        target.config.compliance_frameworks = vec![ComplianceFramework::Gdpr, ComplianceFramework::Soc2];
        target
    }

    /// Create a new hardware security audit target.
    pub fn hardware_security(entity_id: EntityId, label: impl Into<String>) -> Self {
        let mut target = Self::database_encryption(entity_id, label);
        target.monitoring_type = PrivacyMonitoringType::HardwareSecurityAudit;
        target.config.check_interval = Duration::from_secs(7200); // 2 hours
        target.config.compliance_frameworks = vec![ComplianceFramework::PciDss, ComplianceFramework::Iso27001];
        target
    }
}

// ── Serde helpers ──────────────────────────────────────────────────

mod serde_duration_seconds {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn serialize<S: Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u64(d.as_secs())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        let secs = u64::deserialize(d)?;
        Ok(Duration::from_secs(secs))
    }
}
