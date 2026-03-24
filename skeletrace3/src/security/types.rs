//! Security threat monitoring types for the Skeletrace security engine.
//!
//! These types implement threat detection patterns from multiple security domains:
//! - Phishing email identification and business email compromise (BEC) detection
//! - Credential harvesting honeypots and suspicious login monitoring
//! - Vishing (voice phishing) and smishing (SMS phishing) detection
//! - Identity verification workflows for helpdesk operations
//! - Watering hole threat assessment and browser security monitoring
//! - Software update authenticity verification and file integrity checks
//! - Social media security auditing and attack surface reduction

use std::collections::HashMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::types::{Confidence, EntityId, Timestamp};

// ── Threat categories ──────────────────────────────────────────────

/// Primary threat vector categories for security monitoring.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ThreatVector {
    /// Email-based threats (phishing, BEC, malicious attachments).
    Email,
    /// Voice-based social engineering (vishing, impersonation calls).
    Voice,
    /// SMS-based threats (smishing, malicious links).
    Sms,
    /// Web-based threats (watering holes, malicious downloads, fake login pages).
    Web,
    /// File-based threats (malware, unsigned software, tampered updates).
    File,
    /// Social media threats (reconnaissance, fake profiles, credential leaks).
    SocialMedia,
    /// Identity verification bypass attempts (helpdesk fraud, account takeover).
    Identity,
    /// Network-based threats (credential harvesting, man-in-the-middle).
    Network,
}

/// Specific threat types within each vector category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ThreatType {
    // Email threats
    Phishing,
    Spearphishing,
    BusinessEmailCompromise,
    MaliciousAttachment,
    DomainSpoofing,
    
    // Voice threats  
    Vishing,
    CallCenterImpersonation,
    VoicemailPhishing,
    
    // SMS threats
    Smishing,
    SmsPhishing,
    MaliciousSmsLink,
    
    // Web threats
    WateringHole,
    FakeLoginPortal,
    MaliciousDownload,
    TyposquattingDomain,
    
    // File threats
    UnsignedSoftware,
    HashMismatch,
    TamperedUpdate,
    MalwareSignature,
    
    // Social media threats
    FakeProfile,
    SocialEngineering,
    InformationLeakage,
    ReconnaissanceActivity,
    
    // Identity threats
    PasswordResetFraud,
    AccountTakeover,
    CredentialHarvesting,
    MultifactorBypass,
    
    // Network threats
    SuspiciousLogin,
    AnomalousAccess,
    CredentialReuse,
    SessionHijacking,
}

/// Severity level for security threats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ThreatSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl ThreatSeverity {
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

// ── Security events ────────────────────────────────────────────────

/// A detected security threat event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatEvent {
    /// Unique identifier for this event.
    pub id: String,
    /// Entity (node) where the threat was detected.
    pub entity_id: EntityId,
    /// When the threat was detected.
    pub timestamp: Timestamp,
    /// Threat classification.
    pub threat_vector: ThreatVector,
    pub threat_type: ThreatType,
    pub severity: ThreatSeverity,
    /// Risk score (0.0 = benign, 1.0 = definite threat).
    pub risk_score: f64,
    /// Confidence in the threat detection.
    pub confidence: Confidence,
    /// Human-readable description.
    pub description: String,
    /// Source of the threat detection (email gateway, WAF, etc.).
    pub detection_source: String,
    /// Raw indicators and metadata.
    pub indicators: ThreatIndicators,
    /// Whether this event has been investigated.
    pub investigated: bool,
    /// Investigation notes (if any).
    pub notes: String,
}

/// Threat indicators and metadata for different attack vectors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIndicators {
    /// Email-related indicators.
    pub email: Option<EmailIndicators>,
    /// Voice call indicators.
    pub voice: Option<VoiceIndicators>,
    /// SMS indicators.
    pub sms: Option<SmsIndicators>,
    /// Web/URL indicators.
    pub web: Option<WebIndicators>,
    /// File integrity indicators.
    pub file: Option<FileIndicators>,
    /// Social media indicators.
    pub social: Option<SocialIndicators>,
    /// Identity verification indicators.
    pub identity: Option<IdentityIndicators>,
    /// Network access indicators.
    pub network: Option<NetworkIndicators>,
}

// ── Indicator types ────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailIndicators {
    /// Sender address and display name.
    pub from_address: String,
    pub display_name: Option<String>,
    /// Subject line.
    pub subject: String,
    /// SPF/DKIM/DMARC authentication results.
    pub spf_pass: Option<bool>,
    pub dkim_pass: Option<bool>,
    pub dmarc_pass: Option<bool>,
    /// Suspicious elements detected.
    pub suspicious_links: Vec<String>,
    pub suspicious_attachments: Vec<String>,
    /// Language analysis results.
    pub urgency_keywords: Vec<String>,
    pub typos_detected: bool,
    /// Financial transaction indicators (for BEC).
    pub financial_keywords: bool,
    pub payment_request: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoiceIndicators {
    /// Caller ID information.
    pub caller_number: String,
    pub caller_name: Option<String>,
    /// Call characteristics.
    pub call_duration_seconds: u32,
    pub background_noise: bool,
    pub voice_stress_detected: bool,
    /// Social engineering tactics.
    pub urgency_language: bool,
    pub authority_claim: bool,
    pub information_request: bool,
    /// Verification bypass attempts.
    pub security_question_bypass: bool,
    pub callback_refusal: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmsIndicators {
    /// Sender information.
    pub sender_number: String,
    pub sender_name: Option<String>,
    /// Message content analysis.
    pub message_content: String,
    pub suspicious_links: Vec<String>,
    pub urgency_keywords: Vec<String>,
    /// Technical indicators.
    pub spoofed_sender: bool,
    pub link_shorteners: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebIndicators {
    /// URL and domain analysis.
    pub url: String,
    pub domain: String,
    pub subdomain_suspicious: bool,
    pub typosquatting_detected: bool,
    /// SSL/TLS information.
    pub ssl_valid: bool,
    pub certificate_authority: Option<String>,
    pub certificate_age_days: Option<u32>,
    /// Content analysis.
    pub login_form_detected: bool,
    pub credential_fields: Vec<String>,
    pub brand_impersonation: Option<String>,
    /// Reputation scoring.
    pub domain_age_days: Option<u32>,
    pub reputation_score: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileIndicators {
    /// File metadata.
    pub filename: String,
    pub file_size: u64,
    pub file_type: String,
    pub mime_type: String,
    /// Cryptographic verification.
    pub expected_hash: Option<String>,
    pub actual_hash: Option<String>,
    pub hash_algorithm: Option<String>,
    /// Digital signature verification.
    pub signature_valid: Option<bool>,
    pub signer: Option<String>,
    pub signature_timestamp: Option<Timestamp>,
    /// Malware scanning results.
    pub virus_total_score: Option<u32>,
    pub malware_detected: bool,
    pub suspicious_entropy: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocialIndicators {
    /// Platform and account information.
    pub platform: String,
    pub account_handle: String,
    pub account_age_days: Option<u32>,
    pub follower_count: Option<u32>,
    /// Content analysis.
    pub posts_analyzed: u32,
    pub sensitive_info_disclosed: Vec<String>,
    pub company_mentions: u32,
    pub employee_interactions: u32,
    /// Risk factors.
    pub fake_profile_score: Option<f64>,
    pub reconnaissance_indicators: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityIndicators {
    /// Request details.
    pub request_type: String,
    pub requested_account: String,
    pub requester_info: String,
    /// Verification process.
    pub verification_questions_asked: u32,
    pub verification_questions_correct: u32,
    pub callback_verification_attempted: bool,
    /// Risk factors.
    pub request_urgency: bool,
    pub unusual_request_time: bool,
    pub geographic_anomaly: bool,
    pub previous_failed_attempts: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkIndicators {
    /// Access details.
    pub source_ip: String,
    pub user_agent: Option<String>,
    pub login_method: String,
    /// Behavioral analysis.
    pub login_time_anomaly: bool,
    pub geographic_anomaly: bool,
    pub device_fingerprint_mismatch: bool,
    pub concurrent_sessions: u32,
    /// Credential analysis.
    pub password_spray_detected: bool,
    pub credential_stuffing: bool,
    pub brute_force_detected: bool,
    pub successful_login_after_failures: bool,
}

// ── Risk assessment ────────────────────────────────────────────────

/// Aggregated risk score for an entity over time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityRiskProfile {
    pub entity_id: EntityId,
    /// Overall risk score (0.0 = low risk, 1.0 = high risk).
    pub overall_risk_score: f64,
    /// Risk scores by threat vector.
    pub vector_scores: HashMap<ThreatVector, f64>,
    /// Recent threat count by severity.
    pub threat_counts: HashMap<ThreatSeverity, u32>,
    /// Risk trend (increasing/decreasing over time).
    pub risk_trend: f64,
    /// Confidence in the risk assessment.
    pub confidence: Confidence,
    /// Number of events in the assessment window.
    pub sample_count: usize,
    /// Timestamp of the most recent threat event.
    pub last_threat_detected: Option<Timestamp>,
    /// Human-readable risk summary.
    pub risk_summary: String,
}

/// Attack surface assessment for an organization or entity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackSurfaceReport {
    pub timestamp: Timestamp,
    /// Entity risk profiles.
    pub entity_risks: HashMap<EntityId, EntityRiskProfile>,
    /// Threat vector exposure levels.
    pub vector_exposure: HashMap<ThreatVector, f64>,
    /// High-risk entities requiring attention.
    pub high_risk_entities: Vec<EntityId>,
    /// Common attack patterns observed.
    pub attack_patterns: Vec<AttackPattern>,
    /// Overall organizational security posture.
    pub security_posture_score: f64,
    /// Executive summary.
    pub executive_summary: String,
}

/// Observed attack pattern across multiple entities.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPattern {
    /// Pattern identifier.
    pub pattern_id: String,
    /// Threat types involved in this pattern.
    pub threat_types: Vec<ThreatType>,
    /// Entities affected by this pattern.
    pub affected_entities: Vec<EntityId>,
    /// Timeline of the attack pattern.
    pub first_seen: Timestamp,
    pub last_seen: Timestamp,
    /// Pattern characteristics.
    pub frequency: u32,
    pub success_rate: f64,
    pub description: String,
}

// ── Configuration and targets ──────────────────────────────────────

/// Configuration for monitoring a specific security endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityTarget {
    /// The graph entity this target monitors.
    pub entity_id: EntityId,
    /// Type of security monitoring to perform.
    pub monitoring_type: MonitoringType,
    /// Target-specific configuration.
    pub config: SecurityTargetConfig,
    /// Human-readable label.
    pub label: String,
    /// Whether monitoring is enabled.
    pub enabled: bool,
}

/// Type of security monitoring to perform.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MonitoringType {
    EmailGateway,
    WebProxy,
    CredentialHoneypot,
    CallCenterMonitoring,
    SmsGateway,
    FileIntegrityCheck,
    SocialMediaMonitoring,
    IdentityVerificationAudit,
    NetworkAccessMonitoring,
}

/// Security target configuration parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityTargetConfig {
    /// Monitoring interval.
    #[serde(with = "serde_duration_seconds")]
    pub check_interval: Duration,
    /// Risk score threshold for alerting.
    pub alert_threshold: f64,
    /// Confidence threshold for threat detection.
    pub confidence_threshold: f64,
    /// Target-specific parameters.
    pub parameters: HashMap<String, String>,
}

impl SecurityTarget {
    /// Create a new email gateway monitoring target.
    pub fn email_gateway(entity_id: EntityId, label: impl Into<String>) -> Self {
        Self {
            entity_id,
            monitoring_type: MonitoringType::EmailGateway,
            config: SecurityTargetConfig {
                check_interval: Duration::from_secs(300), // 5 minutes
                alert_threshold: 0.7,
                confidence_threshold: 0.8,
                parameters: HashMap::new(),
            },
            label: label.into(),
            enabled: true,
        }
    }

    /// Create a new web proxy monitoring target.
    pub fn web_proxy(entity_id: EntityId, label: impl Into<String>) -> Self {
        let mut target = Self::email_gateway(entity_id, label);
        target.monitoring_type = MonitoringType::WebProxy;
        target.config.check_interval = Duration::from_secs(60); // 1 minute
        target
    }

    /// Create a new credential honeypot monitoring target.
    pub fn credential_honeypot(entity_id: EntityId, label: impl Into<String>) -> Self {
        let mut target = Self::email_gateway(entity_id, label);
        target.monitoring_type = MonitoringType::CredentialHoneypot;
        target.config.check_interval = Duration::from_secs(30); // 30 seconds
        target.config.alert_threshold = 0.5; // Lower threshold for honeypots
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
