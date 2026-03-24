//! Network security and administrative monitoring types for the Skeletrace network engine.
//!
//! These types implement network security patterns from comprehensive infrastructure domains:
//! - Corporate Wi-Fi network security with WPA3 Enterprise configuration monitoring
//! - SSH key usage auditing and password rotation policy enforcement
//! - RDP security deployment using network-level authentication and gateway monitoring
//! - Multi-factor authentication implementation monitoring for banking web applications
//! - ARP spoofing attack detection using advanced network monitoring tools
//! - BGP routing validation using RPKI to prevent route hijacking attacks
//! - Deserialization vulnerability patching in Java web application frameworks
//! - DNS query monitoring for cache poisoning attempt detection
//! - Active Directory security against pass-the-hash attacks with credential guard
//! - Linux system auditing for race condition vulnerabilities in setuid programs

use std::collections::HashMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::types::{Confidence, EntityId, Timestamp};

// ── Network security categories ────────────────────────────────────

/// Primary network security vector categories for infrastructure monitoring.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NetworkSecurityVector {
    /// Wireless network protection (WPA3 Enterprise, corporate Wi-Fi security).
    Wireless,
    /// Remote access security (SSH keys, RDP configuration, authentication).
    RemoteAccess,
    /// Authentication systems (MFA, banking applications, identity management).
    Authentication,
    /// Network protocol security (ARP, BGP, DNS protection).
    Protocol,
    /// Application security (deserialization, Java frameworks, web applications).
    Application,
    /// Directory services (Active Directory, credential management, pass-the-hash).
    Directory,
    /// System administration (Linux auditing, setuid vulnerabilities, race conditions).
    SystemAdmin,
}

/// Specific network security violation types within each vector category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NetworkViolationType {
    // Wireless security violations
    WeakWifiEncryption,
    WifiConfigurationError,
    UnauthorizedAccessPoint,
    WPA3EnterpriseViolation,
    
    // Remote access violations
    WeakSshConfiguration,
    ExpiredSshKeys,
    PasswordPolicyViolation,
    RdpSecurityViolation,
    
    // Authentication violations
    MfaBypassAttempt,
    WeakAuthenticationMethod,
    AuthenticationFailure,
    SessionManagementError,
    
    // Protocol security violations
    ArpSpoofingDetected,
    BgpHijackingAttempt,
    DnsCachePoisoning,
    RouteValidationFailure,
    
    // Application security violations
    DeserializationVulnerability,
    JavaFrameworkExploit,
    WebApplicationCompromise,
    UnpatchedVulnerability,
    
    // Directory service violations
    PassTheHashAttempt,
    ActiveDirectoryCompromise,
    CredentialTheftDetected,
    PrivilegeEscalationAttempt,
    
    // System administration violations
    RaceConditionExploit,
    SetuidVulnerability,
    SystemPrivilegeViolation,
    ConfigurationDrift,
}

/// Severity level for network security violations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum NetworkViolationSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl NetworkViolationSeverity {
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

/// Network security compliance framework for assessment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NetworkSecurityFramework {
    /// NIST Cybersecurity Framework.
    NistCsf,
    /// Center for Internet Security Controls.
    CisControls,
    /// ISO/IEC 27001 Information Security Management.
    Iso27001,
    /// SANS Critical Security Controls.
    SansCritical,
    /// Federal Information Security Management Act.
    Fisma,
    /// Payment Card Industry Network Security Standard.
    PciNss,
    /// SOC 2 Network Security Trust Services.
    Soc2Network,
}

// ── Network security breach events ─────────────────────────────────

/// A detected network security violation or infrastructure breach.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSecurityEvent {
    /// Unique identifier for this event.
    pub id: String,
    /// Entity (node) where the violation was detected.
    pub entity_id: EntityId,
    /// When the violation was detected.
    pub timestamp: Timestamp,
    /// Network security classification.
    pub security_vector: NetworkSecurityVector,
    /// Specific violation type.
    pub violation_type: NetworkViolationType,
    /// Violation severity level.
    pub severity: NetworkViolationSeverity,
    /// Risk score (0.0-1.0).
    pub risk_score: f64,
    /// Detection confidence (0.0-1.0).
    pub confidence: Confidence,
    /// Affected network assets and systems.
    pub affected_assets: Vec<String>,
    /// Network security indicators and evidence.
    pub indicators: NetworkSecurityIndicators,
    /// Compliance framework violations.
    pub compliance_violations: Vec<NetworkComplianceViolation>,
    /// Remediation recommendations.
    pub remediation: NetworkRemediationGuidance,
}

/// Network security indicators and evidence for forensic analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSecurityIndicators {
    /// Wireless security indicators.
    pub wireless: Option<WirelessIndicators>,
    /// Remote access security indicators.
    pub remote_access: Option<RemoteAccessIndicators>,
    /// Authentication system indicators.
    pub authentication: Option<AuthenticationIndicators>,
    /// Network protocol indicators.
    pub protocol: Option<ProtocolIndicators>,
    /// Application security indicators.
    pub application: Option<ApplicationIndicators>,
    /// Directory service indicators.
    pub directory: Option<DirectoryIndicators>,
    /// System administration indicators.
    pub system_admin: Option<SystemAdminIndicators>,
}

/// Wireless network security indicators.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WirelessIndicators {
    /// SSID and network configuration.
    pub network_config: String,
    /// Encryption method and strength.
    pub encryption_method: String,
    /// Authentication protocol version.
    pub auth_protocol: String,
    /// Enterprise security configuration.
    pub enterprise_config: bool,
    /// Detected security weaknesses.
    pub security_weaknesses: Vec<String>,
}

/// Remote access security indicators.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteAccessIndicators {
    /// SSH configuration details.
    pub ssh_config: String,
    /// Key management status.
    pub key_management: String,
    /// Password policy compliance.
    pub password_policy: String,
    /// RDP security configuration.
    pub rdp_security: String,
    /// Network-level authentication status.
    pub network_auth: bool,
}

/// Authentication system security indicators.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationIndicators {
    /// MFA implementation status.
    pub mfa_status: String,
    /// Authentication method strength.
    pub auth_strength: String,
    /// Session management configuration.
    pub session_management: String,
    /// Banking application security.
    pub banking_security: String,
    /// Identity provider configuration.
    pub identity_provider: String,
}

/// Network protocol security indicators.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolIndicators {
    /// ARP table analysis.
    pub arp_analysis: String,
    /// BGP routing validation.
    pub bgp_validation: String,
    /// DNS security configuration.
    pub dns_security: String,
    /// RPKI deployment status.
    pub rpki_status: String,
    /// Route hijacking indicators.
    pub route_hijacking: Vec<String>,
}

/// Application security indicators.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplicationIndicators {
    /// Java framework version and patches.
    pub java_framework: String,
    /// Deserialization vulnerability status.
    pub deserialization_status: String,
    /// Web application security.
    pub webapp_security: String,
    /// Patch management compliance.
    pub patch_management: String,
    /// Vulnerability scan results.
    pub vulnerability_scan: Vec<String>,
}

/// Directory service security indicators.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectoryIndicators {
    /// Active Directory configuration.
    pub ad_config: String,
    /// Credential guard status.
    pub credential_guard: bool,
    /// Pass-the-hash protection.
    pub pth_protection: String,
    /// Domain security policies.
    pub domain_policies: String,
    /// Authentication audit logs.
    pub auth_logs: Vec<String>,
}

/// System administration security indicators.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemAdminIndicators {
    /// Linux system configuration.
    pub linux_config: String,
    /// Setuid program audit.
    pub setuid_audit: String,
    /// Race condition analysis.
    pub race_condition: String,
    /// System privilege monitoring.
    pub privilege_monitoring: String,
    /// Configuration drift detection.
    pub config_drift: Vec<String>,
}

/// Network security compliance violation details.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkComplianceViolation {
    /// Compliance framework violated.
    pub framework: NetworkSecurityFramework,
    /// Specific control or requirement.
    pub control: String,
    /// Framework requirement violated.
    pub requirement: String,
    /// Detailed violation description.
    pub violation_description: String,
    /// Potential penalty or impact.
    pub potential_penalty: Option<f64>,
    /// Remediation deadline.
    pub remediation_deadline: Option<Duration>,
}

/// Network security remediation guidance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkRemediationGuidance {
    /// Immediate action required.
    pub immediate_action: String,
    /// Step-by-step remediation plan.
    pub remediation_steps: Vec<String>,
    /// Long-term security improvements.
    pub long_term_improvements: Vec<String>,
    /// Estimated remediation time.
    pub estimated_time: Duration,
    /// Required resources and tools.
    pub required_resources: Vec<String>,
}

// ── Network monitoring targets ─────────────────────────────────────

/// Network security monitoring configuration type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NetworkMonitoringType {
    /// Wi-Fi network security monitoring.
    WirelessSecurity,
    /// Remote access security monitoring.
    RemoteAccessSecurity,
    /// Authentication system monitoring.
    AuthenticationSecurity,
    /// Network protocol security monitoring.
    ProtocolSecurity,
    /// Application security monitoring.
    ApplicationSecurity,
    /// Directory service security monitoring.
    DirectorySecurity,
    /// System administration monitoring.
    SystemAdminSecurity,
}

/// Network security monitoring target configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSecurityTarget {
    /// Target entity identifier.
    pub entity_id: EntityId,
    /// Monitoring configuration.
    pub config: NetworkMonitoringConfig,
    /// Type of network monitoring.
    pub monitoring_type: NetworkMonitoringType,
    /// Target description.
    pub label: String,
    /// Monitoring enabled status.
    pub enabled: bool,
}

/// Network security monitoring configuration parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkMonitoringConfig {
    /// Monitoring check interval.
    pub check_interval: Duration,
    /// Alert threshold (0.0-1.0).
    pub alert_threshold: f64,
    /// Confidence threshold (0.0-1.0).
    pub confidence_threshold: f64,
    /// Applicable compliance frameworks.
    pub compliance_frameworks: Vec<NetworkSecurityFramework>,
    /// Custom monitoring parameters.
    pub parameters: HashMap<String, String>,
}

impl NetworkSecurityTarget {
    /// Create a new Wi-Fi security monitoring target.
    pub fn wifi_security(entity_id: EntityId, label: impl Into<String>) -> Self {
        Self {
            entity_id,
            monitoring_type: NetworkMonitoringType::WirelessSecurity,
            config: NetworkMonitoringConfig {
                check_interval: Duration::from_secs(300), // 5 minutes
                alert_threshold: 0.7,
                confidence_threshold: 0.8,
                compliance_frameworks: vec![NetworkSecurityFramework::NistCsf, NetworkSecurityFramework::CisControls],
                parameters: HashMap::new(),
            },
            label: label.into(),
            enabled: true,
        }
    }

    /// Create a new remote access security monitoring target.
    pub fn remote_access_security(entity_id: EntityId, label: impl Into<String>) -> Self {
        let mut target = Self::wifi_security(entity_id, label);
        target.monitoring_type = NetworkMonitoringType::RemoteAccessSecurity;
        target.config.check_interval = Duration::from_secs(600); // 10 minutes
        target.config.compliance_frameworks = vec![NetworkSecurityFramework::NistCsf, NetworkSecurityFramework::SansCritical];
        target
    }

    /// Create a new authentication security monitoring target.
    pub fn authentication_security(entity_id: EntityId, label: impl Into<String>) -> Self {
        let mut target = Self::wifi_security(entity_id, label);
        target.monitoring_type = NetworkMonitoringType::AuthenticationSecurity;
        target.config.check_interval = Duration::from_secs(180); // 3 minutes
        target.config.compliance_frameworks = vec![NetworkSecurityFramework::PciNss, NetworkSecurityFramework::Soc2Network];
        target
    }

    /// Create a new protocol security monitoring target.
    pub fn protocol_security(entity_id: EntityId, label: impl Into<String>) -> Self {
        let mut target = Self::wifi_security(entity_id, label);
        target.monitoring_type = NetworkMonitoringType::ProtocolSecurity;
        target.config.check_interval = Duration::from_secs(120); // 2 minutes
        target.config.compliance_frameworks = vec![NetworkSecurityFramework::NistCsf, NetworkSecurityFramework::Iso27001];
        target
    }

    /// Create a new application security monitoring target.
    pub fn application_security(entity_id: EntityId, label: impl Into<String>) -> Self {
        let mut target = Self::wifi_security(entity_id, label);
        target.monitoring_type = NetworkMonitoringType::ApplicationSecurity;
        target.config.check_interval = Duration::from_secs(900); // 15 minutes
        target.config.compliance_frameworks = vec![NetworkSecurityFramework::NistCsf, NetworkSecurityFramework::CisControls];
        target
    }

    /// Create a new directory security monitoring target.
    pub fn directory_security(entity_id: EntityId, label: impl Into<String>) -> Self {
        let mut target = Self::wifi_security(entity_id, label);
        target.monitoring_type = NetworkMonitoringType::DirectorySecurity;
        target.config.check_interval = Duration::from_secs(600); // 10 minutes
        target.config.compliance_frameworks = vec![NetworkSecurityFramework::NistCsf, NetworkSecurityFramework::Fisma];
        target
    }

    /// Create a new system admin security monitoring target.
    pub fn system_admin_security(entity_id: EntityId, label: impl Into<String>) -> Self {
        let mut target = Self::wifi_security(entity_id, label);
        target.monitoring_type = NetworkMonitoringType::SystemAdminSecurity;
        target.config.check_interval = Duration::from_secs(1800); // 30 minutes
        target.config.compliance_frameworks = vec![NetworkSecurityFramework::CisControls, NetworkSecurityFramework::SansCritical];
        target
    }
}

// ── Data subject impact and entity profiling ─────────────────────

/// Network security profile for an entity (node).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityNetworkProfile {
    /// Entity identifier.
    pub entity_id: EntityId,
    /// Network security posture score (0.0-1.0).
    pub security_posture: f64,
    /// Active network violations.
    pub active_violations: Vec<NetworkViolationType>,
    /// Network compliance scores by framework.
    pub compliance_scores: HashMap<NetworkSecurityFramework, f64>,
    /// Last assessment timestamp.
    pub last_assessment: Timestamp,
    /// Network protection recommendations.
    pub recommendations: Vec<String>,
}

/// Network security compliance assessment report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkComplianceReport {
    /// Overall network security posture (0.0-1.0).
    pub network_security_posture: f64,
    /// Compliance scores by framework.
    pub framework_scores: HashMap<NetworkSecurityFramework, f64>,
    /// High-risk network entities.
    pub high_risk_entities: Vec<EntityId>,
    /// Network protection gap analysis.
    pub protection_gaps: Vec<String>,
    /// Executive summary and recommendations.
    pub executive_summary: String,
    /// Report generation timestamp.
    pub generated_at: Timestamp,
}

/// Network asset information for impact assessment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkAsset {
    /// Asset identifier.
    pub id: String,
    /// Asset type and category.
    pub asset_type: String,
    /// Asset criticality level.
    pub criticality: AssetCriticality,
    /// Associated compliance requirements.
    pub compliance_requirements: Vec<NetworkSecurityFramework>,
    /// Asset location and network segment.
    pub network_location: String,
}

/// Network asset criticality classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AssetCriticality {
    /// Low-impact assets.
    Low,
    /// Medium-impact assets.
    Medium,
    /// High-impact business critical assets.
    High,
    /// Mission-critical infrastructure assets.
    Critical,
}

impl AssetCriticality {
    pub fn impact_multiplier(&self) -> f64 {
        match self {
            Self::Low => 1.0,
            Self::Medium => 2.0,
            Self::High => 4.0,
            Self::Critical => 8.0,
        }
    }
}
