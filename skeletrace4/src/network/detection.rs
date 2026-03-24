//! Network security violation detection algorithms for comprehensive infrastructure monitoring.
//!
//! This module implements detection patterns from all major network security domains:
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

use std::time::Duration;

use crate::network::types::{
    ApplicationIndicators, AuthenticationIndicators, DirectoryIndicators,
    NetworkComplianceViolation, NetworkSecurityEvent, NetworkSecurityFramework,
    NetworkSecurityIndicators, NetworkViolationSeverity, NetworkViolationType,
    NetworkSecurityVector, ProtocolIndicators, RemoteAccessIndicators,
    SystemAdminIndicators, WirelessIndicators, NetworkRemediationGuidance,
};
use crate::types::{Confidence, EntityId, Timestamp};

// ── Wireless security detection ───────────────────────────────────

/// Wireless network security analyzer for Wi-Fi and enterprise configuration compliance.
#[derive(Debug)]
pub struct WirelessDetector {
    /// Required Wi-Fi encryption standards.
    required_encryption: Vec<String>,
    /// Enterprise authentication requirements.
    enterprise_requirements: Vec<String>,
    /// Maximum allowed configuration deviation.
    max_deviation_score: f64,
}

impl WirelessDetector {
    pub fn new() -> Self {
        Self {
            required_encryption: vec![
                "WPA3-Enterprise".to_string(),
                "WPA3-Personal".to_string(),
                "WPA2-Enterprise".to_string(),
            ],
            enterprise_requirements: vec![
                "802.1X".to_string(),
                "RADIUS".to_string(),
                "EAP-TLS".to_string(),
                "Certificate Authentication".to_string(),
            ],
            max_deviation_score: 0.3,
        }
    }

    /// Analyze Wi-Fi configuration for security violations.
    pub fn analyze_wifi_security(
        &self,
        entity_id: EntityId,
        wifi_config: &WifiConfiguration,
    ) -> Option<NetworkSecurityEvent> {
        let mut risk_score: f64 = 0.0;
        let mut violations = Vec::new();
        let mut compliance_violations = Vec::new();

        // Check WPA3 Enterprise configuration
        if !wifi_config.encryption_method.contains("WPA3") {
            risk_score += 0.6;
            violations.push(NetworkViolationType::WeakWifiEncryption);
            
            // NIST CSF violation for weak wireless encryption
            compliance_violations.push(NetworkComplianceViolation {
                framework: NetworkSecurityFramework::NistCsf,
                control: "PR.DS-1".to_string(),
                requirement: "Data-in-transit is protected".to_string(),
                violation_description: "Wi-Fi network lacks WPA3 encryption".to_string(),
                potential_penalty: Some(500_000.0), // Security breach penalty
                remediation_deadline: Some(Duration::from_secs(48 * 3600)), // 48 hours
            });
        }

        // Check enterprise authentication configuration
        if !wifi_config.enterprise_mode && wifi_config.network_type == "Corporate" {
            risk_score += 0.7;
            violations.push(NetworkViolationType::WPA3EnterpriseViolation);
            
            compliance_violations.push(NetworkComplianceViolation {
                framework: NetworkSecurityFramework::CisControls,
                control: "CIS Control 12".to_string(),
                requirement: "Boundary Defense".to_string(),
                violation_description: "Corporate Wi-Fi lacks enterprise authentication".to_string(),
                potential_penalty: Some(250_000.0),
                remediation_deadline: Some(Duration::from_secs(72 * 3600)), // 72 hours
            });
        }

        if risk_score > 0.3 && !violations.is_empty() {
            let severity = self.calculate_severity(risk_score);
            Some(self.create_wifi_security_event(
                entity_id,
                risk_score,
                violations[0],
                severity,
                wifi_config,
                compliance_violations,
            ))
        } else {
            None
        }
    }

    fn calculate_severity(&self, risk_score: f64) -> NetworkViolationSeverity {
        match risk_score {
            s if s >= 0.8 => NetworkViolationSeverity::Critical,
            s if s >= 0.6 => NetworkViolationSeverity::High,
            s if s >= 0.4 => NetworkViolationSeverity::Medium,
            s if s >= 0.2 => NetworkViolationSeverity::Low,
            _ => NetworkViolationSeverity::Info,
        }
    }

    fn create_wifi_security_event(
        &self,
        entity_id: EntityId,
        risk_score: f64,
        violation_type: NetworkViolationType,
        severity: NetworkViolationSeverity,
        wifi_config: &WifiConfiguration,
        compliance_violations: Vec<NetworkComplianceViolation>,
    ) -> NetworkSecurityEvent {
        NetworkSecurityEvent {
            id: format!("wifi-{}", uuid::Uuid::new_v4()),
            entity_id,
            timestamp: chrono::Utc::now(),
            security_vector: NetworkSecurityVector::Wireless,
            violation_type,
            severity,
            risk_score,
            confidence: Confidence::new(0.9),
            affected_assets: vec![wifi_config.ssid.clone()],
            indicators: NetworkSecurityIndicators {
                wireless: Some(WirelessIndicators {
                    network_config: format!("SSID: {}, Type: {}", wifi_config.ssid, wifi_config.network_type),
                    encryption_method: wifi_config.encryption_method.clone(),
                    auth_protocol: wifi_config.auth_protocol.clone(),
                    enterprise_config: wifi_config.enterprise_mode,
                    security_weaknesses: wifi_config.detected_weaknesses.clone(),
                }),
                remote_access: None,
                authentication: None,
                protocol: None,
                application: None,
                directory: None,
                system_admin: None,
            },
            compliance_violations,
            remediation: NetworkRemediationGuidance {
                immediate_action: "Upgrade to WPA3-Enterprise with 802.1X authentication".to_string(),
                remediation_steps: vec![
                    "Deploy RADIUS server for enterprise authentication".to_string(),
                    "Configure 802.1X with EAP-TLS certificate authentication".to_string(),
                    "Update all wireless access points to WPA3".to_string(),
                    "Test enterprise authentication functionality".to_string(),
                ],
                long_term_improvements: vec![
                    "Implement network access control (NAC)".to_string(),
                    "Deploy wireless intrusion detection system (WIDS)".to_string(),
                ],
                estimated_time: Duration::from_secs(48 * 3600), // 48 hours
                required_resources: vec!["RADIUS server".to_string(), "SSL certificates".to_string()],
            },
        }
    }
}

/// Wi-Fi network configuration data.
#[derive(Debug, Clone)]
pub struct WifiConfiguration {
    pub ssid: String,
    pub network_type: String,
    pub encryption_method: String,
    pub auth_protocol: String,
    pub enterprise_mode: bool,
    pub detected_weaknesses: Vec<String>,
}

// ── Remote access security detection ──────────────────────────────

/// Remote access security analyzer for SSH and RDP configuration compliance.
#[derive(Debug)]
pub struct RemoteAccessDetector {
    /// Maximum allowed SSH key age in days.
    max_ssh_key_age_days: u32,
    /// Required password policy settings.
    password_policy_requirements: Vec<String>,
    /// RDP security requirements.
    rdp_security_requirements: Vec<String>,
}

impl RemoteAccessDetector {
    pub fn new() -> Self {
        Self {
            max_ssh_key_age_days: 365,
            password_policy_requirements: vec![
                "Minimum 12 characters".to_string(),
                "Complexity requirements".to_string(),
                "90-day expiration".to_string(),
                "Password history: 24".to_string(),
            ],
            rdp_security_requirements: vec![
                "Network Level Authentication".to_string(),
                "SSL/TLS encryption".to_string(),
                "Gateway deployment".to_string(),
                "Multi-factor authentication".to_string(),
            ],
        }
    }

    /// Analyze remote access configuration for security violations.
    pub fn analyze_remote_access(
        &self,
        entity_id: EntityId,
        remote_config: &RemoteAccessConfig,
    ) -> Option<NetworkSecurityEvent> {
        let mut risk_score: f64 = 0.0;
        let mut violations = Vec::new();
        let mut compliance_violations = Vec::new();

        // Check SSH key age and rotation
        if remote_config.ssh_key_age_days > self.max_ssh_key_age_days {
            risk_score += 0.5;
            violations.push(NetworkViolationType::ExpiredSshKeys);
        }

        // Check password policy compliance
        if !remote_config.password_policy_compliant {
            risk_score += 0.6;
            violations.push(NetworkViolationType::PasswordPolicyViolation);
            
            compliance_violations.push(NetworkComplianceViolation {
                framework: NetworkSecurityFramework::NistCsf,
                control: "PR.AC-7".to_string(),
                requirement: "Users and devices are authenticated".to_string(),
                violation_description: "Password policy does not meet security requirements".to_string(),
                potential_penalty: Some(100_000.0),
                remediation_deadline: Some(Duration::from_secs(72 * 3600)),
            });
        }

        // Check RDP security configuration
        if !remote_config.rdp_nla_enabled {
            risk_score += 0.8;
            violations.push(NetworkViolationType::RdpSecurityViolation);
            
            compliance_violations.push(NetworkComplianceViolation {
                framework: NetworkSecurityFramework::SansCritical,
                control: "CSC 4".to_string(),
                requirement: "Controlled Use of Administrative Privileges".to_string(),
                violation_description: "RDP lacks Network Level Authentication".to_string(),
                potential_penalty: Some(300_000.0),
                remediation_deadline: Some(Duration::from_secs(24 * 3600)), // 24 hours
            });
        }

        if risk_score > 0.3 && !violations.is_empty() {
            let severity = self.calculate_severity(risk_score);
            Some(self.create_remote_access_event(
                entity_id,
                risk_score,
                violations[0],
                severity,
                remote_config,
                compliance_violations,
            ))
        } else {
            None
        }
    }

    fn calculate_severity(&self, risk_score: f64) -> NetworkViolationSeverity {
        match risk_score {
            s if s >= 0.8 => NetworkViolationSeverity::Critical,
            s if s >= 0.6 => NetworkViolationSeverity::High,
            s if s >= 0.4 => NetworkViolationSeverity::Medium,
            s if s >= 0.2 => NetworkViolationSeverity::Low,
            _ => NetworkViolationSeverity::Info,
        }
    }

    fn create_remote_access_event(
        &self,
        entity_id: EntityId,
        risk_score: f64,
        violation_type: NetworkViolationType,
        severity: NetworkViolationSeverity,
        remote_config: &RemoteAccessConfig,
        compliance_violations: Vec<NetworkComplianceViolation>,
    ) -> NetworkSecurityEvent {
        NetworkSecurityEvent {
            id: format!("remote-{}", uuid::Uuid::new_v4()),
            entity_id,
            timestamp: chrono::Utc::now(),
            security_vector: NetworkSecurityVector::RemoteAccess,
            violation_type,
            severity,
            risk_score,
            confidence: Confidence::new(0.85),
            affected_assets: vec!["SSH service".to_string(), "RDP service".to_string()],
            indicators: NetworkSecurityIndicators {
                wireless: None,
                remote_access: Some(RemoteAccessIndicators {
                    ssh_config: format!("Key age: {} days", remote_config.ssh_key_age_days),
                    key_management: remote_config.key_management_status.clone(),
                    password_policy: format!("Compliant: {}", remote_config.password_policy_compliant),
                    rdp_security: format!("NLA: {}, Gateway: {}", remote_config.rdp_nla_enabled, remote_config.rdp_gateway_enabled),
                    network_auth: remote_config.rdp_nla_enabled,
                }),
                authentication: None,
                protocol: None,
                application: None,
                directory: None,
                system_admin: None,
            },
            compliance_violations,
            remediation: NetworkRemediationGuidance {
                immediate_action: "Enable Network Level Authentication for RDP and rotate SSH keys".to_string(),
                remediation_steps: vec![
                    "Configure RDP Network Level Authentication".to_string(),
                    "Deploy RDP gateway with SSL/TLS encryption".to_string(),
                    "Implement SSH key rotation policy".to_string(),
                    "Enforce strong password policy requirements".to_string(),
                ],
                long_term_improvements: vec![
                    "Implement privileged access management (PAM)".to_string(),
                    "Deploy jump servers for administrative access".to_string(),
                ],
                estimated_time: Duration::from_secs(24 * 3600), // 24 hours
                required_resources: vec!["RDP gateway".to_string(), "SSL certificates".to_string()],
            },
        }
    }
}

/// Remote access configuration data.
#[derive(Debug, Clone)]
pub struct RemoteAccessConfig {
    pub ssh_key_age_days: u32,
    pub key_management_status: String,
    pub password_policy_compliant: bool,
    pub rdp_nla_enabled: bool,
    pub rdp_gateway_enabled: bool,
}

// ── Authentication security detection ──────────────────────────────

/// Authentication security analyzer for MFA and banking application monitoring.
#[derive(Debug)]
pub struct AuthenticationDetector {
    /// Required MFA methods.
    required_mfa_methods: Vec<String>,
    /// Banking application security requirements.
    banking_security_requirements: Vec<String>,
    /// Maximum session timeout.
    max_session_timeout: Duration,
}

impl AuthenticationDetector {
    pub fn new() -> Self {
        Self {
            required_mfa_methods: vec![
                "TOTP".to_string(),
                "SMS".to_string(),
                "Hardware Token".to_string(),
                "Biometric".to_string(),
            ],
            banking_security_requirements: vec![
                "Multi-factor authentication".to_string(),
                "Device registration".to_string(),
                "Transaction signing".to_string(),
                "Fraud detection".to_string(),
            ],
            max_session_timeout: Duration::from_secs(15 * 60), // 15 minutes
        }
    }

    /// Analyze authentication configuration for security violations.
    pub fn analyze_authentication_security(
        &self,
        entity_id: EntityId,
        auth_config: &AuthenticationConfig,
    ) -> Option<NetworkSecurityEvent> {
        let mut risk_score: f64 = 0.0;
        let mut violations = Vec::new();
        let mut compliance_violations = Vec::new();

        // Check MFA implementation
        if !auth_config.mfa_enabled {
            risk_score += 0.8;
            violations.push(NetworkViolationType::WeakAuthenticationMethod);
            
            compliance_violations.push(NetworkComplianceViolation {
                framework: NetworkSecurityFramework::PciNss,
                control: "PCI DSS 8.3".to_string(),
                requirement: "Incorporate multi-factor authentication".to_string(),
                violation_description: "Banking application lacks multi-factor authentication".to_string(),
                potential_penalty: Some(1_000_000.0), // PCI DSS violation penalty
                remediation_deadline: Some(Duration::from_secs(48 * 3600)),
            });
        }

        // Check session management
        if auth_config.session_timeout > self.max_session_timeout {
            risk_score += 0.4;
            violations.push(NetworkViolationType::SessionManagementError);
        }

        if risk_score > 0.3 && !violations.is_empty() {
            let severity = self.calculate_severity(risk_score);
            Some(self.create_authentication_event(
                entity_id,
                risk_score,
                violations[0],
                severity,
                auth_config,
                compliance_violations,
            ))
        } else {
            None
        }
    }

    fn calculate_severity(&self, risk_score: f64) -> NetworkViolationSeverity {
        match risk_score {
            s if s >= 0.8 => NetworkViolationSeverity::Critical,
            s if s >= 0.6 => NetworkViolationSeverity::High,
            s if s >= 0.4 => NetworkViolationSeverity::Medium,
            s if s >= 0.2 => NetworkViolationSeverity::Low,
            _ => NetworkViolationSeverity::Info,
        }
    }

    fn create_authentication_event(
        &self,
        entity_id: EntityId,
        risk_score: f64,
        violation_type: NetworkViolationType,
        severity: NetworkViolationSeverity,
        auth_config: &AuthenticationConfig,
        compliance_violations: Vec<NetworkComplianceViolation>,
    ) -> NetworkSecurityEvent {
        NetworkSecurityEvent {
            id: format!("auth-{}", uuid::Uuid::new_v4()),
            entity_id,
            timestamp: chrono::Utc::now(),
            security_vector: NetworkSecurityVector::Authentication,
            violation_type,
            severity,
            risk_score,
            confidence: Confidence::new(0.9),
            affected_assets: vec![auth_config.application_name.clone()],
            indicators: NetworkSecurityIndicators {
                wireless: None,
                remote_access: None,
                authentication: Some(AuthenticationIndicators {
                    mfa_status: format!("MFA enabled: {}", auth_config.mfa_enabled),
                    auth_strength: auth_config.auth_method.clone(),
                    session_management: format!("Timeout: {} seconds", auth_config.session_timeout.as_secs()),
                    banking_security: format!("Banking app: {}", auth_config.application_type == "Banking"),
                    identity_provider: auth_config.identity_provider.clone(),
                }),
                protocol: None,
                application: None,
                directory: None,
                system_admin: None,
            },
            compliance_violations,
            remediation: NetworkRemediationGuidance {
                immediate_action: "Implement multi-factor authentication for banking applications".to_string(),
                remediation_steps: vec![
                    "Deploy TOTP-based MFA solution".to_string(),
                    "Configure device registration workflow".to_string(),
                    "Implement transaction signing for high-value operations".to_string(),
                    "Reduce session timeout to 15 minutes maximum".to_string(),
                ],
                long_term_improvements: vec![
                    "Implement adaptive authentication based on risk scoring".to_string(),
                    "Deploy fraud detection and prevention systems".to_string(),
                ],
                estimated_time: Duration::from_secs(72 * 3600), // 72 hours
                required_resources: vec!["MFA service".to_string(), "Mobile app".to_string()],
            },
        }
    }
}

/// Authentication configuration data.
#[derive(Debug, Clone)]
pub struct AuthenticationConfig {
    pub mfa_enabled: bool,
    pub auth_method: String,
    pub session_timeout: Duration,
    pub application_name: String,
    pub application_type: String,
    pub identity_provider: String,
}

// ── Protocol security detection ────────────────────────────────────

/// Network protocol security analyzer for ARP, BGP, and DNS monitoring.
#[derive(Debug)]
pub struct ProtocolDetector {
    /// Known legitimate MAC addresses.
    trusted_mac_addresses: Vec<String>,
    /// RPKI validation requirements.
    rpki_requirements: Vec<String>,
    /// DNS security policies.
    dns_security_policies: Vec<String>,
}

impl ProtocolDetector {
    pub fn new() -> Self {
        Self {
            trusted_mac_addresses: Vec::new(),
            rpki_requirements: vec![
                "ROA validation".to_string(),
                "Origin validation".to_string(),
                "Path validation".to_string(),
            ],
            dns_security_policies: vec![
                "DNSSEC validation".to_string(),
                "DNS over HTTPS".to_string(),
                "Cache poisoning protection".to_string(),
            ],
        }
    }

    /// Analyze protocol security for violations.
    pub fn analyze_protocol_security(
        &self,
        entity_id: EntityId,
        protocol_data: &ProtocolData,
    ) -> Option<NetworkSecurityEvent> {
        let mut risk_score: f64 = 0.0;
        let mut violations = Vec::new();
        let mut compliance_violations = Vec::new();

        // Check for ARP spoofing indicators
        if !protocol_data.arp_table_valid {
            risk_score += 0.7;
            violations.push(NetworkViolationType::ArpSpoofingDetected);
        }

        // Check BGP RPKI validation
        if !protocol_data.rpki_validation_enabled {
            risk_score += 0.6;
            violations.push(NetworkViolationType::BgpHijackingAttempt);
            
            compliance_violations.push(NetworkComplianceViolation {
                framework: NetworkSecurityFramework::NistCsf,
                control: "PR.DS-2".to_string(),
                requirement: "Data-in-transit is protected".to_string(),
                violation_description: "BGP routing lacks RPKI validation".to_string(),
                potential_penalty: Some(750_000.0),
                remediation_deadline: Some(Duration::from_secs(24 * 3600)),
            });
        }

        // Check DNS security
        if protocol_data.dns_cache_poisoning_detected {
            risk_score += 0.9;
            violations.push(NetworkViolationType::DnsCachePoisoning);
        }

        if risk_score > 0.3 && !violations.is_empty() {
            let severity = self.calculate_severity(risk_score);
            Some(self.create_protocol_event(
                entity_id,
                risk_score,
                violations[0],
                severity,
                protocol_data,
                compliance_violations,
            ))
        } else {
            None
        }
    }

    fn calculate_severity(&self, risk_score: f64) -> NetworkViolationSeverity {
        match risk_score {
            s if s >= 0.8 => NetworkViolationSeverity::Critical,
            s if s >= 0.6 => NetworkViolationSeverity::High,
            s if s >= 0.4 => NetworkViolationSeverity::Medium,
            s if s >= 0.2 => NetworkViolationSeverity::Low,
            _ => NetworkViolationSeverity::Info,
        }
    }

    fn create_protocol_event(
        &self,
        entity_id: EntityId,
        risk_score: f64,
        violation_type: NetworkViolationType,
        severity: NetworkViolationSeverity,
        protocol_data: &ProtocolData,
        compliance_violations: Vec<NetworkComplianceViolation>,
    ) -> NetworkSecurityEvent {
        NetworkSecurityEvent {
            id: format!("protocol-{}", uuid::Uuid::new_v4()),
            entity_id,
            timestamp: chrono::Utc::now(),
            security_vector: NetworkSecurityVector::Protocol,
            violation_type,
            severity,
            risk_score,
            confidence: Confidence::new(0.85),
            affected_assets: vec!["Network infrastructure".to_string()],
            indicators: NetworkSecurityIndicators {
                wireless: None,
                remote_access: None,
                authentication: None,
                protocol: Some(ProtocolIndicators {
                    arp_analysis: format!("ARP table valid: {}", protocol_data.arp_table_valid),
                    bgp_validation: format!("RPKI enabled: {}", protocol_data.rpki_validation_enabled),
                    dns_security: format!("Cache poisoning detected: {}", protocol_data.dns_cache_poisoning_detected),
                    rpki_status: format!("RPKI deployment: {}", protocol_data.rpki_validation_enabled),
                    route_hijacking: protocol_data.suspicious_routes.clone(),
                }),
                application: None,
                directory: None,
                system_admin: None,
            },
            compliance_violations,
            remediation: NetworkRemediationGuidance {
                immediate_action: "Enable RPKI validation and implement ARP monitoring".to_string(),
                remediation_steps: vec![
                    "Deploy RPKI validation for BGP routing".to_string(),
                    "Configure ARP inspection and monitoring".to_string(),
                    "Enable DNSSEC validation".to_string(),
                    "Implement DNS over HTTPS (DoH)".to_string(),
                ],
                long_term_improvements: vec![
                    "Deploy network segmentation and microsegmentation".to_string(),
                    "Implement network intrusion detection system".to_string(),
                ],
                estimated_time: Duration::from_secs(48 * 3600), // 48 hours
                required_resources: vec!["RPKI validator".to_string(), "Network monitoring tools".to_string()],
            },
        }
    }
}

/// Protocol security data.
#[derive(Debug, Clone)]
pub struct ProtocolData {
    pub arp_table_valid: bool,
    pub rpki_validation_enabled: bool,
    pub dns_cache_poisoning_detected: bool,
    pub suspicious_routes: Vec<String>,
}

// ── Application security detection ─────────────────────────────────

/// Application security analyzer for Java framework and deserialization monitoring.
#[derive(Debug)]
pub struct ApplicationDetector {
    /// Known vulnerable Java framework versions.
    vulnerable_frameworks: Vec<String>,
    /// Deserialization vulnerability patterns.
    vulnerability_patterns: Vec<String>,
}

impl ApplicationDetector {
    pub fn new() -> Self {
        Self {
            vulnerable_frameworks: vec![
                "Apache Struts < 2.5.26".to_string(),
                "Spring Framework < 5.3.21".to_string(),
                "Jackson < 2.13.3".to_string(),
            ],
            vulnerability_patterns: vec![
                "ObjectInputStream".to_string(),
                "readObject()".to_string(),
                "serialVersionUID".to_string(),
            ],
        }
    }

    /// Analyze application security for vulnerabilities.
    pub fn analyze_application_security(
        &self,
        entity_id: EntityId,
        app_data: &ApplicationData,
    ) -> Option<NetworkSecurityEvent> {
        let mut risk_score: f64 = 0.0;
        let mut violations = Vec::new();
        let mut compliance_violations = Vec::new();

        // Check for vulnerable Java frameworks
        if app_data.has_vulnerable_framework {
            risk_score += 0.8;
            violations.push(NetworkViolationType::UnpatchedVulnerability);
        }

        // Check for deserialization vulnerabilities
        if app_data.deserialization_vulnerability {
            risk_score += 0.9;
            violations.push(NetworkViolationType::DeserializationVulnerability);
            
            compliance_violations.push(NetworkComplianceViolation {
                framework: NetworkSecurityFramework::NistCsf,
                control: "PR.IP-12".to_string(),
                requirement: "A vulnerability management plan is developed and implemented".to_string(),
                violation_description: "Java deserialization vulnerability not patched".to_string(),
                potential_penalty: Some(2_000_000.0), // High-impact vulnerability
                remediation_deadline: Some(Duration::from_secs(24 * 3600)), // Critical - 24 hours
            });
        }

        if risk_score > 0.3 && !violations.is_empty() {
            let severity = self.calculate_severity(risk_score);
            Some(self.create_application_event(
                entity_id,
                risk_score,
                violations[0],
                severity,
                app_data,
                compliance_violations,
            ))
        } else {
            None
        }
    }

    fn calculate_severity(&self, risk_score: f64) -> NetworkViolationSeverity {
        match risk_score {
            s if s >= 0.8 => NetworkViolationSeverity::Critical,
            s if s >= 0.6 => NetworkViolationSeverity::High,
            s if s >= 0.4 => NetworkViolationSeverity::Medium,
            s if s >= 0.2 => NetworkViolationSeverity::Low,
            _ => NetworkViolationSeverity::Info,
        }
    }

    fn create_application_event(
        &self,
        entity_id: EntityId,
        risk_score: f64,
        violation_type: NetworkViolationType,
        severity: NetworkViolationSeverity,
        app_data: &ApplicationData,
        compliance_violations: Vec<NetworkComplianceViolation>,
    ) -> NetworkSecurityEvent {
        NetworkSecurityEvent {
            id: format!("app-{}", uuid::Uuid::new_v4()),
            entity_id,
            timestamp: chrono::Utc::now(),
            security_vector: NetworkSecurityVector::Application,
            violation_type,
            severity,
            risk_score,
            confidence: Confidence::new(0.95),
            affected_assets: vec![app_data.application_name.clone()],
            indicators: NetworkSecurityIndicators {
                wireless: None,
                remote_access: None,
                authentication: None,
                protocol: None,
                application: Some(ApplicationIndicators {
                    java_framework: app_data.framework_version.clone(),
                    deserialization_status: format!("Vulnerable: {}", app_data.deserialization_vulnerability),
                    webapp_security: app_data.security_configuration.clone(),
                    patch_management: format!("Up to date: {}", !app_data.has_vulnerable_framework),
                    vulnerability_scan: app_data.detected_vulnerabilities.clone(),
                }),
                directory: None,
                system_admin: None,
            },
            compliance_violations,
            remediation: NetworkRemediationGuidance {
                immediate_action: "Patch Java deserialization vulnerability immediately".to_string(),
                remediation_steps: vec![
                    "Update Java framework to latest secure version".to_string(),
                    "Implement input validation and deserialization filters".to_string(),
                    "Replace vulnerable serialization with safe alternatives".to_string(),
                    "Deploy web application firewall (WAF)".to_string(),
                ],
                long_term_improvements: vec![
                    "Implement automated vulnerability scanning".to_string(),
                    "Establish continuous security testing in CI/CD pipeline".to_string(),
                ],
                estimated_time: Duration::from_secs(8 * 3600), // 8 hours - urgent
                required_resources: vec!["Development team".to_string(), "Security patches".to_string()],
            },
        }
    }
}

/// Application security data.
#[derive(Debug, Clone)]
pub struct ApplicationData {
    pub application_name: String,
    pub framework_version: String,
    pub has_vulnerable_framework: bool,
    pub deserialization_vulnerability: bool,
    pub security_configuration: String,
    pub detected_vulnerabilities: Vec<String>,
}

// ── Directory service security detection ──────────────────────────

/// Directory service security analyzer for Active Directory and pass-the-hash monitoring.
#[derive(Debug)]
pub struct DirectoryDetector {
    /// Credential guard requirements.
    credential_guard_requirements: Vec<String>,
    /// Pass-the-hash protection methods.
    pth_protection_methods: Vec<String>,
}

impl DirectoryDetector {
    pub fn new() -> Self {
        Self {
            credential_guard_requirements: vec![
                "Windows Defender Credential Guard".to_string(),
                "LSASS protection".to_string(),
                "Virtualization-based security".to_string(),
            ],
            pth_protection_methods: vec![
                "Restricted Admin mode".to_string(),
                "Protected Users group".to_string(),
                "Authentication policy".to_string(),
            ],
        }
    }

    /// Analyze directory service security for violations.
    pub fn analyze_directory_security(
        &self,
        entity_id: EntityId,
        directory_data: &DirectoryData,
    ) -> Option<NetworkSecurityEvent> {
        let mut risk_score: f64 = 0.0;
        let mut violations = Vec::new();
        let mut compliance_violations = Vec::new();

        // Check credential guard status
        if !directory_data.credential_guard_enabled {
            risk_score += 0.7;
            violations.push(NetworkViolationType::CredentialTheftDetected);
        }

        // Check for pass-the-hash attempts
        if directory_data.pth_attack_detected {
            risk_score += 0.9;
            violations.push(NetworkViolationType::PassTheHashAttempt);
            
            compliance_violations.push(NetworkComplianceViolation {
                framework: NetworkSecurityFramework::NistCsf,
                control: "DE.CM-1".to_string(),
                requirement: "The network is monitored to detect potential cybersecurity events".to_string(),
                violation_description: "Pass-the-hash attack detected in Active Directory".to_string(),
                potential_penalty: Some(1_500_000.0),
                remediation_deadline: Some(Duration::from_secs(4 * 3600)), // 4 hours - critical
            });
        }

        if risk_score > 0.3 && !violations.is_empty() {
            let severity = self.calculate_severity(risk_score);
            Some(self.create_directory_event(
                entity_id,
                risk_score,
                violations[0],
                severity,
                directory_data,
                compliance_violations,
            ))
        } else {
            None
        }
    }

    fn calculate_severity(&self, risk_score: f64) -> NetworkViolationSeverity {
        match risk_score {
            s if s >= 0.8 => NetworkViolationSeverity::Critical,
            s if s >= 0.6 => NetworkViolationSeverity::High,
            s if s >= 0.4 => NetworkViolationSeverity::Medium,
            s if s >= 0.2 => NetworkViolationSeverity::Low,
            _ => NetworkViolationSeverity::Info,
        }
    }

    fn create_directory_event(
        &self,
        entity_id: EntityId,
        risk_score: f64,
        violation_type: NetworkViolationType,
        severity: NetworkViolationSeverity,
        directory_data: &DirectoryData,
        compliance_violations: Vec<NetworkComplianceViolation>,
    ) -> NetworkSecurityEvent {
        NetworkSecurityEvent {
            id: format!("directory-{}", uuid::Uuid::new_v4()),
            entity_id,
            timestamp: chrono::Utc::now(),
            security_vector: NetworkSecurityVector::Directory,
            violation_type,
            severity,
            risk_score,
            confidence: Confidence::new(0.9),
            affected_assets: vec!["Active Directory".to_string()],
            indicators: NetworkSecurityIndicators {
                wireless: None,
                remote_access: None,
                authentication: None,
                protocol: None,
                application: None,
                directory: Some(DirectoryIndicators {
                    ad_config: directory_data.domain_configuration.clone(),
                    credential_guard: directory_data.credential_guard_enabled,
                    pth_protection: format!("Protected: {}", !directory_data.pth_attack_detected),
                    domain_policies: directory_data.security_policies.clone(),
                    auth_logs: directory_data.audit_events.clone(),
                }),
                system_admin: None,
            },
            compliance_violations,
            remediation: NetworkRemediationGuidance {
                immediate_action: "Enable Windows Defender Credential Guard and isolate affected systems".to_string(),
                remediation_steps: vec![
                    "Enable Windows Defender Credential Guard on all systems".to_string(),
                    "Configure Protected Users security group".to_string(),
                    "Implement authentication policies to prevent pass-the-hash".to_string(),
                    "Reset all potentially compromised credentials".to_string(),
                ],
                long_term_improvements: vec![
                    "Implement privileged access workstations (PAWs)".to_string(),
                    "Deploy Microsoft Advanced Threat Analytics (ATA)".to_string(),
                ],
                estimated_time: Duration::from_secs(12 * 3600), // 12 hours
                required_resources: vec!["Domain administrator access".to_string(), "Group policy management".to_string()],
            },
        }
    }
}

/// Directory service security data.
#[derive(Debug, Clone)]
pub struct DirectoryData {
    pub domain_configuration: String,
    pub credential_guard_enabled: bool,
    pub pth_attack_detected: bool,
    pub security_policies: String,
    pub audit_events: Vec<String>,
}

// ── System administration security detection ──────────────────────

/// System administration security analyzer for Linux auditing and setuid monitoring.
#[derive(Debug)]
pub struct SystemAdminDetector {
    /// Known safe setuid programs.
    trusted_setuid_programs: Vec<String>,
    /// Race condition vulnerability patterns.
    race_condition_patterns: Vec<String>,
}

impl SystemAdminDetector {
    pub fn new() -> Self {
        Self {
            trusted_setuid_programs: vec![
                "/usr/bin/sudo".to_string(),
                "/usr/bin/passwd".to_string(),
                "/usr/bin/su".to_string(),
            ],
            race_condition_patterns: vec![
                "TOCTOU".to_string(),
                "Signal handling".to_string(),
                "File permissions".to_string(),
            ],
        }
    }

    /// Analyze system administration security for violations.
    pub fn analyze_system_admin_security(
        &self,
        entity_id: EntityId,
        system_data: &SystemAdminData,
    ) -> Option<NetworkSecurityEvent> {
        let mut risk_score: f64 = 0.0;
        let mut violations = Vec::new();
        let mut compliance_violations = Vec::new();

        // Check for setuid vulnerabilities
        if system_data.setuid_vulnerability_found {
            risk_score += 0.8;
            violations.push(NetworkViolationType::SetuidVulnerability);
        }

        // Check for race condition exploits
        if system_data.race_condition_detected {
            risk_score += 0.7;
            violations.push(NetworkViolationType::RaceConditionExploit);
            
            compliance_violations.push(NetworkComplianceViolation {
                framework: NetworkSecurityFramework::CisControls,
                control: "CIS Control 3".to_string(),
                requirement: "Continuous Vulnerability Management".to_string(),
                violation_description: "Race condition vulnerability in setuid program".to_string(),
                potential_penalty: Some(500_000.0),
                remediation_deadline: Some(Duration::from_secs(72 * 3600)),
            });
        }

        if risk_score > 0.3 && !violations.is_empty() {
            let severity = self.calculate_severity(risk_score);
            Some(self.create_system_admin_event(
                entity_id,
                risk_score,
                violations[0],
                severity,
                system_data,
                compliance_violations,
            ))
        } else {
            None
        }
    }

    fn calculate_severity(&self, risk_score: f64) -> NetworkViolationSeverity {
        match risk_score {
            s if s >= 0.8 => NetworkViolationSeverity::Critical,
            s if s >= 0.6 => NetworkViolationSeverity::High,
            s if s >= 0.4 => NetworkViolationSeverity::Medium,
            s if s >= 0.2 => NetworkViolationSeverity::Low,
            _ => NetworkViolationSeverity::Info,
        }
    }

    fn create_system_admin_event(
        &self,
        entity_id: EntityId,
        risk_score: f64,
        violation_type: NetworkViolationType,
        severity: NetworkViolationSeverity,
        system_data: &SystemAdminData,
        compliance_violations: Vec<NetworkComplianceViolation>,
    ) -> NetworkSecurityEvent {
        NetworkSecurityEvent {
            id: format!("sysadmin-{}", uuid::Uuid::new_v4()),
            entity_id,
            timestamp: chrono::Utc::now(),
            security_vector: NetworkSecurityVector::SystemAdmin,
            violation_type,
            severity,
            risk_score,
            confidence: Confidence::new(0.85),
            affected_assets: vec![system_data.system_name.clone()],
            indicators: NetworkSecurityIndicators {
                wireless: None,
                remote_access: None,
                authentication: None,
                protocol: None,
                application: None,
                directory: None,
                system_admin: Some(SystemAdminIndicators {
                    linux_config: system_data.linux_configuration.clone(),
                    setuid_audit: format!("Vulnerabilities found: {}", system_data.setuid_vulnerability_found),
                    race_condition: format!("Race condition detected: {}", system_data.race_condition_detected),
                    privilege_monitoring: system_data.privilege_status.clone(),
                    config_drift: system_data.configuration_changes.clone(),
                }),
            },
            compliance_violations,
            remediation: NetworkRemediationGuidance {
                immediate_action: "Patch setuid vulnerabilities and implement privilege monitoring".to_string(),
                remediation_steps: vec![
                    "Audit all setuid programs for vulnerabilities".to_string(),
                    "Implement file system access control lists (ACLs)".to_string(),
                    "Deploy system call monitoring and logging".to_string(),
                    "Remove unnecessary setuid bits from programs".to_string(),
                ],
                long_term_improvements: vec![
                    "Implement mandatory access controls (MAC) with SELinux".to_string(),
                    "Deploy runtime application self-protection (RASP)".to_string(),
                ],
                estimated_time: Duration::from_secs(48 * 3600), // 48 hours
                required_resources: vec!["System administrator".to_string(), "Security patches".to_string()],
            },
        }
    }
}

/// System administration security data.
#[derive(Debug, Clone)]
pub struct SystemAdminData {
    pub system_name: String,
    pub linux_configuration: String,
    pub setuid_vulnerability_found: bool,
    pub race_condition_detected: bool,
    pub privilege_status: String,
    pub configuration_changes: Vec<String>,
}
