//! Network security and administrative monitoring engine for comprehensive infrastructure assessment.
//!
//! This module implements comprehensive network security monitoring patterns from multiple infrastructure domains:
//!
//! - **Corporate Wi-Fi network security** → WPA3 Enterprise configuration monitoring and wireless authentication
//! - **SSH key usage auditing** → Password rotation policy enforcement and credential lifecycle management
//! - **RDP security deployment** → Network-level authentication and secure gateway configuration monitoring
//! - **Multi-factor authentication** → Banking web application identity security implementation monitoring
//! - **ARP spoofing detection** → Advanced network monitoring tools for layer 2 attack prevention
//! - **BGP routing validation** → RPKI implementation to prevent route hijacking attacks and ensure routing integrity
//! - **Deserialization vulnerability patching** → Java web application framework security and exploit prevention
//! - **DNS query monitoring** → Cache poisoning attempt detection and DNS security policy enforcement
//! - **Active Directory security** → Pass-the-hash attack prevention with credential guard and domain protection
//! - **Linux system auditing** → Race condition vulnerability detection in setuid programs and privilege escalation prevention
//!
//! ## Architecture
//!
//! The network security engine consists of four main components:
//!
//! - **`types`** — Core data structures for network security events, infrastructure violations, and compliance assessment
//! - **`detection`** — Network security violation detection algorithms for all infrastructure protection vectors
//! - **`analysis`** — Network security posture assessment, compliance scoring, and infrastructure risk evaluation
//! - **`engine`** — Main orchestrator integrating detection, analysis, and network infrastructure compliance reporting
//!
//! ## Integration with Skeletrace
//!
//! The network engine integrates seamlessly with Skeletrace's existing architecture:
//!
//! - Uses `entity::Node` and `entity::Edge` as network infrastructure monitoring targets
//! - Records network security events as `metric::Sample` entries for infrastructure compliance trending
//! - Leverages `graph::Graph` for organizational network security posture assessment
//! - Respects `cache` tiering for network compliance data and infrastructure framework storage
//!
//! ## Usage
//!
//! ```rust
//! use skeletrace::network::{NetworkEngine, NetworkSecurityTarget};
//! use skeletrace::types::EntityId;
//!
//! // Create network security engine
//! let mut engine = NetworkEngine::new();
//!
//! // Add Wi-Fi security monitoring
//! let wifi_target = NetworkSecurityTarget::wifi_security(
//!     EntityId(uuid::Uuid::new_v4()),
//!     "Corporate Wi-Fi Network"
//! );
//! engine.add_target(wifi_target);
//!
//! // Add remote access security monitoring
//! let remote_target = NetworkSecurityTarget::remote_access_security(
//!     EntityId(uuid::Uuid::new_v4()),
//!     "SSH and RDP Services"
//! );
//! engine.add_target(remote_target);
//!
//! // Execute network security monitoring cycle
//! let result = engine.execute_network_cycle();
//!
//! // Generate compliance metrics for Skeletrace
//! let samples = engine.generate_metric_samples(&graph);
//!
//! // Run network security analysis
//! if let Some(report) = engine.analyze_network_security(&graph) {
//!     println!("Network security posture: {:.1}%", report.network_security_posture * 100.0);
//! }
//! ```
//!
//! ## Network Security Patterns Implemented
//!
//! ### Comprehensive Infrastructure Protection
//! Monitors all major network security vectors simultaneously with specialized detection engines
//! for each infrastructure domain. Correlates violations across vectors to identify systemic network gaps.
//!
//! ### Network Security Compliance Assessment
//! Implements compliance scoring for NIST CSF, CIS Controls, ISO 27001, SANS Critical, FISMA, PCI NSS, and SOC 2.
//! Provides automated network compliance reporting with violation impact assessment and remediation guidance.
//!
//! ### Infrastructure Risk Analysis
//! Tracks affected network assets across security events with infrastructure-aware risk assessment.
//! Implements comprehensive network security posture evaluation with gap analysis and protection recommendations.
//!
//! ### Network Security by Design Assessment
//! Evaluates network security architecture implementations including wireless protection, access controls,
//! and infrastructure monitoring. Provides recommendations for network security-enhancing technologies.
//!
//! ### Real-Time Network Breach Detection
//! Generates prioritized network security alerts based on risk thresholds, infrastructure impact, and asset criticality.
//! Supports alert acknowledgment, investigation tracking, and network remediation workflow management.
//!
//! ## Network Security Vector Coverage
//!
//! ### Wireless Network Security (WPA3 Enterprise & Corporate Wi-Fi)
//! - WPA3 Enterprise configuration validation with 802.1X authentication verification
//! - Corporate wireless network policy enforcement and compliance assessment
//! - RADIUS server deployment monitoring and enterprise authentication validation
//! - Wireless intrusion detection and rogue access point identification
//! - Network access control (NAC) implementation and device authentication verification
//!
//! ### Remote Access Security (SSH & RDP Protection)
//! - SSH key lifecycle management with automated rotation policy enforcement
//! - Password policy compliance and credential strength verification
//! - RDP Network Level Authentication deployment and secure gateway monitoring
//! - Privileged access management (PAM) implementation and jump server configuration
//! - Remote access session monitoring and security policy enforcement
//!
//! ### Authentication Security (MFA & Banking Application Protection)
//! - Multi-factor authentication implementation monitoring for banking web applications
//! - Device registration workflow validation and transaction signing verification
//! - Identity provider configuration assessment and adaptive authentication evaluation
//! - Session management policy enforcement and fraud detection system validation
//! - Biometric authentication deployment and fallback security mechanism assessment
//!
//! ### Network Protocol Security (ARP, BGP & DNS Protection)
//! - ARP spoofing detection using advanced network monitoring and inspection tools
//! - BGP routing validation with RPKI deployment and route hijacking prevention
//! - DNS security policy enforcement with cache poisoning attempt detection
//! - Network intrusion detection system deployment and traffic pattern analysis
//! - Protocol security violation identification and network segmentation validation
//!
//! ### Application Security (Java Framework & Deserialization Protection)
//! - Java web application framework vulnerability assessment and patch management
//! - Deserialization vulnerability detection and input validation implementation
//! - Web application firewall (WAF) deployment and security configuration validation
//! - Continuous security testing integration and automated vulnerability scanning
//! - Application security policy enforcement and secure coding practice assessment
//!
//! ### Directory Service Security (Active Directory & Pass-the-Hash Prevention)
//! - Windows Defender Credential Guard deployment and LSASS protection monitoring
//! - Pass-the-hash attack prevention with Protected Users group and authentication policies
//! - Active Directory security configuration assessment and domain policy enforcement
//! - Privileged access workstation (PAW) deployment and administrative access monitoring
//! - Microsoft Advanced Threat Analytics (ATA) implementation and credential theft detection
//!
//! ### System Administration Security (Linux Auditing & Setuid Protection)
//! - Linux system privilege escalation detection and setuid vulnerability assessment
//! - Race condition vulnerability identification in setuid programs and system services
//! - SELinux mandatory access control implementation and policy enforcement
//! - System call monitoring and configuration drift detection
//! - Runtime application self-protection (RASP) deployment and security monitoring
//!
//! ## Network Security Compliance Framework Support
//!
//! ### NIST Cybersecurity Framework (CSF)
//! - PR.DS-1 & PR.DS-2: Data-in-transit protection and network communication security
//! - PR.AC-7: User and device authentication in network infrastructure
//! - DE.CM-1: Network monitoring for cybersecurity event detection
//! - PR.IP-12: Vulnerability management plan implementation and network security assessment
//! - Network security control effectiveness validation and compliance reporting
//!
//! ### CIS Critical Security Controls
//! - CIS Control 3: Continuous vulnerability management for network infrastructure
//! - CIS Control 4: Controlled use of administrative privileges and network access
//! - CIS Control 12: Boundary defense and network segmentation implementation
//! - CIS Control 15: Wireless access control and corporate Wi-Fi security
//! - CIS Control 16: Account monitoring and control for network authentication
//!
//! ### ISO/IEC 27001 Information Security Management
//! - Network security control implementation and information security management
//! - Risk assessment and treatment for network infrastructure components
//! - Security incident management and network breach response procedures
//! - Network access control and user authentication requirements
//! - Information security monitoring and network compliance measurement
//!
//! ### SANS Critical Security Controls
//! - Network infrastructure inventory and asset management
//! - Secure network architecture and configuration management
//! - Network monitoring and log management for security event detection
//! - Incident response and network security breach management
//! - Network security training and awareness programs
//!
//! ### Federal Information Security Management Act (FISMA)
//! - Federal network security standard compliance and government infrastructure protection
//! - Network security control assessment and authorization procedures
//! - Continuous monitoring and network security posture management
//! - Network incident reporting and federal compliance requirements
//! - Security assessment and authorization for network systems
//!
//! ### Payment Card Industry Network Security Standard (PCI NSS)
//! - Network security for payment card data protection and transaction security
//! - Secure network architecture and payment processing infrastructure
//! - Network access control for cardholder data environment protection
//! - Network monitoring and logging for payment security compliance
//! - Regular network security testing and vulnerability assessment
//!
//! ### SOC 2 Network Security Trust Services
//! - Network security principle compliance and control effectiveness validation
//! - Network availability and processing integrity for service organizations
//! - Network confidentiality and privacy control assessment
//! - Network security change management and configuration monitoring
//! - Network incident response and security monitoring compliance
//!
//! ## Network Asset Protection
//!
//! ### Infrastructure Impact Assessment
//! Automatically calculates network asset impact based on:
//! - Number of affected network devices and infrastructure components per security event
//! - Network asset criticality (low, medium, high, mission-critical infrastructure)
//! - Network segment location and business function criticality
//! - Compliance requirements and regulatory framework applicability
//!
//! ### Network Security Rights Management
//! Supports automated compliance for network infrastructure security:
//! - Network access control policy enforcement and validation
//! - Infrastructure configuration management and change control
//! - Network security incident response and breach notification
//! - Network monitoring and security event correlation
//! - Infrastructure compliance reporting and audit evidence collection
//!
//! ## Integration Benefits
//!
//! ### Organizational Network Security Posture
//! - Unified network security risk assessment across all business infrastructure
//! - Executive dashboard with network compliance score trending and infrastructure visibility
//! - Network protection gap identification and infrastructure remediation prioritization
//! - Regulatory audit preparation and network security evidence collection
//!
//! ### Operational Efficiency
//! - Automated network compliance monitoring reduces manual infrastructure audit overhead
//! - Real-time network security breach detection enables rapid incident response
//! - Integrated remediation workflows accelerate network security incident resolution
//! - Continuous network compliance assessment ensures ongoing regulatory adherence
//!
//! ### Strategic Value
//! - Network security-by-design assessment supports infrastructure development
//! - Compliance framework comparison enables network security regulatory strategy
//! - Network asset impact analysis supports infrastructure security investment decisions
//! - Protection vector analysis guides network security technology priorities

pub mod types;
pub mod detection;
pub mod analysis;
pub mod engine;

// Re-export key types for convenience
pub use engine::{
    NetworkEngine, NetworkEngineConfig, NetworkEngineStats, NetworkAlert, NetworkAlertUrgency,
    NetworkCycleResult,
};
pub use types::{
    NetworkSecurityTarget, NetworkSecurityEvent, NetworkSecurityVector, NetworkViolationType,
    NetworkViolationSeverity, EntityNetworkProfile, NetworkComplianceReport,
    NetworkMonitoringType, NetworkSecurityFramework, NetworkAsset, AssetCriticality,
};
pub use detection::{
    WirelessDetector, RemoteAccessDetector, AuthenticationDetector, ProtocolDetector,
    ApplicationDetector, DirectoryDetector, SystemAdminDetector,
};
pub use analysis::{NetworkSecurityAnalyzer, NetworkComplianceAnalyzer};
