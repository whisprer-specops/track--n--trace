//! Data protection and privacy breach monitoring engine for comprehensive compliance assessment.
//!
//! This module implements comprehensive privacy monitoring patterns from multiple regulatory frameworks:
//!
//! - **Database encryption at rest** → Key management policy validation and encryption compliance
//! - **Repository credential scanning** → Automated detection of accidentally exposed secrets and API keys
//! - **OAuth 2.0 token validation** → Short-lived access grant verification and API security assessment
//! - **Constant-time comparison analysis** → Side-channel timing attack detection and prevention
//! - **Browser credential storage security** → Hardware-backed keystore validation and protection
//! - **NFC access badge configuration** → Encryption settings audit and physical security assessment
//! - **Rogue base station detection** → Signal analysis on standard mobile equipment for network security
//! - **Hardware wallet protection** → Private key protection from fault injection attacks
//! - **USB device whitelisting** → Policy configuration and unauthorized access prevention
//! - **Clipboard access auditing** → Permission monitoring across installed applications
//!
//! ## Architecture
//!
//! The privacy engine consists of four main components:
//!
//! - **`types`** — Core data structures for privacy events, compliance violations, and data subjects
//! - **`detection`** — Privacy violation detection algorithms for all data protection vectors
//! - **`analysis`** — Compliance scoring, data subject impact assessment, and privacy posture evaluation
//! - **`engine`** — Main orchestrator integrating detection, analysis, and compliance reporting
//!
//! ## Integration with Skeletrace
//!
//! The privacy engine integrates seamlessly with Skeletrace's existing architecture:
//!
//! - Uses `entity::Node` and `entity::Edge` as privacy monitoring targets
//! - Records privacy events as `metric::Sample` entries for compliance trending
//! - Leverages `graph::Graph` for organizational privacy posture assessment
//! - Respects `cache` tiering for compliance data and regulatory framework storage
//!
//! ## Usage
//!
//! ```rust
//! use skeletrace::privacy::{PrivacyEngine, PrivacyTarget};
//! use skeletrace::types::EntityId;
//!
//! // Create privacy engine
//! let mut engine = PrivacyEngine::new();
//!
//! // Add database encryption monitoring
//! let db_target = PrivacyTarget::database_encryption(
//!     EntityId(uuid::Uuid::new_v4()),
//!     "Customer Database"
//! );
//! engine.add_target(db_target);
//!
//! // Add repository credential scanning
//! let repo_target = PrivacyTarget::repository_scanning(
//!     EntityId(uuid::Uuid::new_v4()),
//!     "Main Application Repository"
//! );
//! engine.add_target(repo_target);
//!
//! // Execute privacy monitoring cycle
//! let result = engine.execute_privacy_cycle();
//!
//! // Generate compliance metrics for Skeletrace
//! let samples = engine.generate_metric_samples();
//!
//! // Run compliance analysis
//! if let Some(report) = engine.analyze_compliance(&graph) {
//!     println!("Privacy posture: {:.1}%", report.privacy_posture_score * 100.0);
//! }
//! ```
//!
//! ## Privacy Patterns Implemented
//!
//! ### Comprehensive Data Protection
//! Monitors all major data protection vectors simultaneously with specialized detection engines
//! for each privacy domain. Correlates violations across vectors to identify systemic compliance gaps.
//!
//! ### Regulatory Compliance Assessment
//! Implements compliance scoring for GDPR, CCPA, HIPAA, PCI-DSS, SOC 2, ISO 27001, and NIST CSF.
//! Provides automated compliance reporting with violation impact assessment and remediation guidance.
//!
//! ### Data Subject Impact Analysis
//! Tracks affected data subjects across privacy events with jurisdiction-aware risk assessment.
//! Implements GDPR Article 35 Data Protection Impact Assessment (DPIA) requirements.
//!
//! ### Privacy by Design Assessment
//! Evaluates privacy-preserving technology implementations including encryption, access controls,
//! and data minimization. Provides recommendations for privacy-enhancing technologies.
//!
//! ### Real-Time Breach Detection
//! Generates prioritized privacy alerts based on risk thresholds, compliance impact, and data subject count.
//! Supports alert acknowledgment, investigation tracking, and remediation workflow management.
//!
//! ## Data Protection Vector Coverage
//!
//! ### Database Protection (Encryption & Key Management)
//! - Encryption at rest validation with algorithm strength assessment
//! - Key rotation policy compliance and age verification
//! - Access control audit and privilege assessment
//! - Audit logging compliance for regulatory requirements
//! - Plaintext storage detection and remediation guidance
//!
//! ### Repository Security (Credential Exposure Prevention)
//! - High-entropy string detection using Shannon entropy analysis
//! - Known credential pattern matching (AWS, GitHub, Slack, etc.)
//! - Commit history analysis for recently exposed secrets
//! - False positive reduction using contextual analysis
//! - Automated remediation recommendations and workflow integration
//!
//! ### API Security (OAuth 2.0 & Token Validation)
//! - Token age validation with short-lived access grant verification
//! - Scope validation and least privilege principle enforcement
//! - Signature verification and trusted issuer validation
//! - HTTPS enforcement and transport security assessment
//! - Rate limiting compliance and abuse prevention
//!
//! ### Hardware Security (Physical Protection & Device Management)
//! - NFC badge encryption configuration auditing
//! - USB device whitelisting policy enforcement
//! - Hardware wallet fault injection protection assessment
//! - Secure element validation and tamper detection
//! - Device fingerprinting and authentication verification
//!
//! ### Side-Channel Protection (Timing Attack Prevention)
//! - Constant-time implementation verification using statistical analysis
//! - Timing variance measurement with nanosecond precision
//! - Power consumption anomaly detection for DPA resistance
//! - Electromagnetic emanation analysis for TEMPEST compliance
//! - Acoustic leakage detection and countermeasure validation
//!
//! ### Credential Storage Security (Browser & Application Protection)
//! - Hardware-backed keystore validation and utilization assessment
//! - Master password policy enforcement and strength verification
//! - Biometric protection enablement and fallback security
//! - Session timeout configuration and automatic logout compliance
//! - Credential sharing detection and unauthorized access prevention
//!
//! ### Network Security (Signal Analysis & Rogue Detection)
//! - Base station authentication and operator verification
//! - Signal strength anomaly detection and triangulation analysis
//! - Downgrade attack prevention and protocol security validation
//! - Certificate pinning verification and TLS configuration assessment
//! - Man-in-the-middle detection using traffic pattern analysis
//!
//! ### Access Control Security (Permission & Policy Auditing)
//! - Clipboard access permission auditing across applications
//! - Data exfiltration risk assessment and prevention
//! - Privilege escalation detection and sandboxing verification
//! - Policy compliance monitoring and violation detection
//! - Unauthorized device access prevention and whitelist enforcement
//!
//! ## Compliance Framework Support
//!
//! ### GDPR (General Data Protection Regulation)
//! - Article 32: Security of processing and encryption requirements
//! - Article 35: Data Protection Impact Assessment (DPIA) automation
//! - Article 25: Privacy by design and by default assessment
//! - Breach notification requirements and timeline compliance
//! - Data subject rights verification and response automation
//!
//! ### CCPA (California Consumer Privacy Act)
//! - Consumer rights verification and data inventory compliance
//! - Personal information category classification and protection
//! - Third-party data sharing assessment and consent validation
//! - Opt-out mechanism verification and preference enforcement
//! - Data deletion and portability compliance automation
//!
//! ### HIPAA (Health Insurance Portability and Accountability Act)
//! - Protected Health Information (PHI) encryption and access control
//! - Business Associate Agreement (BAA) compliance verification
//! - Audit logging and access monitoring for healthcare data
//! - Breach notification and risk assessment automation
//! - Minimum necessary standard enforcement and validation
//!
//! ### PCI-DSS (Payment Card Industry Data Security Standard)
//! - Cardholder data encryption and tokenization compliance
//! - Network security and access control requirement verification
//! - Regular security testing and vulnerability assessment
//! - Secure network architecture and firewall configuration
//! - Strong authentication and access control implementation
//!
//! ### SOC 2 (System and Organization Controls)
//! - Security principle compliance and control effectiveness
//! - Availability and processing integrity verification
//! - Confidentiality and privacy control assessment
//! - Change management and configuration monitoring
//! - Incident response and security monitoring compliance
//!
//! ## Data Subject Protection
//!
//! ### Impact Assessment
//! Automatically calculates data subject impact based on:
//! - Number of affected individuals per privacy event
//! - Data category sensitivity (personal, financial, health, biometric)
//! - Geographic jurisdiction and applicable regulations
//! - Processing purpose and legal basis validation
//!
//! ### Rights Management
//! Supports automated compliance for data subject rights:
//! - Right to access and data portability automation
//! - Right to rectification and correction workflow
//! - Right to erasure (right to be forgotten) implementation
//! - Right to restrict processing and objection handling
//! - Consent management and withdrawal processing
//!
//! ## Integration Benefits
//!
//! ### Organizational Privacy Posture
//! - Unified privacy risk assessment across all business units
//! - Executive dashboard with compliance score trending
//! - Protection gap identification and remediation prioritization
//! - Regulatory audit preparation and evidence collection
//!
//! ### Operational Efficiency
//! - Automated compliance monitoring reduces manual audit overhead
//! - Real-time privacy breach detection enables rapid response
//! - Integrated remediation workflows accelerate incident resolution
//! - Continuous compliance assessment ensures ongoing regulatory adherence
//!
//! ### Strategic Value
//! - Privacy-by-design assessment supports product development
//! - Compliance framework comparison enables regulatory strategy
//! - Data subject impact analysis supports privacy impact assessments
//! - Protection vector analysis guides technology investment priorities

pub mod types;
pub mod detection;
pub mod analysis;
pub mod engine;

// Re-export key types for convenience
pub use engine::{PrivacyEngine, PrivacyEngineConfig, PrivacyEngineStats, PrivacyAlert, AlertUrgency};
pub use types::{
    PrivacyTarget, PrivacyEvent, ProtectionVector, PrivacyViolationType, ViolationSeverity,
    EntityPrivacyProfile, PrivacyComplianceReport, PrivacyMonitoringType, ComplianceFramework,
    DataCategory, DataSubject,
};
pub use detection::{ApiDetector, DatabaseDetector, HardwareDetector, RepositoryDetector};
pub use analysis::{PrivacyAnalyzer, ComplianceAnalyzer};
