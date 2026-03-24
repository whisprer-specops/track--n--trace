//! Security threat monitoring engine for multi-vector attack detection and risk assessment.
//!
//! This module implements comprehensive security monitoring patterns from multiple domains:
//!
//! - **Security awareness training** → Phishing email identification and BEC detection
//! - **Credential harvesting honeypots** → Behavioral monitoring and fraud detection  
//! - **Call center vishing training** → Voice-based social engineering detection
//! - **SMS security (smishing)** → SMS content analysis and sender verification
//! - **IT helpdesk identity verification** → Multi-factor authentication and fraud prevention
//! - **Watering hole threat assessment** → Web browsing behavior and malicious site detection
//! - **Software update authenticity** → Digital signature and hash verification
//! - **Business email compromise (BEC) detection** → Financial fraud pattern recognition
//! - **Social media security audits** → Information leakage and reconnaissance detection
//! - **Browser security settings** → Suspicious login portal detection and warning systems
//!
//! ## Architecture
//!
//! The security engine consists of four main components:
//!
//! - **`types`** — Core data structures for threats, risks, indicators, and security events
//! - **`detection`** — Threat detection algorithms for email, web, file, voice, and SMS vectors
//! - **`analysis`** — Risk scoring, behavioral analysis, and attack surface assessment
//! - **`engine`** — Main orchestrator integrating detection, analysis, and alerting
//!
//! ## Integration with Skeletrace
//!
//! The security engine integrates seamlessly with Skeletrace's existing architecture:
//!
//! - Uses `entity::Node` and `entity::Edge` as security monitoring targets
//! - Records threat events as `metric::Sample` entries for trending and analysis
//! - Leverages `graph::Graph` for attack surface and risk correlation analysis
//! - Respects `cache` tiering for threat intelligence and indicator storage
//!
//! ## Usage
//!
//! ```rust
//! use skeletrace::security::{SecurityEngine, SecurityTarget};
//! use skeletrace::types::EntityId;
//!
//! // Create security engine
//! let mut engine = SecurityEngine::new();
//!
//! // Add email gateway monitoring
//! let email_target = SecurityTarget::email_gateway(
//!     EntityId(uuid::Uuid::new_v4()),
//!     "Corporate Email Gateway"
//! );
//! engine.add_target(email_target);
//!
//! // Add web proxy monitoring
//! let web_target = SecurityTarget::web_proxy(
//!     EntityId(uuid::Uuid::new_v4()),
//!     "Internet Proxy"
//! );
//! engine.add_target(web_target);
//!
//! // Execute threat detection cycle
//! let result = engine.execute_detection_cycle();
//!
//! // Generate metrics for Skeletrace
//! let samples = engine.generate_metric_samples();
//!
//! // Run attack surface analysis
//! if let Some(report) = engine.analyze_attack_surface(&graph) {
//!     println!("Security posture: {:.1}%", report.security_posture_score * 100.0);
//! }
//! ```
//!
//! ## Security Patterns Implemented
//!
//! ### Multi-Vector Threat Detection
//! Monitors all major attack vectors simultaneously with specialized detection engines
//! for each threat type. Correlates threats across vectors to identify coordinated campaigns.
//!
//! ### Behavioral Risk Analysis
//! Tracks entity behavior over time to establish baselines and detect anomalies.
//! Implements time-weighted decay for threat events and confidence-based scoring.
//!
//! ### Attack Surface Assessment
//! Provides comprehensive organizational security posture evaluation with
//! vector exposure analysis, high-risk entity identification, and executive reporting.
//!
//! ### Real-Time Alerting
//! Generates prioritized security alerts based on risk thresholds and threat severity.
//! Supports alert acknowledgment, assignment, and lifecycle management.
//!
//! ### Threat Intelligence Integration
//! Correlates detected threats with known indicators and attack patterns.
//! Maintains threat actor campaign tracking and success rate analysis.
//!
//! ## Threat Vector Coverage
//!
//! ### Email Security (Phishing & BEC)
//! - SPF/DKIM/DMARC authentication analysis
//! - Domain reputation and typosquatting detection
//! - Content analysis with urgency keyword detection
//! - Business email compromise (BEC) pattern recognition
//! - Attachment and link analysis
//!
//! ### Web Security (Watering Holes & Fake Portals)
//! - Domain reputation and malicious site detection
//! - Typosquatting and brand impersonation analysis
//! - SSL certificate validation and suspicious CA detection
//! - Fake login portal identification
//! - URL analysis and redirect chain inspection
//!
//! ### File Integrity (Software Authenticity)
//! - Digital signature verification and trusted publisher validation
//! - Hash verification and integrity checking
//! - Malware scanning integration and entropy analysis
//! - Unsigned software detection and risk assessment
//! - Update authenticity verification
//!
//! ### Voice Security (Vishing Detection)
//! - Caller ID analysis and spoofing detection
//! - Social engineering tactic recognition
//! - Call pattern and behavioral analysis
//! - Authority claim and urgency language detection
//! - Verification bypass attempt identification
//!
//! ### SMS Security (Smishing Detection)
//! - Sender verification and spoofing analysis
//! - Message content and link analysis
//! - Urgency keyword and social engineering detection
//! - Link shortener and malicious URL identification
//!
//! ### Social Media Security
//! - Profile authenticity and fake account detection
//! - Information leakage and disclosure analysis
//! - Reconnaissance activity identification
//! - Employee interaction monitoring
//! - Brand mention and impersonation detection
//!
//! ### Identity Verification Security
//! - Multi-factor authentication bypass detection
//! - Password reset fraud and account takeover analysis
//! - Verification question and callback analysis
//! - Geographic and temporal anomaly detection
//! - Help desk social engineering detection
//!
//! ### Network Access Security
//! - Suspicious login and access pattern detection
//! - Credential stuffing and password spray identification
//! - Device fingerprinting and session analysis
//! - Geographic and behavioral anomaly detection
//! - Concurrent session and credential reuse analysis

pub mod types;
pub mod detection;
pub mod analysis;
pub mod engine;

// Re-export key types for convenience
pub use engine::{SecurityEngine, SecurityEngineConfig, SecurityEngineStats, SecurityAlert, AlertUrgency};
pub use types::{
    SecurityTarget, ThreatEvent, ThreatVector, ThreatType, ThreatSeverity,
    EntityRiskProfile, AttackSurfaceReport, MonitoringType,
};
pub use detection::{EmailDetector, WebDetector, FileDetector};
pub use analysis::{SecurityAnalyzer, AttackSurfaceAnalyzer};
