//! Threat detection algorithms for multi-vector security monitoring.
//!
//! This module implements detection patterns from all major security domains:
//! - Email security (phishing, BEC) using header analysis and content inspection
//! - Voice security (vishing) using call pattern analysis and social engineering detection
//! - SMS security (smishing) using content analysis and sender verification
//! - Web security (watering holes, fake logins) using URL analysis and content inspection
//! - File security using signature verification and integrity checking
//! - Social media security using profile analysis and information leakage detection
//! - Identity security using verification workflow analysis and fraud detection
//! - Network security using behavioral analysis and anomaly detection

use std::collections::HashMap;

use log::{debug, warn};

use crate::security::types::{
    EmailIndicators, FileIndicators, IdentityIndicators, NetworkIndicators, 
    SecurityTarget, SmsIndicators, SocialIndicators, ThreatEvent, ThreatSeverity,
    ThreatType, ThreatVector, VoiceIndicators, WebIndicators, ThreatIndicators,
};
use crate::types::{Confidence, EntityId};

// ── Email threat detection ─────────────────────────────────────────

/// Email security analyzer for phishing and BEC detection.
#[derive(Debug)]
pub struct EmailDetector {
    /// Known phishing domains.
    phishing_domains: HashMap<String, f64>,
    /// Suspicious keywords for BEC detection.
    bec_keywords: Vec<String>,
    /// Urgency indicators.
    urgency_patterns: Vec<String>,
}

impl EmailDetector {
    pub fn new() -> Self {
        Self {
            phishing_domains: Self::load_phishing_domains(),
            bec_keywords: Self::load_bec_keywords(),
            urgency_patterns: Self::load_urgency_patterns(),
        }
    }

    /// Analyze an email for threats and return a threat event if detected.
    pub fn analyze_email(
        &self,
        entity_id: EntityId,
        email_data: &EmailData,
    ) -> Option<ThreatEvent> {
        let mut risk_score = 0.0;
        let mut threat_types = Vec::new();
        let mut confidence_factors = Vec::new();

        // SPF/DKIM/DMARC authentication analysis
        let auth_score = self.analyze_email_authentication(&email_data.headers);
        if auth_score > 0.3 {
            risk_score += auth_score * 0.4;
            confidence_factors.push(0.9); // High confidence in auth checks
        }

        // Domain reputation analysis
        let domain_score = self.analyze_sender_domain(&email_data.from_domain);
        if domain_score > 0.3 {
            risk_score += domain_score * 0.3;
            threat_types.push(ThreatType::DomainSpoofing);
            confidence_factors.push(0.8);
        }

        // Content analysis for phishing indicators
        let content_score = self.analyze_email_content(&email_data.content);
        if content_score.phishing_score > 0.4 {
            risk_score += content_score.phishing_score * 0.3;
            threat_types.push(ThreatType::Phishing);
            confidence_factors.push(content_score.confidence);
        }

        // BEC-specific analysis
        let bec_score = self.analyze_bec_indicators(&email_data.content, &email_data.subject);
        if bec_score > 0.5 {
            risk_score += bec_score * 0.4;
            threat_types.push(ThreatType::BusinessEmailCompromise);
            confidence_factors.push(0.7);
        }

        // Generate threat event if risk exceeds threshold
        if risk_score > 0.3 && !threat_types.is_empty() {
            let avg_confidence = confidence_factors.iter().sum::<f64>() / confidence_factors.len() as f64;
            
            Some(self.create_email_threat_event(
                entity_id,
                risk_score,
                threat_types[0], // Primary threat type
                avg_confidence,
                email_data,
            ))
        } else {
            None
        }
    }

    fn analyze_email_authentication(&self, headers: &HashMap<String, String>) -> f64 {
        let mut auth_failures: f64 = 0.0;
        
        if let Some(spf) = headers.get("Authentication-Results") {
            if spf.contains("spf=fail") {
                auth_failures += 0.4;
            }
            if spf.contains("dkim=fail") {
                auth_failures += 0.3;
            }
            if spf.contains("dmarc=fail") {
                auth_failures += 0.5;
            }
        }
        
        auth_failures.min(1.0)
    }

    fn analyze_sender_domain(&self, domain: &str) -> f64 {
        // Check against known phishing domains
        if let Some(&score) = self.phishing_domains.get(domain) {
            return score;
        }

        // Check for suspicious patterns
        let mut suspicion: f64 = 0.0;
        
        // Excessive subdomains
        if domain.matches('.').count() > 3 {
            suspicion += 0.2;
        }
        
        // Common phishing TLDs
        if domain.ends_with(".tk") || domain.ends_with(".ml") || domain.ends_with(".ga") {
            suspicion += 0.3;
        }
        
        // Lookalike domain detection (simplified)
        if domain.contains("paypal") || domain.contains("amazon") || domain.contains("microsoft") {
            if !domain.ends_with("paypal.com") && !domain.ends_with("amazon.com") && !domain.ends_with("microsoft.com") {
                suspicion += 0.6;
            }
        }
        
        suspicion.min(1.0)
    }

    fn analyze_email_content(&self, content: &str) -> ContentAnalysisResult {
        let mut phishing_score = 0.0;
        let mut confidence: f64 = 0.5;

        // Urgency keyword detection
        let urgency_matches = self.urgency_patterns.iter()
            .filter(|pattern| content.to_lowercase().contains(&pattern.to_lowercase()))
            .count();
        
        if urgency_matches > 0 {
            phishing_score += 0.3 + (urgency_matches as f64 * 0.1);
            confidence += 0.2;
        }

        // Suspicious link analysis
        let url_count = content.matches("http").count();
        if url_count > 3 {
            phishing_score += 0.2;
        }

        // Typo detection (simplified)
        let typo_indicators = ["recieve", "seperate", "loose", "definately"];
        let typos = typo_indicators.iter()
            .filter(|typo| content.to_lowercase().contains(&typo.to_lowercase()))
            .count();
        
        if typos > 0 {
            phishing_score += typos as f64 * 0.1;
            confidence += 0.1;
        }

        ContentAnalysisResult {
            phishing_score: phishing_score.min(1.0),
            confidence: confidence.min(1.0),
        }
    }

    fn analyze_bec_indicators(&self, content: &str, subject: &str) -> f64 {
        let content_lower = content.to_lowercase();
        let subject_lower = subject.to_lowercase();
        
        let mut bec_score: f64 = 0.0;
        
        // Financial keywords
        let financial_terms = ["wire transfer", "urgent payment", "invoice", "bank account", "payroll"];
        for term in &financial_terms {
            if content_lower.contains(term) {
                bec_score += 0.15;
            }
        }
        
        // Executive impersonation
        let exec_terms = ["ceo", "cfo", "president", "director", "urgent request from"];
        for term in &exec_terms {
            if subject_lower.contains(term) || content_lower.contains(term) {
                bec_score += 0.2;
            }
        }
        
        // Secrecy and urgency
        if content_lower.contains("confidential") && content_lower.contains("urgent") {
            bec_score += 0.3;
        }
        
        bec_score.min(1.0)
    }

    fn create_email_threat_event(
        &self,
        entity_id: EntityId,
        risk_score: f64,
        threat_type: ThreatType,
        confidence: f64,
        email_data: &EmailData,
    ) -> ThreatEvent {
        let severity = match risk_score {
            s if s >= 0.8 => ThreatSeverity::Critical,
            s if s >= 0.6 => ThreatSeverity::High,
            s if s >= 0.4 => ThreatSeverity::Medium,
            _ => ThreatSeverity::Low,
        };

        let indicators = ThreatIndicators {
            email: Some(EmailIndicators {
                from_address: email_data.from_address.clone(),
                display_name: email_data.display_name.clone(),
                subject: email_data.subject.clone(),
                spf_pass: email_data.spf_pass,
                dkim_pass: email_data.dkim_pass,
                dmarc_pass: email_data.dmarc_pass,
                suspicious_links: self.extract_suspicious_links(&email_data.content),
                suspicious_attachments: email_data.attachments.clone(),
                urgency_keywords: self.extract_urgency_keywords(&email_data.content),
                typos_detected: self.detect_typos(&email_data.content),
                financial_keywords: self.has_financial_keywords(&email_data.content),
                payment_request: self.has_payment_request(&email_data.content),
            }),
            voice: None,
            sms: None,
            web: None,
            file: None,
            social: None,
            identity: None,
            network: None,
        };

        ThreatEvent {
            id: format!("email-{}-{}", entity_id.0, chrono::Utc::now().timestamp()),
            entity_id,
            timestamp: chrono::Utc::now(),
            threat_vector: ThreatVector::Email,
            threat_type,
            severity,
            risk_score,
            confidence: Confidence::new(confidence),
            description: format!("Email threat detected: {:?}", threat_type),
            detection_source: "EmailDetector".to_string(),
            indicators,
            investigated: false,
            notes: String::new(),
        }
    }

    // Helper methods for content analysis
    fn extract_suspicious_links(&self, content: &str) -> Vec<String> {
        // Simplified URL extraction and analysis
        let mut links = Vec::new();
        
        for word in content.split_whitespace() {
            if word.starts_with("http") {
                // Check for suspicious characteristics
                if word.contains("bit.ly") || word.contains("tinyurl") || word.len() > 100 {
                    links.push(word.to_string());
                }
            }
        }
        
        links
    }

    fn extract_urgency_keywords(&self, content: &str) -> Vec<String> {
        let content_lower = content.to_lowercase();
        self.urgency_patterns.iter()
            .filter(|pattern| content_lower.contains(&pattern.to_lowercase()))
            .cloned()
            .collect()
    }

    fn detect_typos(&self, content: &str) -> bool {
        let typo_indicators = ["recieve", "seperate", "loose", "definately"];
        let content_lower = content.to_lowercase();
        typo_indicators.iter().any(|typo| content_lower.contains(typo))
    }

    fn has_financial_keywords(&self, content: &str) -> bool {
        let financial_terms = ["wire transfer", "bank account", "invoice", "payment"];
        let content_lower = content.to_lowercase();
        financial_terms.iter().any(|term| content_lower.contains(term))
    }

    fn has_payment_request(&self, content: &str) -> bool {
        let payment_terms = ["pay", "transfer", "send money", "wire"];
        let content_lower = content.to_lowercase();
        payment_terms.iter().any(|term| content_lower.contains(term))
    }

    // Data loading methods (normally from config files or databases)
    fn load_phishing_domains() -> HashMap<String, f64> {
        let mut domains = HashMap::new();
        domains.insert("suspicious-bank.tk".to_string(), 0.9);
        domains.insert("fake-paypal.ml".to_string(), 0.85);
        domains.insert("phishing-site.ga".to_string(), 0.8);
        domains
    }

    fn load_bec_keywords() -> Vec<String> {
        vec![
            "urgent payment".to_string(),
            "wire transfer".to_string(),
            "confidential request".to_string(),
            "ceo request".to_string(),
            "vendor payment".to_string(),
        ]
    }

    fn load_urgency_patterns() -> Vec<String> {
        vec![
            "urgent".to_string(),
            "immediate".to_string(),
            "asap".to_string(),
            "deadline".to_string(),
            "expires today".to_string(),
            "act now".to_string(),
            "limited time".to_string(),
        ]
    }
}

impl Default for EmailDetector {
    fn default() -> Self {
        Self::new()
    }
}

// ── Web threat detection ───────────────────────────────────────────

/// Web security analyzer for watering holes and fake login portals.
#[derive(Debug)]
pub struct WebDetector {
    /// Known malicious domains.
    malicious_domains: HashMap<String, f64>,
    /// Brand protection patterns.
    protected_brands: Vec<String>,
}

impl WebDetector {
    pub fn new() -> Self {
        Self {
            malicious_domains: Self::load_malicious_domains(),
            protected_brands: Self::load_protected_brands(),
        }
    }

    /// Analyze a web request for threats.
    pub fn analyze_web_request(
        &self,
        entity_id: EntityId,
        request_data: &WebRequestData,
    ) -> Option<ThreatEvent> {
        let mut risk_score = 0.0;
        let mut threat_type = ThreatType::WateringHole;

        // Domain reputation check
        let domain_score = self.analyze_domain_reputation(&request_data.domain);
        if domain_score > 0.3 {
            risk_score += domain_score * 0.5;
        }

        // Typosquatting detection
        let typosquatting_score = self.detect_typosquatting(&request_data.domain);
        if typosquatting_score > 0.5 {
            risk_score += typosquatting_score * 0.4;
            threat_type = ThreatType::TyposquattingDomain;
        }

        // Fake login portal detection
        let login_portal_score = self.detect_fake_login_portal(request_data);
        if login_portal_score > 0.6 {
            risk_score += login_portal_score * 0.6;
            threat_type = ThreatType::FakeLoginPortal;
        }

        // SSL/Certificate analysis
        let ssl_score = self.analyze_ssl_certificate(&request_data.ssl_info);
        if ssl_score > 0.3 {
            risk_score += ssl_score * 0.2;
        }

        if risk_score > 0.3 {
            Some(self.create_web_threat_event(entity_id, risk_score, threat_type, request_data))
        } else {
            None
        }
    }

    fn analyze_domain_reputation(&self, domain: &str) -> f64 {
        if let Some(&score) = self.malicious_domains.get(domain) {
            return score;
        }

        // Check for suspicious patterns
        let mut suspicion = 0.0;
        
        // Recently registered domains (simplified check)
        if domain.len() > 50 {
            suspicion += 0.2;
        }

        // Suspicious TLDs
        if domain.ends_with(".tk") || domain.ends_with(".ml") || domain.ends_with(".cf") {
            suspicion += 0.3;
        }

        suspicion
    }

    fn detect_typosquatting(&self, domain: &str) -> f64 {
        for brand in &self.protected_brands {
            if domain.contains(brand) && !domain.ends_with(&format!("{}.com", brand)) {
                // Calculate similarity score (simplified)
                let distance = self.levenshtein_distance(domain, &format!("{}.com", brand));
                if distance < 3 && distance > 0 {
                    return 0.8;
                }
            }
        }
        0.0
    }

    fn detect_fake_login_portal(&self, request_data: &WebRequestData) -> f64 {
        let mut score: f64 = 0.0;

        // Check for login-related paths
        let login_paths = ["/login", "/signin", "/auth", "/sso"];
        for path in &login_paths {
            if request_data.path.contains(path) {
                score += 0.3;
                break;
            }
        }

        // Check for brand impersonation in domain
        for brand in &self.protected_brands {
            if request_data.domain.contains(brand) && !request_data.domain.ends_with(&format!("{}.com", brand)) {
                score += 0.5;
                break;
            }
        }

        // Check SSL certificate validity
        if request_data.ssl_info.is_some() && !request_data.ssl_info.as_ref().unwrap().valid {
            score += 0.3;
        }

        score.min(1.0)
    }

    fn analyze_ssl_certificate(&self, ssl_info: &Option<SslInfo>) -> f64 {
        match ssl_info {
            Some(info) => {
                let mut score = 0.0;
                
                if !info.valid {
                    score += 0.5;
                }
                
                if let Some(age_days) = info.age_days {
                    if age_days < 30 {
                        score += 0.3; // Very new certificate
                    }
                }
                
                score
            }
            None => 0.4, // No SSL on a login page is suspicious
        }
    }

    fn levenshtein_distance(&self, s1: &str, s2: &str) -> usize {
        let len1 = s1.len();
        let len2 = s2.len();
        let mut matrix = vec![vec![0; len2 + 1]; len1 + 1];

        for i in 0..=len1 {
            matrix[i][0] = i;
        }
        for j in 0..=len2 {
            matrix[0][j] = j;
        }

        for i in 1..=len1 {
            for j in 1..=len2 {
                let cost = if s1.chars().nth(i - 1) == s2.chars().nth(j - 1) {
                    0
                } else {
                    1
                };

                matrix[i][j] = [
                    matrix[i - 1][j] + 1,
                    matrix[i][j - 1] + 1,
                    matrix[i - 1][j - 1] + cost,
                ]
                .iter()
                .min()
                .unwrap()
                .clone();
            }
        }

        matrix[len1][len2]
    }

    fn create_web_threat_event(
        &self,
        entity_id: EntityId,
        risk_score: f64,
        threat_type: ThreatType,
        request_data: &WebRequestData,
    ) -> ThreatEvent {
        let severity = match risk_score {
            s if s >= 0.8 => ThreatSeverity::Critical,
            s if s >= 0.6 => ThreatSeverity::High,
            s if s >= 0.4 => ThreatSeverity::Medium,
            _ => ThreatSeverity::Low,
        };

        let indicators = ThreatIndicators {
            email: None,
            voice: None,
            sms: None,
            web: Some(WebIndicators {
                url: format!("https://{}{}", request_data.domain, request_data.path),
                domain: request_data.domain.clone(),
                subdomain_suspicious: request_data.domain.matches('.').count() > 2,
                typosquatting_detected: self.detect_typosquatting(&request_data.domain) > 0.5,
                ssl_valid: request_data.ssl_info.as_ref().map(|info| info.valid).unwrap_or(false),
                certificate_authority: request_data.ssl_info.as_ref().and_then(|info| info.issuer.clone()),
                certificate_age_days: request_data.ssl_info.as_ref().and_then(|info| info.age_days),
                login_form_detected: request_data.path.contains("login"),
                credential_fields: vec!["username".to_string(), "password".to_string()],
                brand_impersonation: self.detect_brand_impersonation(&request_data.domain),
                domain_age_days: None,
                reputation_score: self.malicious_domains.get(&request_data.domain).copied(),
            }),
            file: None,
            social: None,
            identity: None,
            network: None,
        };

        ThreatEvent {
            id: format!("web-{}-{}", entity_id.0, chrono::Utc::now().timestamp()),
            entity_id,
            timestamp: chrono::Utc::now(),
            threat_vector: ThreatVector::Web,
            threat_type,
            severity,
            risk_score,
            confidence: Confidence::new(0.8),
            description: format!("Web threat detected: {:?} on {}", threat_type, request_data.domain),
            detection_source: "WebDetector".to_string(),
            indicators,
            investigated: false,
            notes: String::new(),
        }
    }

    fn detect_brand_impersonation(&self, domain: &str) -> Option<String> {
        for brand in &self.protected_brands {
            if domain.contains(brand) && !domain.ends_with(&format!("{}.com", brand)) {
                return Some(brand.clone());
            }
        }
        None
    }

    fn load_malicious_domains() -> HashMap<String, f64> {
        let mut domains = HashMap::new();
        domains.insert("malicious-site.tk".to_string(), 0.95);
        domains.insert("fake-bank.ml".to_string(), 0.9);
        domains.insert("phishing.ga".to_string(), 0.85);
        domains
    }

    fn load_protected_brands() -> Vec<String> {
        vec![
            "google".to_string(),
            "microsoft".to_string(),
            "paypal".to_string(),
            "amazon".to_string(),
            "apple".to_string(),
            "facebook".to_string(),
        ]
    }
}

impl Default for WebDetector {
    fn default() -> Self {
        Self::new()
    }
}

// ── File integrity detection ───────────────────────────────────────

/// File integrity analyzer for software authenticity verification.
#[derive(Debug)]
pub struct FileDetector {
    /// Trusted software publishers.
    trusted_publishers: Vec<String>,
}

impl FileDetector {
    pub fn new() -> Self {
        Self {
            trusted_publishers: Self::load_trusted_publishers(),
        }
    }

    /// Analyze a file for integrity and authenticity threats.
    pub fn analyze_file(
        &self,
        entity_id: EntityId,
        file_data: &FileData,
    ) -> Option<ThreatEvent> {
        let mut risk_score = 0.0;
        let mut threat_type = ThreatType::UnsignedSoftware;

        // Hash verification
        if let Some(hash_score) = self.verify_file_hash(file_data) {
            if hash_score > 0.5 {
                risk_score += hash_score * 0.4;
                threat_type = ThreatType::HashMismatch;
            }
        }

        // Digital signature verification
        let signature_score = self.verify_digital_signature(file_data);
        if signature_score > 0.3 {
            risk_score += signature_score * 0.5;
            if signature_score > 0.8 {
                threat_type = ThreatType::TamperedUpdate;
            }
        }

        // Malware scanning results
        if let Some(malware_score) = file_data.malware_scan_score {
            if malware_score > 0.3 {
                risk_score += malware_score * 0.6;
                threat_type = ThreatType::MalwareSignature;
            }
        }

        if risk_score > 0.3 {
            Some(self.create_file_threat_event(entity_id, risk_score, threat_type, file_data))
        } else {
            None
        }
    }

    fn verify_file_hash(&self, file_data: &FileData) -> Option<f64> {
        match (&file_data.expected_hash, &file_data.actual_hash) {
            (Some(expected), Some(actual)) => {
                if expected != actual {
                    Some(0.9) // Hash mismatch is very suspicious
                } else {
                    Some(0.0) // Hash matches
                }
            }
            _ => None, // No hash information available
        }
    }

    fn verify_digital_signature(&self, file_data: &FileData) -> f64 {
        let mut score = 0.0;

        match &file_data.signature_info {
            Some(sig_info) => {
                if !sig_info.valid {
                    score += 0.6; // Invalid signature
                }

                if let Some(ref signer) = sig_info.signer {
                    if !self.trusted_publishers.iter().any(|publisher| signer.contains(publisher)) {
                        score += 0.4; // Unknown publisher
                    }
                } else {
                    score += 0.3; // No signer information
                }
            }
            None => {
                // No signature on executable file
                if file_data.file_type.contains("executable") {
                    score += 0.5;
                }
            }
        }

        score
    }

    fn create_file_threat_event(
        &self,
        entity_id: EntityId,
        risk_score: f64,
        threat_type: ThreatType,
        file_data: &FileData,
    ) -> ThreatEvent {
        let severity = match risk_score {
            s if s >= 0.8 => ThreatSeverity::Critical,
            s if s >= 0.6 => ThreatSeverity::High,
            s if s >= 0.4 => ThreatSeverity::Medium,
            _ => ThreatSeverity::Low,
        };

        let indicators = ThreatIndicators {
            email: None,
            voice: None,
            sms: None,
            web: None,
            file: Some(FileIndicators {
                filename: file_data.filename.clone(),
                file_size: file_data.file_size,
                file_type: file_data.file_type.clone(),
                mime_type: file_data.mime_type.clone(),
                expected_hash: file_data.expected_hash.clone(),
                actual_hash: file_data.actual_hash.clone(),
                hash_algorithm: file_data.hash_algorithm.clone(),
                signature_valid: file_data.signature_info.as_ref().map(|s| s.valid),
                signer: file_data.signature_info.as_ref().and_then(|s| s.signer.clone()),
                signature_timestamp: file_data.signature_info.as_ref().and_then(|s| s.timestamp),
                virus_total_score: file_data.virus_total_score,
                malware_detected: file_data.malware_scan_score.unwrap_or(0.0) > 0.5,
                suspicious_entropy: file_data.entropy.unwrap_or(0.0) > 7.5,
            }),
            social: None,
            identity: None,
            network: None,
        };

        ThreatEvent {
            id: format!("file-{}-{}", entity_id.0, chrono::Utc::now().timestamp()),
            entity_id,
            timestamp: chrono::Utc::now(),
            threat_vector: ThreatVector::File,
            threat_type,
            severity,
            risk_score,
            confidence: Confidence::new(0.85),
            description: format!("File threat detected: {:?} in {}", threat_type, file_data.filename),
            detection_source: "FileDetector".to_string(),
            indicators,
            investigated: false,
            notes: String::new(),
        }
    }

    fn load_trusted_publishers() -> Vec<String> {
        vec![
            "Microsoft Corporation".to_string(),
            "Apple Inc.".to_string(),
            "Google LLC".to_string(),
            "Mozilla Corporation".to_string(),
            "Adobe Inc.".to_string(),
        ]
    }
}

impl Default for FileDetector {
    fn default() -> Self {
        Self::new()
    }
}

// ── Supporting data structures ─────────────────────────────────────

/// Input data for email threat analysis.
#[derive(Debug, Clone)]
pub struct EmailData {
    pub from_address: String,
    pub display_name: Option<String>,
    pub from_domain: String,
    pub subject: String,
    pub content: String,
    pub headers: HashMap<String, String>,
    pub attachments: Vec<String>,
    pub spf_pass: Option<bool>,
    pub dkim_pass: Option<bool>,
    pub dmarc_pass: Option<bool>,
}

/// Input data for web request threat analysis.
#[derive(Debug, Clone)]
pub struct WebRequestData {
    pub domain: String,
    pub path: String,
    pub ssl_info: Option<SslInfo>,
    pub user_agent: Option<String>,
    pub referer: Option<String>,
}

/// SSL certificate information.
#[derive(Debug, Clone)]
pub struct SslInfo {
    pub valid: bool,
    pub issuer: Option<String>,
    pub age_days: Option<u32>,
}

/// Input data for file integrity analysis.
#[derive(Debug, Clone)]
pub struct FileData {
    pub filename: String,
    pub file_size: u64,
    pub file_type: String,
    pub mime_type: String,
    pub expected_hash: Option<String>,
    pub actual_hash: Option<String>,
    pub hash_algorithm: Option<String>,
    pub signature_info: Option<SignatureInfo>,
    pub virus_total_score: Option<u32>,
    pub malware_scan_score: Option<f64>,
    pub entropy: Option<f64>,
}

/// Digital signature information.
#[derive(Debug, Clone)]
pub struct SignatureInfo {
    pub valid: bool,
    pub signer: Option<String>,
    pub timestamp: Option<crate::types::Timestamp>,
}

/// Result of email content analysis.
#[derive(Debug, Clone)]
struct ContentAnalysisResult {
    pub phishing_score: f64,
    pub confidence: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_email_detector_creation() {
        let detector = EmailDetector::new();
        assert!(!detector.phishing_domains.is_empty());
        assert!(!detector.urgency_patterns.is_empty());
    }

    #[test]
    fn test_web_detector_typosquatting() {
        let detector = WebDetector::new();
        let score = detector.detect_typosquatting("gooogle.com");
        assert!(score > 0.5);
    }

    #[test]
    fn test_file_detector_hash_verification() {
        let detector = FileDetector::new();
        let file_data = FileData {
            filename: "test.exe".to_string(),
            file_size: 1024,
            file_type: "executable".to_string(),
            mime_type: "application/octet-stream".to_string(),
            expected_hash: Some("abc123".to_string()),
            actual_hash: Some("def456".to_string()),
            hash_algorithm: Some("SHA256".to_string()),
            signature_info: None,
            virus_total_score: None,
            malware_scan_score: None,
            entropy: None,
        };
        
        let hash_score = detector.verify_file_hash(&file_data);
        assert_eq!(hash_score, Some(0.9)); // Hash mismatch
    }
}
