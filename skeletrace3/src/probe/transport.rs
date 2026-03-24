//! Rate-limit aware HTTP transport for probe operations using std library only.
//!
//! This builds on the transport patterns established in earlier Skeletrace work.
//! Uses std::net::TcpStream for HTTP to avoid external dependency version conflicts
//! and keep the probe engine simple for CLI-only initial deployment.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

use log::{debug, warn};

use crate::probe::types::{ProbeResult, ProbeStatus, ProbeTarget};

// ── Rate limiter ───────────────────────────────────────────────────

/// Simple token-bucket rate limiter per host.
#[derive(Debug)]
struct RateLimiter {
    /// Tokens available.
    tokens: f64,
    /// Maximum tokens (bucket capacity).
    capacity: f64,
    /// Refill rate (tokens per second).
    refill_rate: f64,
    /// Last refill time.
    last_refill: Instant,
}

impl RateLimiter {
    fn new(capacity: f64, refill_rate: f64) -> Self {
        Self {
            tokens: capacity,
            capacity,
            refill_rate,
            last_refill: Instant::now(),
        }
    }

    /// Try to consume one token. Returns true if successful.
    fn try_consume(&mut self) -> bool {
        self.refill();
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Refill tokens based on elapsed time.
    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        let new_tokens = self.tokens + (elapsed * self.refill_rate);
        self.tokens = new_tokens.min(self.capacity);
        self.last_refill = now;
    }

    /// How long until next token is available.
    fn wait_time(&mut self) -> Duration {
        self.refill();
        if self.tokens >= 1.0 {
            Duration::ZERO
        } else {
            let needed = 1.0 - self.tokens;
            Duration::from_secs_f64(needed / self.refill_rate)
        }
    }
}

// ── HTTP transport client ──────────────────────────────────────────

/// Configuration for the HTTP probe transport.
#[derive(Debug, Clone)]
pub struct TransportConfig {
    /// Maximum requests per second per host.
    pub max_rps_per_host: f64,
    /// Token bucket capacity (burst allowance).
    pub burst_capacity: f64,
    /// Global timeout for all requests.
    pub global_timeout: Duration,
    /// User-Agent header to send.
    pub user_agent: String,
    /// Whether to follow redirects.
    pub follow_redirects: bool,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            max_rps_per_host: 2.0,
            burst_capacity: 5.0,
            global_timeout: Duration::from_secs(30),
            user_agent: "skeletrace-probe/0.1.0".to_string(),
            follow_redirects: false, // Keep simple for now
        }
    }
}

/// Simple HTTP response parser.
#[derive(Debug)]
struct HttpResponse {
    status_code: u16,
    headers: HashMap<String, String>,
    body_length: usize,
}

/// Rate-limit aware HTTP client for probe operations.
#[derive(Debug)]
pub struct ProbeTransport {
    /// Rate limiters per hostname.
    rate_limiters: HashMap<String, RateLimiter>,
    /// Transport configuration.
    config: TransportConfig,
}

impl ProbeTransport {
    /// Create a new probe transport with default configuration.
    pub fn new() -> Self {
        Self::with_config(TransportConfig::default())
    }

    /// Create a new probe transport with custom configuration.
    pub fn with_config(config: TransportConfig) -> Self {
        Self {
            rate_limiters: HashMap::new(),
            config,
        }
    }

    /// Execute a single probe operation.
    ///
    /// This handles rate limiting, HTTP execution, and result packaging.
    /// Returns a `ProbeResult` regardless of success/failure.
    pub fn execute_probe(&mut self, target: &ProbeTarget) -> ProbeResult {
        let start_time = chrono::Utc::now();
        let probe_start = Instant::now();

        // Parse URL to get hostname and path
        let (hostname, port, path) = match self.parse_url(&target.url) {
            Ok(parts) => parts,
            Err(e) => {
                return ProbeResult {
                    entity_id: target.entity_id,
                    timestamp: start_time,
                    status: ProbeStatus::Down,
                    latency: None,
                    http_status: None,
                    response_bytes: None,
                    error: Some(format!("Invalid URL: {}", e)),
                    url: target.url.clone(),
                };
            }
        };

        // Rate limiting check
        if let Err(wait_time) = self.check_rate_limit(&hostname) {
            debug!(
                "Rate limited for {}: would wait {:?}",
                hostname, wait_time
            );
            return ProbeResult {
                entity_id: target.entity_id,
                timestamp: start_time,
                status: ProbeStatus::Skipped,
                latency: None,
                http_status: None,
                response_bytes: None,
                error: Some(format!("Rate limited, would wait {:?}", wait_time)),
                url: target.url.clone(),
            };
        }

        // Execute HTTP request
        match self.execute_http_request(&hostname, port, &path, target) {
            Ok(response) => {
                let latency = probe_start.elapsed();
                let is_expected = target.expected_status.contains(&response.status_code);

                let status = if is_expected {
                    ProbeStatus::Up
                } else {
                    ProbeStatus::Degraded
                };

                ProbeResult {
                    entity_id: target.entity_id,
                    timestamp: start_time,
                    status,
                    latency: Some(latency),
                    http_status: Some(response.status_code),
                    response_bytes: Some(response.body_length),
                    error: None,
                    url: target.url.clone(),
                }
            }
            Err(e) => {
                warn!("HTTP error for {}: {}", target.url, e);
                ProbeResult {
                    entity_id: target.entity_id,
                    timestamp: start_time,
                    status: ProbeStatus::Down,
                    latency: None,
                    http_status: None,
                    response_bytes: None,
                    error: Some(e),
                    url: target.url.clone(),
                }
            }
        }
    }

    // ── Helpers ────────────────────────────────────────────────────

    /// Parse URL to extract hostname, port, and path.
    fn parse_url(&self, url: &str) -> Result<(String, u16, String), String> {
        let url = url.trim();
        
        // Extract scheme
        let (scheme, after_scheme) = if let Some(pos) = url.find("://") {
            let scheme = &url[..pos];
            let after = &url[pos + 3..];
            (scheme, after)
        } else {
            return Err("No scheme found".to_string());
        };

        // Default port based on scheme
        let default_port = match scheme.to_lowercase().as_str() {
            "http" => 80,
            "https" => 443,
            _ => return Err(format!("Unsupported scheme: {}", scheme)),
        };

        // Split hostname:port from path
        let (host_part, path) = if let Some(pos) = after_scheme.find('/') {
            let host = &after_scheme[..pos];
            let path = &after_scheme[pos..];
            (host, path.to_string())
        } else {
            (after_scheme, "/".to_string())
        };

        // Parse hostname and port
        let (hostname, port) = if let Some(pos) = host_part.find(':') {
            let host = &host_part[..pos];
            let port_str = &host_part[pos + 1..];
            let port = port_str.parse::<u16>()
                .map_err(|_| format!("Invalid port: {}", port_str))?;
            (host.to_lowercase(), port)
        } else {
            (host_part.to_lowercase(), default_port)
        };

        if hostname.is_empty() {
            return Err("Empty hostname".to_string());
        }

        Ok((hostname, port, path))
    }

    /// Execute HTTP request using std::net::TcpStream.
    fn execute_http_request(
        &self,
        hostname: &str,
        port: u16,
        path: &str,
        target: &ProbeTarget,
    ) -> Result<HttpResponse, String> {
        // Connect with timeout
        let addr = format!("{}:{}", hostname, port);
        let addrs: Vec<_> = addr.to_socket_addrs()
            .map_err(|e| format!("DNS resolution failed: {}", e))?
            .collect();
        
        if addrs.is_empty() {
            return Err("No addresses resolved".to_string());
        }

        let mut stream = TcpStream::connect_timeout(&addrs[0], target.timeout)
            .map_err(|e| format!("Connection failed: {}", e))?;
        
        // Set read timeout
        stream.set_read_timeout(Some(target.timeout))
            .map_err(|e| format!("Failed to set timeout: {}", e))?;

        // Build HTTP request
        let method = target.method.as_str();
        let mut request = format!("{} {} HTTP/1.1\r\n", method, path);
        request.push_str(&format!("Host: {}\r\n", hostname));
        request.push_str(&format!("User-Agent: {}\r\n", self.config.user_agent));
        request.push_str("Connection: close\r\n");
        
        // Add custom headers
        for (key, value) in &target.headers {
            request.push_str(&format!("{}: {}\r\n", key, value));
        }

        // Add body for POST requests
        if let Some(ref body) = target.body {
            request.push_str(&format!("Content-Length: {}\r\n", body.len()));
            request.push_str("Content-Type: application/json\r\n");
            request.push_str("\r\n");
            request.push_str(body);
        } else {
            request.push_str("\r\n");
        }

        // Send request
        stream.write_all(request.as_bytes())
            .map_err(|e| format!("Failed to send request: {}", e))?;

        // Read response
        let mut response_data = Vec::new();
        stream.read_to_end(&mut response_data)
            .map_err(|e| format!("Failed to read response: {}", e))?;

        // Parse HTTP response
        self.parse_http_response(&response_data)
    }

    /// Parse HTTP response from raw bytes.
    fn parse_http_response(&self, data: &[u8]) -> Result<HttpResponse, String> {
        let response_str = String::from_utf8_lossy(data);
        let lines: Vec<&str> = response_str.split("\r\n").collect();
        
        if lines.is_empty() {
            return Err("Empty response".to_string());
        }

        // Parse status line: "HTTP/1.1 200 OK"
        let status_line = lines[0];
        let status_parts: Vec<&str> = status_line.split_whitespace().collect();
        if status_parts.len() < 2 {
            return Err("Invalid status line".to_string());
        }

        let status_code = status_parts[1].parse::<u16>()
            .map_err(|_| format!("Invalid status code: {}", status_parts[1]))?;

        // Parse headers
        let mut headers = HashMap::new();
        let mut i = 1;
        while i < lines.len() && !lines[i].is_empty() {
            if let Some(pos) = lines[i].find(':') {
                let key = lines[i][..pos].trim().to_lowercase();
                let value = lines[i][pos + 1..].trim().to_string();
                headers.insert(key, value);
            }
            i += 1;
        }

        // Estimate body length
        let body_start = i + 1;
        let body_length = lines[body_start..].join("\r\n").len();

        Ok(HttpResponse {
            status_code,
            headers,
            body_length,
        })
    }

    /// Check rate limit for hostname. Returns Ok() if request can proceed,
    /// Err(wait_time) if rate limited.
    fn check_rate_limit(&mut self, hostname: &str) -> Result<(), Duration> {
        let limiter = self.rate_limiters.entry(hostname.to_string()).or_insert_with(|| {
            RateLimiter::new(self.config.burst_capacity, self.config.max_rps_per_host)
        });

        if limiter.try_consume() {
            Ok(())
        } else {
            Err(limiter.wait_time())
        }
    }
}

impl Default for ProbeTransport {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limiter() {
        let mut limiter = RateLimiter::new(2.0, 1.0); // 2 tokens, 1 token/sec refill

        // Should be able to consume 2 tokens immediately
        assert!(limiter.try_consume());
        assert!(limiter.try_consume());

        // Third token should fail
        assert!(!limiter.try_consume());

        // Wait time should be ~1 second for next token
        let wait = limiter.wait_time();
        assert!(wait.as_secs_f64() > 0.9 && wait.as_secs_f64() <= 1.0);
    }

    #[test]
    fn test_url_parsing() {
        let transport = ProbeTransport::new();
        
        // Basic HTTP URL
        let (host, port, path) = transport.parse_url("http://example.com/test").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 80);
        assert_eq!(path, "/test");

        // HTTPS with port
        let (host, port, path) = transport.parse_url("https://api.example.com:8443/health").unwrap();
        assert_eq!(host, "api.example.com");
        assert_eq!(port, 8443);
        assert_eq!(path, "/health");

        // Root path
        let (host, port, path) = transport.parse_url("http://example.com").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 80);
        assert_eq!(path, "/");
    }
}

