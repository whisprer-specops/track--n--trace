//! HTTP transport/request profiles.
//!
//! This keeps authentication, custom headers, and proxy routing out of the
//! core engine contracts while still allowing adapters to remain lean and
//! configurable.

use std::time::Duration;

use base64::Engine as _;
use serde::{Deserialize, Serialize};

use crate::types::ValidationError;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransportError {
    Validation(String),
    Proxy(String),
    Request(String),
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Validation(msg) => write!(f, "transport validation error: {msg}"),
            Self::Proxy(msg) => write!(f, "transport proxy error: {msg}"),
            Self::Request(msg) => write!(f, "transport request error: {msg}"),
        }
    }
}

impl std::error::Error for TransportError {}

impl From<ValidationError> for TransportError {
    fn from(value: ValidationError) -> Self {
        Self::Validation(value.to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeaderPair {
    pub name: String,
    pub value: String,
}

impl HeaderPair {
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.name.trim().is_empty() {
            return Err(ValidationError::EmptyField("header.name".into()));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthConfig {
    BearerToken { token: String },
    Basic { username: String, password: String },
    Header { name: String, value: String },
}

impl AuthConfig {
    pub fn validate(&self) -> Result<(), ValidationError> {
        match self {
            Self::BearerToken { token } if token.trim().is_empty() => {
                Err(ValidationError::EmptyField("auth.bearer_token".into()))
            }
            Self::Basic { username, .. } if username.trim().is_empty() => {
                Err(ValidationError::EmptyField("auth.basic.username".into()))
            }
            Self::Header { name, value } => {
                if name.trim().is_empty() {
                    return Err(ValidationError::EmptyField("auth.header.name".into()));
                }
                if value.trim().is_empty() {
                    return Err(ValidationError::EmptyField("auth.header.value".into()));
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProxyRoute {
    Direct,
    Http { proxy_url: String },
    Socks5 { proxy_url: String },
    TorDefault,
    TorCustom { proxy_url: String },
}

impl ProxyRoute {
    pub fn validate(&self) -> Result<(), ValidationError> {
        match self {
            Self::Http { proxy_url }
            | Self::Socks5 { proxy_url }
            | Self::TorCustom { proxy_url }
                if proxy_url.trim().is_empty() =>
            {
                Err(ValidationError::EmptyField("proxy.proxy_url".into()))
            }
            _ => Ok(()),
        }
    }

    #[must_use]
    pub fn proxy_url(&self) -> Option<&str> {
        match self {
            Self::Direct => None,
            Self::Http { proxy_url }
            | Self::Socks5 { proxy_url }
            | Self::TorCustom { proxy_url } => Some(proxy_url.as_str()),
            Self::TorDefault => Some("socks5://127.0.0.1:9050"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpRequestProfile {
    pub timeout: Duration,
    pub headers: Vec<HeaderPair>,
    pub auth: Option<AuthConfig>,
    pub proxy_route: ProxyRoute,
    pub user_agent: Option<String>,
}

impl HttpRequestProfile {
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.timeout.is_zero() {
            return Err(ValidationError::ZeroCapacity(
                "request_profile.timeout".into(),
            ));
        }
        self.proxy_route.validate()?;
        for header in &self.headers {
            header.validate()?;
        }
        if let Some(auth) = &self.auth {
            auth.validate()?;
        }
        if let Some(user_agent) = &self.user_agent {
            if user_agent.trim().is_empty() {
                return Err(ValidationError::EmptyField(
                    "request_profile.user_agent".into(),
                ));
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn direct(timeout: Duration) -> Self {
        Self {
            timeout,
            headers: Vec::new(),
            auth: None,
            proxy_route: ProxyRoute::Direct,
            user_agent: Some("skeletrace/0.5".into()),
        }
    }

    #[must_use]
    pub fn tor_default(timeout: Duration) -> Self {
        Self {
            proxy_route: ProxyRoute::TorDefault,
            ..Self::direct(timeout)
        }
    }
}

pub fn http_get_text(
    endpoint: &str,
    profile: &HttpRequestProfile,
) -> Result<String, TransportError> {
    profile.validate()?;

    let mut builder = ureq::AgentBuilder::new()
        .timeout_connect(profile.timeout)
        .timeout_read(profile.timeout)
        .timeout_write(profile.timeout);

    if let Some(proxy_url) = profile.proxy_route.proxy_url() {
        let proxy =
            ureq::Proxy::new(proxy_url).map_err(|err| TransportError::Proxy(err.to_string()))?;
        builder = builder.proxy(proxy);
    }

    let agent = builder.build();
    let mut request = agent.get(endpoint);

    if let Some(user_agent) = &profile.user_agent {
        request = request.set("User-Agent", user_agent);
    }
    for header in &profile.headers {
        request = request.set(&header.name, &header.value);
    }
    if let Some(auth) = &profile.auth {
        request = match auth {
            AuthConfig::BearerToken { token } => {
                request.set("Authorization", &format!("Bearer {token}"))
            }
            AuthConfig::Basic { username, password } => {
                let encoded = base64::engine::general_purpose::STANDARD
                    .encode(format!("{username}:{password}"));
                request.set("Authorization", &format!("Basic {encoded}"))
            }
            AuthConfig::Header { name, value } => request.set(name, value),
        };
    }

    let response = request
        .call()
        .map_err(|err| TransportError::Request(err.to_string()))?;
    response
        .into_string()
        .map_err(|err| TransportError::Request(err.to_string()))
}
