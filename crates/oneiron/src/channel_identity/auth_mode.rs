//! Credential mechanism labels. Secret material never belongs to a channel row.
use crate::error::{RecordError, Result};

/// Closed authentication modes. These describe a host adapter, not credentials.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelAuthMode {
    /// In-process channel with no external credential.
    Local,
    /// Host-held provider API credential.
    ApiKey,
    /// Host-held OAuth grant.
    OAuth,
}
impl ChannelAuthMode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::ApiKey => "api_key",
            Self::OAuth => "oauth",
        }
    }
}
impl std::str::FromStr for ChannelAuthMode {
    type Err = crate::Error;
    fn from_str(value: &str) -> Result<Self> {
        match value {
            "local" => Ok(Self::Local),
            "api_key" => Ok(Self::ApiKey),
            "oauth" => Ok(Self::OAuth),
            _ => Err(RecordError::InvalidChannelIdentityBody("unknown auth mode").into()),
        }
    }
}
