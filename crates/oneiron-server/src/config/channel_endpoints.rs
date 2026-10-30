//! `[channel_endpoints]`: where the served sinks reach each provider's API
//! (FIX 4435). File-only, like `[line]`. Absent, or a provider unnamed, means
//! the provider's public API. A host names one to send through its own relay,
//! or a recording stand-in that sees exactly what a send would deliver.
//!
//! ```toml
//! [channel_endpoints]
//! slack = "https://slack.relay.example.com/api"   # default https://slack.com/api
//! line = "http://127.0.0.1:9400"                  # default https://api.line.me
//! telegram = "http://127.0.0.1:9401"              # default https://api.telegram.org
//! ```

use oneiron::outbound::ServedEndpoints;
use serde::Deserialize;

/// The provider API bases a host moves; each https, or http on loopback.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ChannelEndpointsConfig {
    #[serde(default)]
    pub slack: Option<String>,
    #[serde(default)]
    pub line: Option<String>,
    #[serde(default)]
    pub telegram: Option<String>,
}

impl ChannelEndpointsConfig {
    /// The served sinks' provider APIs this section names.
    ///
    /// # Errors
    /// A named base is not https, or http on loopback, or carries
    /// credentials, a query or a fragment.
    pub(crate) fn endpoints(&self) -> oneiron::Result<ServedEndpoints> {
        let mut endpoints = ServedEndpoints::default();
        if let Some(base) = &self.slack {
            endpoints = endpoints.with_slack(base)?;
        }
        if let Some(base) = &self.line {
            endpoints = endpoints.with_line(base)?;
        }
        if let Some(base) = &self.telegram {
            endpoints = endpoints.with_telegram(base)?;
        }
        Ok(endpoints)
    }

    pub(super) fn validate(&self) -> anyhow::Result<()> {
        self.endpoints()
            .map(|_| ())
            .map_err(|error| anyhow::anyhow!("[channel_endpoints]: {error}"))
    }
}
