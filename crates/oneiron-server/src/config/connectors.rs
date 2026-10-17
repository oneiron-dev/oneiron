//! `[connectors.<name>]`: where this host installed each catalog
//! connector's transport (ONE-2510).
//!
//! File-only, like `[native_mail]`. Canon keeps the transport beneath the
//! catalog name, never part of it: the guest calls a connector by name, and
//! this section is where the host says how that name is reached. A name with
//! no section has no installed transport, so its calls are refused. The
//! grant's endpoint allowlist still gates the endpoint named here.
//!
//! ```toml
//! [connectors.github]
//! transport = "mcp_http"
//! endpoint = "https://mcp.example.com/mcp"
//! ```

use serde::Deserialize;

/// How the host reaches a connector. MCP streamable HTTP is the only one.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorTransport {
    McpHttp,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConnectorHostConfig {
    pub transport: ConnectorTransport,
    /// The MCP endpoint: https, or http on loopback.
    pub endpoint: String,
}

impl ConnectorHostConfig {
    pub(crate) fn validate(&self, name: &str) -> anyhow::Result<()> {
        if normalize_name(name).is_empty() {
            anyhow::bail!("[connectors]: a connector section needs a name");
        }
        let url = reqwest::Url::parse(&self.endpoint)
            .map_err(|_| anyhow::anyhow!("[connectors.{name}]: endpoint is not a URL"))?;
        let loopback = matches!(
            url.host_str(),
            Some("localhost" | "127.0.0.1" | "[::1]" | "::1")
        );
        if !(url.scheme() == "https" || url.scheme() == "http" && loopback)
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
        {
            anyhow::bail!(
                "[connectors.{name}]: endpoint must be https, or http on loopback, with no \
                 credentials or fragment"
            );
        }
        Ok(())
    }
}

/// A section name spelled as the engine stores catalog names.
pub fn normalize_name(name: &str) -> String {
    name.trim().to_ascii_lowercase().replace('-', "_")
}
