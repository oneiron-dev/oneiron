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
//!
//! [connectors.notes]
//! transport = "http_api"
//! endpoint = "https://api.example.com/v1"
//! document = "/etc/oneiron/notes-openapi.json"
//! ```

use serde::Deserialize;

/// How the host reaches a connector.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorTransport {
    /// MCP streamable HTTP.
    McpHttp,
    /// A plain HTTP API its OpenAPI document describes (L8-31): each
    /// operation is a tool, and each call is one request to the endpoint.
    HttpApi,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConnectorHostConfig {
    pub transport: ConnectorTransport,
    /// The MCP endpoint, or the HTTP API's base URL every call goes under:
    /// https, or http on loopback.
    pub endpoint: String,
    /// `http_api` only: the API's document, an absolute file path on this
    /// host or a URL (https, or http on loopback). The host reads it at
    /// register and refresh; a call never does.
    #[serde(default)]
    pub document: Option<String>,
}

impl ConnectorHostConfig {
    pub(crate) fn validate(&self, name: &str) -> anyhow::Result<()> {
        if normalize_name(name).is_empty() {
            anyhow::bail!("[connectors]: a connector section needs a name");
        }
        checked_url(name, "endpoint", &self.endpoint)?;
        match (self.transport, &self.document) {
            (ConnectorTransport::McpHttp, None) => {}
            (ConnectorTransport::McpHttp, Some(_)) => {
                anyhow::bail!("[connectors.{name}]: document is for transport = \"http_api\" only")
            }
            (ConnectorTransport::HttpApi, None) => {
                anyhow::bail!("[connectors.{name}]: transport = \"http_api\" needs a document")
            }
            (ConnectorTransport::HttpApi, Some(document)) => {
                if !document.starts_with('/') {
                    checked_url(name, "document", document)?;
                }
            }
        }
        Ok(())
    }
}

/// `value` is https, or http on loopback, with no credentials or fragment.
fn checked_url(name: &str, field: &str, value: &str) -> anyhow::Result<()> {
    let url = reqwest::Url::parse(value)
        .map_err(|_| anyhow::anyhow!("[connectors.{name}]: {field} is not a URL"))?;
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
            "[connectors.{name}]: {field} must be https, or http on loopback, with no \
             credentials or fragment"
        );
    }
    Ok(())
}

/// A section name spelled as the engine stores catalog names.
pub fn normalize_name(name: &str) -> String {
    name.trim().to_ascii_lowercase().replace('-', "_")
}
