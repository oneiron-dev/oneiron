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
//! transport = "mcp_stdio"
//! command = ["python3", "/opt/notes-mcp/server.py"]
//! env = { LOG_LEVEL = "info" }
//! cwd = "/opt/notes-mcp"
//!
//! [connectors.issues]
//! transport = "mcp_stdio"
//! command = ["issues-mcp", "stdio"]
//! upstream = { origin = "https://api.example.com", base_url_env = "ISSUES_API_URL", token_env = "ISSUES_TOKEN" }
//! ```
//!
//! An `mcp_stdio` connector is a child process this host starts under the
//! runner fence (canon `#runner-fence`, row L8-27) and speaks MCP to over
//! its standard input and output. Its endpoint, the one a grant names, is
//! `stdio:<name>:<16 hex>`, the hex a digest of its command, environment,
//! working directory and upstream, so any change to them is a new endpoint
//! the owner grants again, as for an HTTP endpoint that moves. Its
//! environment holds no credential: a name that reads as one is refused
//! here. A connector that names an `upstream` reaches that API through this
//! server's loopback door (B2, RULING L8-27-B2-STDIO): its environment holds
//! the door's URL and a reference to the door, and the door adds the
//! credential the call presents. A route that presents a credential to a
//! stdio connector with no upstream is not sent.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;

/// How the host reaches a connector: MCP streamable HTTP, or MCP over the
/// standard streams of a child process it starts.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorTransport {
    McpHttp,
    McpStdio,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConnectorHostConfig {
    pub transport: ConnectorTransport,
    /// The MCP endpoint of an `mcp_http` connector: https, or http on
    /// loopback. An `mcp_stdio` connector names none.
    #[serde(default)]
    pub endpoint: Option<String>,
    /// An `mcp_stdio` connector's program and its arguments.
    #[serde(default)]
    pub command: Vec<String>,
    /// Variables an `mcp_stdio` child gets beside the few it inherits;
    /// never a credential.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// The absolute directory an `mcp_stdio` child starts in; its own
    /// temp directory when absent.
    #[serde(default)]
    pub cwd: Option<PathBuf>,
    /// The API an `mcp_stdio` child calls with the credential its call
    /// presents, through this server's door.
    #[serde(default)]
    pub upstream: Option<StdioUpstream>,
}

/// The API an `mcp_stdio` connector's child calls, and the variables it
/// reads that API's base URL and key from. The child gets the door's URL and
/// its reference to the door in them; the door sends each request on to
/// `origin` with the credential the call presents.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StdioUpstream {
    /// `https://host[:port]`, or `http` on loopback: no path, query,
    /// fragment or credentials.
    pub origin: String,
    /// The variable the child reads the API's base URL from.
    pub base_url_env: String,
    /// The variable the child reads its API key from.
    pub token_env: String,
}

/// The variables an `mcp_stdio` child keeps of this process's environment:
/// the MCP SDKs' default inherited set on a Unix host.
pub const STDIO_INHERITED_ENV: [&str; 6] = ["HOME", "LOGNAME", "PATH", "SHELL", "TERM", "USER"];

/// The scheme of the endpoint an `mcp_stdio` connector is granted under.
pub const STDIO_ENDPOINT_SCHEME: &str = "stdio";

impl ConnectorHostConfig {
    /// Checks the section `[connectors.<name>]` as the config loads it.
    ///
    /// # Errors
    /// The section names no connector; an `mcp_http` one has no https (or
    /// loopback http) endpoint, or names stdio settings; an `mcp_stdio` one
    /// names an endpoint, no command, a part or variable that cannot be
    /// set, a variable that reads as a credential, a relative `cwd`, or an
    /// upstream whose origin is not https (or loopback http) alone or whose
    /// variables cannot be set apart from the rest.
    pub fn validate(&self, name: &str) -> anyhow::Result<()> {
        if normalize_name(name).is_empty() {
            anyhow::bail!("[connectors]: a connector section needs a name");
        }
        match self.transport {
            ConnectorTransport::McpHttp => self.validate_http(name),
            ConnectorTransport::McpStdio => self.validate_stdio(name),
        }
    }

    fn validate_http(&self, name: &str) -> anyhow::Result<()> {
        if !self.command.is_empty()
            || !self.env.is_empty()
            || self.cwd.is_some()
            || self.upstream.is_some()
        {
            anyhow::bail!(
                "[connectors.{name}]: command, env, cwd and upstream belong to an mcp_stdio \
                 connector"
            );
        }
        let Some(endpoint) = self.endpoint.as_deref() else {
            anyhow::bail!("[connectors.{name}]: an mcp_http connector needs an endpoint");
        };
        if sendable_url(endpoint).is_none() {
            anyhow::bail!(
                "[connectors.{name}]: endpoint must be https, or http on loopback, with no \
                 credentials or fragment"
            );
        }
        Ok(())
    }

    fn validate_stdio(&self, name: &str) -> anyhow::Result<()> {
        if self.endpoint.is_some() {
            anyhow::bail!(
                "[connectors.{name}]: an mcp_stdio connector names no endpoint; its command is \
                 its transport"
            );
        }
        if self
            .command
            .first()
            .is_none_or(|program| program.is_empty())
        {
            anyhow::bail!("[connectors.{name}]: an mcp_stdio connector needs a command");
        }
        if self.command.iter().any(|part| part.contains('\0')) {
            anyhow::bail!("[connectors.{name}]: a command part holds a NUL byte");
        }
        for (key, value) in &self.env {
            if key.is_empty() || key.contains(['=', '\0']) || value.contains('\0') {
                anyhow::bail!("[connectors.{name}]: env holds a variable that cannot be set");
            }
            if names_a_credential(key) {
                anyhow::bail!(
                    "[connectors.{name}]: env variable {key} reads as a credential; a stdio \
                     connector's credential goes through custody, never its environment"
                );
            }
        }
        if self.cwd.as_deref().is_some_and(|cwd| !cwd.is_absolute()) {
            anyhow::bail!("[connectors.{name}]: cwd must be an absolute path");
        }
        if let Some(upstream) = &self.upstream {
            self.validate_upstream(name, upstream)?;
        }
        Ok(())
    }

    fn validate_upstream(&self, name: &str, upstream: &StdioUpstream) -> anyhow::Result<()> {
        let origin = sendable_url(&upstream.origin).filter(|url| {
            matches!(url.path(), "" | "/") && url.query().is_none() && url.host_str().is_some()
        });
        if origin.is_none() {
            anyhow::bail!(
                "[connectors.{name}]: upstream origin must be https, or http on loopback, with \
                 no path, query, credentials or fragment"
            );
        }
        let names = [upstream.base_url_env.as_str(), upstream.token_env.as_str()];
        for variable in names {
            let settable = variable
                .chars()
                .next()
                .is_some_and(|first| first.is_ascii_alphabetic() || first == '_')
                && variable
                    .chars()
                    .all(|part| part.is_ascii_alphanumeric() || part == '_');
            if !settable
                || variable == "TMPDIR"
                || STDIO_INHERITED_ENV.contains(&variable)
                || self.env.contains_key(variable)
            {
                anyhow::bail!(
                    "[connectors.{name}]: upstream variable {variable:?} cannot be set apart \
                     from the child's other variables"
                );
            }
        }
        if names[0] == names[1] {
            anyhow::bail!("[connectors.{name}]: upstream base_url_env and token_env must differ");
        }
        Ok(())
    }

    /// The endpoint this host installed for the connector `name`: the URL of
    /// an `mcp_http` connector, and `stdio:<name>:<16 hex>` for an
    /// `mcp_stdio` one. A grant's endpoint allowlist names exactly this, and
    /// a send goes only where its frozen call's endpoint still equals it.
    #[must_use]
    pub fn installed_endpoint(&self, name: &str) -> String {
        match self.transport {
            ConnectorTransport::McpHttp => self.endpoint.clone().unwrap_or_default(),
            ConnectorTransport::McpStdio => format!(
                "{STDIO_ENDPOINT_SCHEME}:{}:{}",
                normalize_name(name),
                stdio_identity(
                    &self.command,
                    &self.env,
                    self.cwd.as_deref(),
                    self.upstream.as_ref()
                )
            ),
        }
    }

    /// The URL an `mcp_http` connector is installed at; `None` for an
    /// `mcp_stdio` one, which has no HTTP session to take up, poll or end.
    #[must_use]
    pub fn http_endpoint(&self) -> Option<&str> {
        match self.transport {
            ConnectorTransport::McpHttp => self.endpoint.as_deref(),
            ConnectorTransport::McpStdio => None,
        }
    }
}

/// 16 hex of blake3 over a stdio connector's command, environment,
/// working directory and upstream, each part length-prefixed so no two
/// settings hash alike. A connector with no upstream hashes as it did
/// before upstreams were taken.
fn stdio_identity(
    command: &[String],
    env: &BTreeMap<String, String>,
    cwd: Option<&Path>,
    upstream: Option<&StdioUpstream>,
) -> String {
    let mut digest = blake3::Hasher::new();
    let mut part = |bytes: &[u8]| {
        digest.update(&(bytes.len() as u64).to_le_bytes());
        digest.update(bytes);
    };
    part(b"oneiron connector stdio v1");
    part(&(command.len() as u64).to_le_bytes());
    for arg in command {
        part(arg.as_bytes());
    }
    part(&(env.len() as u64).to_le_bytes());
    for (key, value) in env {
        part(key.as_bytes());
        part(value.as_bytes());
    }
    match cwd {
        Some(cwd) => part(cwd.as_os_str().as_encoded_bytes()),
        None => part(&[]),
    }
    if let Some(upstream) = upstream {
        part(b"upstream");
        part(upstream.origin.as_bytes());
        part(upstream.base_url_env.as_bytes());
        part(upstream.token_env.as_bytes());
    }
    let hex = digest.finalize().to_hex();
    hex[..16].to_owned()
}

/// Whether an environment variable name reads as a credential: one of its
/// `_`, `-` or `.` separated words is a credential word (`GITHUB_TOKEN`,
/// `OPENAI_API_KEY`, `DB_PASSWORD`), or the whole name is one
/// (`ACCESSTOKEN`). A word that only contains one (`TOKENIZERS_PARALLELISM`)
/// is not.
fn names_a_credential(key: &str) -> bool {
    const WORDS: [&str; 22] = [
        "key",
        "apikey",
        "token",
        "accesstoken",
        "refreshtoken",
        "idtoken",
        "secret",
        "secretkey",
        "clientsecret",
        "privatekey",
        "signingkey",
        "password",
        "passwd",
        "pwd",
        "auth",
        "authorization",
        "bearer",
        "credential",
        "credentials",
        "cookie",
        "pat",
        "session",
    ];
    key.to_ascii_lowercase()
        .split(['_', '-', '.'])
        .any(|word| WORDS.contains(&word))
}

/// `text` as a URL this host sends to: https, or http on loopback, with no
/// credentials or fragment.
fn sendable_url(text: &str) -> Option<reqwest::Url> {
    let url = reqwest::Url::parse(text).ok()?;
    let loopback = matches!(
        url.host_str(),
        Some("localhost" | "127.0.0.1" | "[::1]" | "::1")
    );
    let sendable = (url.scheme() == "https" || url.scheme() == "http" && loopback)
        && url.username().is_empty()
        && url.password().is_none()
        && url.fragment().is_none();
    sendable.then_some(url)
}

/// A section name spelled as the engine stores catalog names.
pub fn normalize_name(name: &str) -> String {
    name.trim().to_ascii_lowercase().replace('-', "_")
}
