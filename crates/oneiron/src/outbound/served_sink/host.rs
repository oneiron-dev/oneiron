//! What a served host hands its served sinks beyond the vault (OF-187): where
//! each provider's API is, the host's own mail server, and its connector
//! calls. A host installs one on its vault handle; every served sink on that
//! handle reads it. A sink on a handle with none sends to each provider's
//! public API, has no mail server and makes no connector call.

use std::sync::Arc;

use crate::Vault;
use crate::channel_identity_provider::stalwart::StalwartConfig;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::outbound_consent::{
    ConnectorCallInvocation, ConnectorCallOutcome, ConnectorCallRequest,
};
use crate::outbound_intent_ledger::IntentLedgerError;

/// Slack's Web API.
pub const SLACK_API_BASE: &str = "https://slack.com/api";
/// LINE's Messaging API.
pub const LINE_API_BASE: &str = "https://api.line.me";
/// Telegram's Bot API.
pub const TELEGRAM_API_BASE: &str = "https://api.telegram.org";

/// The provider APIs a served sink sends to: each provider's public API
/// unless the host moves it, to a relay of its own or a recording stand-in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServedEndpoints {
    slack: String,
    line: String,
    telegram: String,
}

impl Default for ServedEndpoints {
    fn default() -> Self {
        Self {
            slack: SLACK_API_BASE.to_owned(),
            line: LINE_API_BASE.to_owned(),
            telegram: TELEGRAM_API_BASE.to_owned(),
        }
    }
}

impl ServedEndpoints {
    /// Slack's Web API at `base` (in place of [`SLACK_API_BASE`]).
    ///
    /// # Errors
    ///
    /// `base` is not https, or http on loopback, with no credentials, query
    /// or fragment.
    pub fn with_slack(mut self, base: &str) -> Result<Self> {
        self.slack = endpoint_base(base, "slack")?;
        Ok(self)
    }

    /// LINE's Messaging API at `base` (in place of [`LINE_API_BASE`]).
    ///
    /// # Errors
    ///
    /// As [`Self::with_slack`].
    pub fn with_line(mut self, base: &str) -> Result<Self> {
        self.line = endpoint_base(base, "line")?;
        Ok(self)
    }

    /// Telegram's Bot API at `base` (in place of [`TELEGRAM_API_BASE`]).
    ///
    /// # Errors
    ///
    /// As [`Self::with_slack`].
    pub fn with_telegram(mut self, base: &str) -> Result<Self> {
        self.telegram = endpoint_base(base, "telegram")?;
        Ok(self)
    }

    /// One Slack Web API method's URL.
    pub(super) fn slack(&self, method: &str) -> String {
        format!("{}/{method}", self.slack)
    }

    /// One LINE Messaging API path's URL; `path` starts with `/`.
    pub(super) fn line(&self, path: &str) -> String {
        format!("{}{path}", self.line)
    }

    /// One Telegram Bot API method's URL. The bot token is part of the
    /// path, so the URL is never logged.
    pub(super) fn telegram(&self, token: &str, method: &str) -> String {
        format!("{}/bot{token}/{method}", self.telegram)
    }
}

/// A provider API base: https, or http on loopback, with no credentials,
/// query or fragment, kept without a trailing slash.
fn endpoint_base(base: &str, provider: &str) -> Result<String> {
    let invalid = || {
        Error::InvalidConfig(format!(
            "the {provider} endpoint must be an https URL, or http on loopback, with no credentials, query or fragment"
        ))
    };
    let url = reqwest::Url::parse(base.trim()).map_err(|_| invalid())?;
    let loopback = matches!(
        url.host_str(),
        Some("localhost" | "127.0.0.1" | "[::1]" | "::1")
    );
    if !(url.scheme() == "https" || url.scheme() == "http" && loopback)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(invalid());
    }
    Ok(url.as_str().trim_end_matches('/').to_owned())
}

/// The host's connector calls (FIX 1168): a served send that rides an
/// installed connector's tools (LinkedIn's) makes each tool call through
/// them, as an admitted installed-tool call for its sender on the host's
/// connector call host, the path every connector tool call takes: the
/// caller's standing grant, the approved schema, the gate and the intent
/// ledger. Blocking: a call sends.
pub trait ServedConnectorCalls: Send + Sync + std::fmt::Debug {
    /// One tool call for `caller` on the vault this is installed on. A
    /// named `invocation` is one logical call: run again, it replays or
    /// resumes the call it held instead of sending twice; `None` is a call
    /// of its own.
    ///
    /// # Errors
    ///
    /// The call could not be prepared, held or recorded.
    fn call(
        &self,
        caller: EntityId,
        caller_class: EdgeActorClass,
        request: ConnectorCallRequest,
        invocation: Option<ConnectorCallInvocation>,
    ) -> std::result::Result<ConnectorCallOutcome, IntentLedgerError>;
}

/// What a served host gives its served sinks: the provider APIs, the
/// placement of its own mail server, which email sends leave through, and
/// its connector calls, which LinkedIn sends leave through.
#[derive(Clone, Debug, Default)]
pub struct ServedTransports {
    endpoints: ServedEndpoints,
    native_mail: Option<StalwartConfig>,
    connector_calls: Option<Arc<dyn ServedConnectorCalls>>,
}

impl ServedTransports {
    #[must_use]
    pub fn new(endpoints: ServedEndpoints) -> Self {
        Self {
            endpoints,
            native_mail: None,
            connector_calls: None,
        }
    }

    /// Email sends from native mail identities leave through the mail server
    /// at `placement`, the host's `[native_mail]` server.
    #[must_use]
    pub fn with_native_mail(mut self, placement: StalwartConfig) -> Self {
        self.native_mail = Some(placement);
        self
    }

    /// Sends that ride an installed connector's tools call them through
    /// `calls`, the host's own connector call host.
    #[must_use]
    pub fn with_connector_calls(mut self, calls: Arc<dyn ServedConnectorCalls>) -> Self {
        self.connector_calls = Some(calls);
        self
    }

    #[must_use]
    pub fn connector_calls(&self) -> Option<Arc<dyn ServedConnectorCalls>> {
        self.connector_calls.clone()
    }

    #[must_use]
    pub fn endpoints(&self) -> &ServedEndpoints {
        &self.endpoints
    }

    #[must_use]
    pub fn native_mail(&self) -> Option<&StalwartConfig> {
        self.native_mail.as_ref()
    }
}

impl Vault {
    /// Installs the host's served transports on this vault handle, once per
    /// open vault and never process-global. A second install does nothing.
    pub fn install_served_transports(&self, transports: Arc<ServedTransports>) {
        let _ = self.served_transports.set(transports);
    }

    /// The installed served transports; the public provider APIs and no mail
    /// server when the host installed none.
    pub(crate) fn served_transports(&self) -> Arc<ServedTransports> {
        self.served_transports.get().cloned().unwrap_or_default()
    }
}
