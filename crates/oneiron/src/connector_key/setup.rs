//! Guided pack setup's grants and connection checks (OF-378).
//!
//! An owner allows a connection's permissions one by one; each allowed
//! permission is one standing consent grant whose Gate receipt the consent
//! door writes, and one withdrawn is revoked through the same door, with its
//! receipt. There is no second grant or receipt store: the setup session
//! keeps the grant refs and decision ids only.
//!
//! A connection is checked before use. The check is the host's: either a
//! [`PackConnectionVerifier`] runs one read-only provider call through the
//! credential door, or a bound connector key clears its real qualification
//! suite. A pack names a check; it never names a URL. A check passes against
//! exactly the grants, custody records and key it ran with; when any of them
//! moves, the result goes stale and the connection is not ready.

use std::collections::BTreeSet;
use std::io::Read;
use std::time::Duration;

use serde::Deserialize;
use zeroize::{Zeroize, Zeroizing};

use super::normalize_connector_key;
use super::qualification::{GroundingOracle, QualificationConnector, QualificationPlan};
use super::record::ConnectorKeyStatus;
use super::txn::read_connector_key_in_txn;
use crate::consent::{ActionClass, ActionEnvelope, ActorBound, AuthenticatedOwner, GrantBound};
use crate::error::{Error, Result};
use crate::skill_hub::pack_catalog::{
    PackSetupActor, PackSetupAuth, PackSetupCheckRecord, PackSetupConnection,
    PackSetupConnectionState, PackSetupGrantRef, PackSetupKeyRef, PackSetupPermission,
    PackSetupSecret, PackSetupSession, PackSetupView, live_custody_in_txn,
    pin_connection_custody_in_txn,
};
use crate::{EntityId, Vault};

// An agent's `allow`, put to the owner as a decision ask.
mod allow_ask;
mod google_code;
mod grants;
// Microsoft's code exchange and refresh ([MICROSOFT365-OAUTH-EXCHANGE]).
mod microsoft_code;
pub use google_code::GoogleAuthorizationCode;
pub use microsoft_code::MicrosoftAuthorizationCode;
#[cfg(oneiron_test_support)]
pub(crate) use microsoft_code::{exchange_microsoft_code_at, refresh_stored_microsoft_grant_at};
// A built-in channel's isolated probe replies (FIX 710).
mod probe;
// `self.use`'s own checks, cleared inside the door (FIX 7647).
mod sent_check;

pub use allow_ask::{PACK_SETUP_ALLOW_ASK_DOOR, PACK_SETUP_ALLOW_ASK_QUEUE, PackSetupOwnerAsk};

/// The actor class every pack-connection grant is narrowed to.
pub const PACK_CONNECTION_ACTOR_CLASS: &str = "pack-connection";
/// The connection checks [`ProviderConnectionChecks`] runs, by name.
pub const SLACK_AUTH_TEST_CHECK: &str = "slack.auth_test";
pub const LINE_BOT_INFO_CHECK: &str = "line.bot_info";
pub const GMAIL_PROFILE_CHECK: &str = "gmail.profile";
pub const LINKEDIN_SESSION_CHECK: &str = "linkedin.session";
/// Telegram's `getMe` with the bot token: the bot it belongs to.
pub const TELEGRAM_GET_ME_CHECK: &str = "telegram.get_me";
/// Local readiness, not a provider call: the host's browser guest starts a
/// session and closes it. Only a served host with a `[browser]` guest runs it.
pub const BROWSER_SESSION_CHECK: &str = "browser.session";
/// Authenticated JMAP discovery and a domain read on the host's own mail
/// server. Only a served host with a `[native_mail]` server runs it.
pub const NATIVE_MAIL_JMAP_CHECK: &str = "native_mail.jmap";
/// Google's token information for the stored Google grant of the built-in
/// Google pack (FIX 4862; L3-17): the account it belongs to and the scopes
/// it holds.
pub const GOOGLE_TOKEN_CHECK: &str = "google.token";
/// The Microsoft 365 connection's check (L3-17-EXCEL-CONNECTION = B): the
/// Graph profile of the account the stored grant belongs to.
pub const MICROSOFT365_ME_CHECK: &str = "microsoft365.me";
const LINKEDIN_ME_URL: &str = "https://www.linkedin.com/voyager/api/me";
/// Google's OAuth token endpoint: where a stored Gmail refresh token is
/// exchanged for the access token its check presents.
const GOOGLE_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
/// Google's token information endpoint: the account and scopes an access
/// token holds. The token goes in the form body, never in the URL.
const GOOGLE_TOKENINFO_URL: &str = "https://oauth2.googleapis.com/tokeninfo";
// Identity scopes can accompany a Google grant (Gmail's, the Google pack's)
// without adding mail or file access.
const GOOGLE_IDENTITY_SCOPES: [&str; 5] = [
    "openid",
    "email",
    "profile",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
];
const MAX_CHECK_REPLY_BYTES: u64 = 64 * 1024;
const MAX_CHECK_TEXT_BYTES: usize = 512;

/// What a host is asked to prove about one connection. Names only: the host
/// reads the credential through the credential door itself.
#[derive(Debug, Clone, Copy)]
pub struct PackConnectionCheck<'a> {
    pub pack: &'a str,
    pub connection: &'a str,
    /// The declared check name the host maps to its own provider call.
    pub check: &'a str,
    pub auth: PackSetupAuth,
    /// The connection's credential names; the first is the one to present.
    pub secrets: &'a [PackSetupSecret],
    /// The provider scopes of the permissions the owner allowed.
    pub allowed_scopes: &'a [String],
}

/// What the provider said about the credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackConnectionEvidence {
    /// The provider account the credential belongs to: a workspace, an
    /// Official Account, a mailbox.
    pub account: String,
    /// The provider's stable id for that account, when it reports one.
    pub provider_account: Option<String>,
    /// What the provider reports the credential holds. Empty when the
    /// provider reports nothing; then only the account is compared.
    pub scopes: Vec<String>,
    /// A digest of the provider's reply, never the reply.
    pub evidence: String,
}

/// The host's connection check. One read-only provider call: never a send,
/// a post or a connection request, and never a URL the pack chose.
pub trait PackConnectionVerifier {
    /// A refusal is the reason in plain words.
    fn verify(
        &self,
        vault: &Vault,
        check: &PackConnectionCheck<'_>,
    ) -> std::result::Result<PackConnectionEvidence, String>;

    /// The host's isolated probe of `check`, a built-in channel's connection
    /// (FIX 710): the channel's own read-only identity call, each read on a
    /// transport of its own, never a send and never a vault write. `None`
    /// when this host has no client for the channel; the built-in then
    /// qualifies on its checked setup.
    fn builtin_probe<'a>(
        &'a self,
        vault: &'a Vault,
        check: PackConnectionCheck<'a>,
    ) -> Option<Box<dyn QualificationConnector + 'a>> {
        let _ = (vault, check);
        None
    }
}

/// A grant a provider's code exchange made (Google's, Microsoft's), ready
/// for ordinary credential custody: the stored grant's bytes, wiped on drop,
/// never an API reply.
pub struct AuthorizationCodeGrant {
    bytes: Zeroizing<Vec<u8>>,
    refreshable: bool,
}

impl AuthorizationCodeGrant {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Whether the provider issued a refresh token with the access token.
    pub fn has_refresh_token(&self) -> bool {
        self.refreshable
    }
}

/// The read-only provider checks the engine ships for its built-in packs.
/// Each check name maps to one fixed provider endpoint; the credential is
/// read through the credential door for the declared effector and goes
/// only to that endpoint.
pub struct ProviderConnectionChecks {
    client: reqwest::blocking::Client,
}

impl ProviderConnectionChecks {
    /// Every check name this verifier answers.
    pub const CHECKS: [&'static str; 7] = [
        SLACK_AUTH_TEST_CHECK,
        LINE_BOT_INFO_CHECK,
        GMAIL_PROFILE_CHECK,
        LINKEDIN_SESSION_CHECK,
        TELEGRAM_GET_ME_CHECK,
        GOOGLE_TOKEN_CHECK,
        MICROSOFT365_ME_CHECK,
    ];

    /// A bounded HTTPS client: no proxy, no redirects, short timeouts.
    pub fn new() -> Result<Self> {
        let client = reqwest::blocking::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(15))
            .build()
            .map_err(|_| invalid("connection check client unavailable"))?;
        Ok(Self { client })
    }
}

impl ProviderConnectionChecks {
    /// The one read-only provider call `check` names, with `value` as its
    /// credential: the reply's status, its reported scopes and its body,
    /// read within the bound.
    fn send(
        &self,
        check: &str,
        method: &reqwest::Method,
        url: &str,
        value: &[u8],
    ) -> Result<CheckReply> {
        let credential =
            std::str::from_utf8(value).map_err(|_| invalid("the stored credential is not text"))?;
        // Telegram takes its bot token in the method's path, never a header.
        let request = if check == TELEGRAM_GET_ME_CHECK {
            self.client.request(
                method.clone(),
                format!("{url}/bot{}/getMe", credential.trim()),
            )
        } else {
            self.client.request(method.clone(), url)
        };
        let request = if check == LINKEDIN_SESSION_CHECK {
            linkedin_session(request, credential)
        } else if check == TELEGRAM_GET_ME_CHECK {
            request
        } else {
            request.bearer_auth(credential.trim())
        };
        let response = request.send().map_err(|error| {
            Error::InvalidConfig(format!(
                "connection check could not reach the provider: {}",
                error.without_url()
            ))
        })?;
        let status = response.status().as_u16();
        let scopes = response
            .headers()
            .get("x-oauth-scopes")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let mut body = Vec::new();
        response
            .take(MAX_CHECK_REPLY_BYTES + 1)
            .read_to_end(&mut body)
            .map_err(|_| invalid("connection check reply unreadable"))?;
        if body.len() as u64 > MAX_CHECK_REPLY_BYTES {
            return Err(invalid("connection check reply exceeds bound"));
        }
        Ok(CheckReply {
            status,
            scopes,
            body,
        })
    }

    /// The Gmail profile read with the stored grant. A grant that carries a
    /// refresh token and the OAuth client it was issued to (the shape
    /// Google's own tools store) is first exchanged at Google's token
    /// endpoint, here inside the credential door, and the scopes Google's
    /// reply names stand as the scopes the credential holds. A grant that
    /// carries only an access token presents it, and bare text is the access
    /// token. An exchanged access token is presented once and never kept.
    fn send_gmail_profile(
        &self,
        method: &reqwest::Method,
        url: &str,
        value: &[u8],
    ) -> Result<CheckReply> {
        let text = std::str::from_utf8(value)
            .map_err(|_| invalid("the stored credential is not text"))?
            .trim();
        if !text.starts_with('{') {
            return self.send(GMAIL_PROFILE_CHECK, method, url, value);
        }
        let grant: StoredGoogleGrant = serde_json::from_str(text)
            .map_err(|_| invalid("the stored Gmail grant is not JSON"))?;
        if let Some((refresh_token, client_id)) = grant.refresh_pair()? {
            let (access_token, granted) = self.exchange_google_refresh(
                refresh_token,
                client_id,
                present(&grant.client_secret),
            )?;
            let mut reply = self.send(GMAIL_PROFILE_CHECK, method, url, access_token.as_bytes())?;
            reply.scopes = granted.or(reply.scopes);
            return Ok(reply);
        }
        let access_token = present(&grant.access_token).ok_or_else(|| {
            invalid(
                "the stored Gmail grant holds neither an access token nor a refresh token with its OAuth client",
            )
        })?;
        self.send(GMAIL_PROFILE_CHECK, method, url, access_token.as_bytes())
    }

    /// The Microsoft Graph profile read with the stored grant. A grant the
    /// Microsoft code exchange stored (a refresh token, its OAuth client and
    /// its tenant) is first refreshed at its tenant's token endpoint, here
    /// inside the credential door; any other grant presents its access token
    /// as it is: bare text, or a JSON grant's `access_token`. A Microsoft
    /// grant never goes to Google's token endpoint.
    fn send_microsoft365_me(
        &self,
        method: &reqwest::Method,
        url: &str,
        value: &[u8],
    ) -> Result<CheckReply> {
        if let Some(fresh) = Self::refresh_stored_microsoft_grant(&self.client, value)? {
            return self.send(MICROSOFT365_ME_CHECK, method, url, fresh.as_bytes());
        }
        let text = std::str::from_utf8(value)
            .map_err(|_| invalid("the stored credential is not text"))?
            .trim();
        if !text.starts_with('{') {
            return self.send(MICROSOFT365_ME_CHECK, method, url, value);
        }
        let grant: StoredAccessGrant = serde_json::from_str(text)
            .map_err(|_| invalid("the stored Microsoft grant is not JSON"))?;
        let access_token = present(&grant.access_token)
            .ok_or_else(|| invalid("the stored Microsoft grant holds no access token"))?;
        self.send(MICROSOFT365_ME_CHECK, method, url, access_token.as_bytes())
    }

    /// Google's token information for the stored Google grant (FIX 4862):
    /// the grant's access token, refreshed first when the grant carries a
    /// refresh token and its OAuth client, goes in the form body of one POST
    /// to `url`. The scopes Google reports for the token stand as the scopes
    /// the credential holds. An exchanged access token is presented once and
    /// never kept.
    fn send_google_token(&self, url: &str, value: &[u8]) -> Result<CheckReply> {
        let (access_token, granted) = self.stored_google_access_token(value)?;
        let response = self
            .client
            .post(url)
            .form(&[("access_token", access_token.as_str())])
            .send()
            .map_err(|error| {
                Error::InvalidConfig(format!(
                    "connection check could not reach Google's token information: {}",
                    error.without_url()
                ))
            })?;
        let status = response.status().as_u16();
        let mut body = Vec::new();
        response
            .take(MAX_CHECK_REPLY_BYTES + 1)
            .read_to_end(&mut body)
            .map_err(|_| invalid("connection check reply unreadable"))?;
        if body.len() as u64 > MAX_CHECK_REPLY_BYTES {
            return Err(invalid("connection check reply exceeds bound"));
        }
        let reported = serde_json::from_slice::<serde_json::Value>(&body)
            .ok()
            .and_then(|reply| reply_field(&reply, "scope").map(str::to_owned));
        Ok(CheckReply {
            status,
            scopes: reported.or(granted),
            body,
        })
    }

    /// The access token a stored Google grant presents, beside the scopes
    /// Google granted it when it was just refreshed: a fresh one when the
    /// grant carries a refresh token and its OAuth client, else its stored
    /// access token, else the bare text.
    fn stored_google_access_token(
        &self,
        value: &[u8],
    ) -> Result<(Zeroizing<String>, Option<String>)> {
        let text = std::str::from_utf8(value)
            .map_err(|_| invalid("the stored credential is not text"))?
            .trim();
        if !text.starts_with('{') {
            return Ok((Zeroizing::new(text.to_owned()), None));
        }
        let grant: StoredGoogleGrant = serde_json::from_str(text)
            .map_err(|_| invalid("the stored Google grant is not JSON"))?;
        if let Some((refresh_token, client_id)) = grant.refresh_pair()? {
            return self.exchange_google_refresh(
                refresh_token,
                client_id,
                present(&grant.client_secret),
            );
        }
        let access_token = present(&grant.access_token).ok_or_else(|| {
            invalid(
                "the stored Google grant holds neither an access token nor a refresh token with its OAuth client",
            )
        })?;
        Ok((Zeroizing::new(access_token.to_owned()), None))
    }

    /// A fresh access token for a stored grant that carries its OAuth client.
    /// Called only inside an admitted credential door; nothing is persisted.
    pub(crate) fn refresh_stored_google_grant(
        client: &reqwest::blocking::Client,
        value: &[u8],
    ) -> Result<Option<Zeroizing<String>>> {
        let text = std::str::from_utf8(value)
            .map_err(|_| invalid("the stored credential is not text"))?
            .trim();
        if !text.starts_with('{') {
            return Ok(None);
        }
        let grant: StoredGoogleGrant = serde_json::from_str(text)
            .map_err(|_| invalid("the stored Gmail grant is not JSON"))?;
        let Some((refresh_token, client_id)) = grant.refresh_pair()? else {
            return Ok(None);
        };
        let checks = Self {
            client: client.clone(),
        };
        let (token, _) = checks.exchange_google_refresh(
            refresh_token,
            client_id,
            present(&grant.client_secret),
        )?;
        Ok(Some(token))
    }

    /// Exchanges a stored refresh token for a fresh access token at Google's
    /// token endpoint: the token, held only for the call that presents it,
    /// and the scopes Google granted it, as its reply names them.
    fn exchange_google_refresh(
        &self,
        refresh_token: &str,
        client_id: &str,
        client_secret: Option<&str>,
    ) -> Result<(Zeroizing<String>, Option<String>)> {
        let mut form = vec![
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", client_id),
        ];
        if let Some(secret) = client_secret {
            form.push(("client_secret", secret));
        }
        let response = self
            .client
            .post(GOOGLE_TOKEN_URL)
            .form(&form)
            .send()
            .map_err(|error| {
                Error::InvalidConfig(format!(
                    "connection check could not reach Google's token endpoint: {}",
                    error.without_url()
                ))
            })?;
        let status = response.status().as_u16();
        let mut body = Zeroizing::new(Vec::new());
        response
            .take(MAX_CHECK_REPLY_BYTES + 1)
            .read_to_end(&mut body)
            .map_err(|_| invalid("Google's token reply is unreadable"))?;
        if body.len() as u64 > MAX_CHECK_REPLY_BYTES {
            return Err(invalid("Google's token reply exceeds its bound"));
        }
        let mut reply: GoogleTokenReply = serde_json::from_slice(&body)
            .map_err(|_| invalid("Google's token reply is not JSON"))?;
        match reply.access_token.take().map(Zeroizing::new) {
            Some(token) if (200..300).contains(&status) && !token.trim().is_empty() => {
                Ok((token, reply.scope.take()))
            }
            _ => Err(Error::InvalidConfig(format!(
                "pack setup: Google refused the stored refresh token (HTTP {status}): {}",
                bounded(reply.error.as_deref().unwrap_or("no reason given"))
            ))),
        }
    }
}

/// A stored Google grant, read inside the credential door and wiped on drop.
#[derive(Deserialize)]
struct StoredGoogleGrant {
    #[serde(default)]
    access_token: Option<String>,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    client_secret: Option<String>,
    /// Named only by a Microsoft grant ([`MicrosoftAuthorizationCode`]).
    #[serde(default)]
    tenant: Option<String>,
}

impl StoredGoogleGrant {
    /// The refresh token and the OAuth client it was issued to, when the
    /// grant carries both. A grant that names a Microsoft tenant is refused
    /// whole: its refresh token and client secret never go to Google.
    fn refresh_pair(&self) -> Result<Option<(&str, &str)>> {
        if present(&self.tenant).is_some() {
            return Err(invalid(
                "the stored grant is a Microsoft grant; it is never sent to Google",
            ));
        }
        Ok(present(&self.refresh_token).zip(present(&self.client_id)))
    }
}

impl Drop for StoredGoogleGrant {
    fn drop(&mut self) {
        self.access_token.zeroize();
        self.refresh_token.zeroize();
        self.client_secret.zeroize();
    }
}

/// A stored grant whose access token is presented as it is, read inside the
/// credential door and wiped on drop. Its other fields are skipped unread.
#[derive(Deserialize)]
struct StoredAccessGrant {
    #[serde(default)]
    access_token: Option<String>,
}

impl Drop for StoredAccessGrant {
    fn drop(&mut self) {
        self.access_token.zeroize();
    }
}

/// Google's token reply: the fresh access token, wiped on drop, and the
/// space-separated scopes it holds.
#[derive(Deserialize)]
struct GoogleTokenReply {
    #[serde(default)]
    access_token: Option<String>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    error: Option<String>,
}

impl Drop for GoogleTokenReply {
    fn drop(&mut self) {
        self.access_token.zeroize();
    }
}

#[cfg(oneiron_test_support)]
impl ProviderConnectionChecks {
    /// The checks on `client`: a test's own transport.
    pub(crate) fn on_client(client: reqwest::blocking::Client) -> Self {
        Self { client }
    }

    /// The HTTP status of the `microsoft365.me` check's provider call with
    /// `value` as the stored grant.
    pub(crate) fn microsoft365_me_status(&self, value: &[u8]) -> Result<u16> {
        let (method, url) = provider_call(MICROSOFT365_ME_CHECK).map_err(Error::InvalidConfig)?;
        self.send_microsoft365_me(&method, url, value)
            .map(|reply| reply.status)
    }
}

/// A stored field's value, trimmed, when it holds one.
fn present(field: &Option<String>) -> Option<&str> {
    field
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

impl PackConnectionVerifier for ProviderConnectionChecks {
    fn verify(
        &self,
        vault: &Vault,
        check: &PackConnectionCheck<'_>,
    ) -> std::result::Result<PackConnectionEvidence, String> {
        let (method, url) = provider_call(check.check)?;
        let secret = check
            .secrets
            .first()
            .ok_or_else(|| "the connection names no credential to check".to_owned())?;
        let mut reply = None;
        vault
            .inject_secret_at_door(&secret.name, &secret.effector, &mut |value: &[u8]| {
                reply = Some(match check.check {
                    GMAIL_PROFILE_CHECK => self.send_gmail_profile(&method, url, value)?,
                    GOOGLE_TOKEN_CHECK => self.send_google_token(url, value)?,
                    MICROSOFT365_ME_CHECK => self.send_microsoft365_me(&method, url, value)?,
                    _ => self.send(check.check, &method, url, value)?,
                });
                Ok(())
            })
            .map_err(|error| error.to_string())?;
        let reply = reply.ok_or_else(|| "the check did not run".to_owned())?;
        evidence_of(check.check, reply)
    }
}

/// What one provider call answered, before it is read.
struct CheckReply {
    status: u16,
    scopes: Option<String>,
    body: Vec<u8>,
}

/// The provider endpoint a check name maps to; why this host runs none for
/// any other name.
fn provider_call(check: &str) -> std::result::Result<(reqwest::Method, &'static str), String> {
    Ok(match check {
        SLACK_AUTH_TEST_CHECK => (reqwest::Method::POST, "https://slack.com/api/auth.test"),
        LINE_BOT_INFO_CHECK => (reqwest::Method::GET, "https://api.line.me/v2/bot/info"),
        GMAIL_PROFILE_CHECK => (
            reqwest::Method::GET,
            "https://gmail.googleapis.com/gmail/v1/users/me/profile",
        ),
        LINKEDIN_SESSION_CHECK => (reqwest::Method::GET, LINKEDIN_ME_URL),
        TELEGRAM_GET_ME_CHECK => (reqwest::Method::GET, "https://api.telegram.org"),
        GOOGLE_TOKEN_CHECK => (reqwest::Method::POST, GOOGLE_TOKENINFO_URL),
        MICROSOFT365_ME_CHECK => (reqwest::Method::GET, "https://graph.microsoft.com/v1.0/me"),
        BROWSER_SESSION_CHECK => {
            return Err(
                "this host runs no browser guest; a served host with a [browser] guest checks it"
                    .to_owned(),
            );
        }
        NATIVE_MAIL_JMAP_CHECK => {
            return Err(
                "this host names no mail server; a served host with a [native_mail] server checks it"
                    .to_owned(),
            );
        }
        other => return Err(format!("this host has no connection check named {other}")),
    })
}

/// The provider's reply to `check`, read as the evidence a check answers.
fn evidence_of(
    check: &str,
    reply: CheckReply,
) -> std::result::Result<PackConnectionEvidence, String> {
    let CheckReply {
        status,
        scopes,
        body,
    } = reply;
    let evidence = blake3::hash(&body).to_hex().to_string();
    if !(200..300).contains(&status) {
        return Err(format!(
            "the provider refused the credential (HTTP {status})"
        ));
    }
    let reply: serde_json::Value =
        serde_json::from_slice(&body).map_err(|_| "the provider's reply is not JSON".to_owned())?;
    let field = |name| reply_field(&reply, name);
    let account = match check {
        SLACK_AUTH_TEST_CHECK => {
            if reply.get("ok").and_then(serde_json::Value::as_bool) != Some(true) {
                return Err(format!(
                    "Slack refused the credential: {}",
                    field("error").unwrap_or("no reason given")
                ));
            }
            format!(
                "{} ({}) as {}",
                field("team").unwrap_or("workspace"),
                field("team_id").unwrap_or("unknown"),
                field("user").unwrap_or("the app")
            )
        }
        LINE_BOT_INFO_CHECK => format!(
            "{} ({})",
            field("displayName").unwrap_or("Official Account"),
            field("basicId").unwrap_or("unknown")
        ),
        TELEGRAM_GET_ME_CHECK => {
            let bot = reply
                .get("result")
                .filter(|_| reply.get("ok").and_then(serde_json::Value::as_bool) == Some(true))
                .ok_or_else(|| "Telegram refused the bot token".to_owned())?;
            format!(
                "{} (@{})",
                reply_field(bot, "first_name").unwrap_or("bot"),
                reply_field(bot, "username").unwrap_or("unknown")
            )
        }
        LINKEDIN_SESSION_CHECK => {
            let profile = |name| {
                reply
                    .get("miniProfile")
                    .and_then(|profile| reply_field(profile, name))
            };
            profile("publicIdentifier").map_or_else(String::new, |handle| {
                let name = [profile("firstName"), profile("lastName")]
                    .into_iter()
                    .flatten()
                    .collect::<Vec<_>>()
                    .join(" ");
                let name = if name.trim().is_empty() {
                    "LinkedIn member"
                } else {
                    name.trim()
                };
                format!("{name} ({handle})")
            })
        }
        // Google names the account by email when the grant holds an
        // identity scope, and by its stable subject id always.
        GOOGLE_TOKEN_CHECK => field("email")
            .or_else(|| field("sub"))
            .unwrap_or_default()
            .to_owned(),
        // Graph names a work account by its sign-in name, its mail address
        // when it has one.
        MICROSOFT365_ME_CHECK => field("userPrincipalName")
            .or_else(|| field("mail"))
            .unwrap_or_default()
            .to_owned(),
        _ => field("emailAddress").unwrap_or_default().to_owned(),
    };
    // The provider's stable id a served host binds inbound events to:
    // the workspace a Slack event names, the bot a LINE webhook is for.
    // The bot's numeric id, the one a Telegram update's bot is named by.
    let telegram_bot = reply
        .pointer("/result/id")
        .and_then(serde_json::Value::as_i64)
        .map(|id| id.to_string());
    let provider_account = match check {
        TELEGRAM_GET_ME_CHECK => telegram_bot.as_deref(),
        SLACK_AUTH_TEST_CHECK => field("team_id"),
        LINE_BOT_INFO_CHECK => field("userId"),
        LINKEDIN_SESSION_CHECK => reply
            .get("miniProfile")
            .and_then(|profile| reply_field(profile, "publicIdentifier")),
        GOOGLE_TOKEN_CHECK => field("sub"),
        MICROSOFT365_ME_CHECK => field("id"),
        _ => field("emailAddress"),
    }
    .map(str::to_owned);
    Ok(PackConnectionEvidence {
        account,
        provider_account,
        // A header lists scopes comma-separated; an OAuth token reply,
        // space-separated.
        scopes: scopes
            .map(|header| {
                header
                    .split(|separator: char| separator == ',' || separator.is_whitespace())
                    .filter(|scope| !scope.is_empty())
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default(),
        evidence,
    })
}

/// One allowed permission's standing bound: the pack, as a pack-connection
/// actor, may do the permission's grant class, on this connection of this
/// exact source, with a receipt on every use.
fn connection_bound(
    pack: &str,
    content_hash: &str,
    connection: &str,
    permission: &PackSetupPermission,
) -> Result<GrantBound> {
    let actor =
        ActorBound::new(format!("pack:{pack}"))?.with_actor_class(PACK_CONNECTION_ACTOR_CLASS)?;
    let class = ActionClass::new(
        permission
            .grant
            .clone()
            .unwrap_or_else(|| format!("pack.{connection}.{}", permission.id)),
    )?;
    let envelope = ActionEnvelope::new([
        format!("connection:{connection}"),
        format!("permission:{}", permission.id),
        format!("source:{content_hash}"),
    ])?
    .with_receipt_required(true);
    GrantBound::action(actor, class, envelope)
}

/// The provider's word against the owner's: an account must be named, and
/// reported scopes must be allowed, apart from undeclared Google identity
/// scopes accompanying a Gmail or Google pack grant. Declared-but-declined scopes
/// still fail.
fn judge_evidence(
    declared: &PackSetupConnection,
    allowed: &[String],
    evidence: PackConnectionEvidence,
    basis: String,
    at: u64,
) -> PackSetupCheckRecord {
    let held: BTreeSet<&str> = evidence.scopes.iter().map(String::as_str).collect();
    let explained: BTreeSet<&str> = declared
        .permissions
        .iter()
        .filter_map(|permission| permission.scope.as_deref())
        .collect();
    let reason = if evidence.account.trim().is_empty() {
        Some("the provider named no account for this credential".to_owned())
    } else if held.is_empty() {
        None
    } else {
        let missing: Vec<&str> = allowed
            .iter()
            .map(String::as_str)
            .filter(|scope| !held.contains(scope))
            .collect();
        let unexplained: Vec<&str> = held
            .iter()
            .copied()
            .filter(|scope| {
                !explained.contains(scope)
                    && !((declared.verify == GMAIL_PROFILE_CHECK
                        || declared.verify == GOOGLE_TOKEN_CHECK)
                        && GOOGLE_IDENTITY_SCOPES.contains(scope))
            })
            .collect();
        let declined: Vec<&str> = held
            .iter()
            .copied()
            .filter(|scope| explained.contains(scope) && !allowed.iter().any(|a| a == scope))
            .collect();
        if !missing.is_empty() {
            Some(format!("the provider did not grant {}", missing.join(", ")))
        } else if !unexplained.is_empty() {
            Some(format!(
                "the credential holds permissions this pack never explained: {}",
                unexplained.join(", ")
            ))
        } else if !declined.is_empty() {
            Some(format!(
                "the credential holds permissions you declined: {}",
                declined.join(", ")
            ))
        } else {
            None
        }
    };
    PackSetupCheckRecord {
        connection: declared.id.clone(),
        verified: reason.is_none(),
        account: Some(bounded(&evidence.account)),
        provider_account: evidence.provider_account.as_deref().map(bounded),
        evidence: Some(evidence.evidence),
        reason: reason.map(|reason| bounded(&reason)),
        basis,
        checked_at: at,
    }
}

/// LinkedIn's signed-in member read: the session goes as its `li_at` cookie,
/// with a CSRF token this check picks and echoes as `JSESSIONID`. It reads
/// the member only; it never sends a message or a request.
fn linkedin_session(
    request: reqwest::blocking::RequestBuilder,
    cookie: &str,
) -> reqwest::blocking::RequestBuilder {
    let session = cookie.trim();
    let session = session.strip_prefix("li_at=").unwrap_or(session);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_nanos() % 10_u128.pow(19));
    let csrf = format!("ajax:{nanos:019}");
    request
        .header(
            reqwest::header::COOKIE,
            format!("li_at={session}; JSESSIONID=\"{csrf}\""),
        )
        .header("csrf-token", csrf)
        .header("x-restli-protocol-version", "2.0.0")
        .header(reqwest::header::ACCEPT, "application/json")
}

fn reply_field<'a>(reply: &'a serde_json::Value, name: &str) -> Option<&'a str> {
    reply.get(name).and_then(serde_json::Value::as_str)
}

fn declared_connection<'a>(
    connections: &'a [PackSetupConnection],
    id: &str,
) -> Result<&'a PackSetupConnection> {
    connections
        .iter()
        .find(|connection| connection.id == id)
        .ok_or_else(|| invalid("the pack declares no such connection"))
}

fn check_allowed(connection: &PackSetupConnection, allowed: &[String]) -> Result<()> {
    if allowed.iter().any(|id| connection.permission(id).is_none()) {
        return Err(invalid("the connection asks for no such permission"));
    }
    if connection
        .required()
        .any(|permission| !allowed.contains(&permission.id))
    {
        return Err(invalid(
            "the connection cannot work without a permission it requires; allow it or leave the connection unset",
        ));
    }
    Ok(())
}

fn frame(hasher: &mut blake3::Hasher, part: &[u8]) {
    hasher.update(&(part.len() as u64).to_be_bytes());
    hasher.update(part);
}

fn bounded(text: &str) -> String {
    let mut cut = text.len().min(MAX_CHECK_TEXT_BYTES);
    while !text.is_char_boundary(cut) {
        cut -= 1;
    }
    text[..cut].to_owned()
}

fn invalid(reason: &'static str) -> Error {
    Error::InvalidConfig(format!("pack setup: {reason}"))
}
