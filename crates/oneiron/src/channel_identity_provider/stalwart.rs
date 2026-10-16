//! Stalwart 0.16 JMAP driver for the native mail pack.
//!
//! Each client belongs to one owning account and one Stalwart instance, in
//! either run mode. Domain creation, DNS and DKIM custody remain host-owned.
//! The host supplies authorization in memory; it never enters vault records.

mod inbox;
mod reputation;
mod send;

pub use inbox::{StalwartInboxCursor, StalwartInboxOutcome, StalwartQuarantine};
pub use reputation::{
    NativeMailReputationReport, NativeMailReputationUpdate, NativeMailSignalSource,
    NativeMailWarmupPolicy,
};
pub use send::{NATIVE_MAIL_MAX_MESSAGE_BYTES, NativeMailMessage, StalwartSendSink};

use std::collections::BTreeMap;
use std::io::Read;
use std::sync::Arc;

use reqwest::blocking::{Client, Response};
use reqwest::header::{AUTHORIZATION, HeaderValue};
use serde_json::{Value, json};

use super::EmailProviderInbound;
use super::native_mail::{NativeMailHost, NativeMailRunMode};
use super::shared_validate::{normalize_domain, validate_provision_intent};
use crate::channel_identity::ChannelIdentityFulfillment;
use crate::channel_identity_lifecycle::ProvisionIntent;
use crate::{EntityId, Error, Result};

/// The registry schema used here is the 0.16 JMAP API, not the retired REST API.
pub const STALWART_JMAP_SCHEMA_VERSION: &str = "0.16.0";
const CORE: &str = "urn:ietf:params:jmap:core";
const MAIL: &str = "urn:ietf:params:jmap:mail";
const SUBMISSION: &str = "urn:ietf:params:jmap:submission";
const STALWART: &str = "urn:stalwart:jmap";
const MAX_RESPONSE_BYTES: u64 = 16 * 1024 * 1024;

/// Placement of one already-configured, per-owner MTA instance. Pooled and
/// customer-BYO domains both arrive as an exact domain and its registry id.
#[derive(Debug, Clone)]
pub struct StalwartConfig {
    session_url: reqwest::Url,
    instance_ref: String,
    owner_ref: String,
    domain: String,
    domain_id: String,
    mode: NativeMailRunMode,
}

impl StalwartConfig {
    pub fn new(
        session_url: &str,
        instance_ref: impl Into<String>,
        owner_ref: impl Into<String>,
        domain: &str,
        domain_id: impl Into<String>,
        mode: NativeMailRunMode,
    ) -> Result<Self> {
        let session_url = reqwest::Url::parse(session_url)
            .map_err(|_| invalid("invalid Stalwart session URL"))?;
        let loopback = matches!(
            session_url.host_str(),
            Some("localhost" | "127.0.0.1" | "[::1]" | "::1")
        );
        if !(session_url.scheme() == "https" || session_url.scheme() == "http" && loopback)
            || !session_url.username().is_empty()
            || session_url.password().is_some()
            || session_url.fragment().is_some()
        {
            return Err(invalid("Stalwart requires HTTPS or a loopback instance"));
        }
        let config = Self {
            session_url,
            instance_ref: instance_ref.into(),
            owner_ref: owner_ref.into(),
            domain: normalize_domain(domain)?,
            domain_id: domain_id.into(),
            mode,
        };
        for value in [&config.instance_ref, &config.owner_ref, &config.domain_id] {
            if value.trim().is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
                return Err(invalid("invalid Stalwart instance binding"));
            }
        }
        Ok(config)
    }

    pub fn domain(&self) -> &str {
        &self.domain
    }
    pub fn instance_ref(&self) -> &str {
        &self.instance_ref
    }
    pub fn owner_ref(&self) -> &str {
        &self.owner_ref
    }
    pub fn run_mode(&self) -> NativeMailRunMode {
        self.mode
    }
}

/// Optional cloud ingress verifier. Authentication is over the original bytes,
/// before JSON parsing. The verifier must quarantine the raw mail and return
/// its payload reference. Self-run hosts may use authenticated JMAP polling only.
pub trait StalwartWebhookVerifier: Send + Sync {
    fn verify(
        &self,
        body: &[u8],
        headers: &BTreeMap<String, String>,
    ) -> Result<EmailProviderInbound>;
}

/// Host-side HTTP client. Clones retain the same instance and owner binding.
#[derive(Clone)]
pub struct StalwartClient {
    config: StalwartConfig,
    http: Client,
    authorization: HeaderValue,
    api_url: reqwest::Url,
    download_url: String,
    webhook_verifier: Option<Arc<dyn StalwartWebhookVerifier>>,
}

#[derive(Debug, Clone)]
pub(super) struct StalwartMailbox {
    identity_ref: EntityId,
    address: String,
    account_id: String,
}

impl StalwartClient {
    /// Discover JMAP and verify that the configured domain belongs to this
    /// instance. The authorization header is sensitive and is never debugged.
    pub fn connect(config: StalwartConfig, mut authorization: HeaderValue) -> Result<Self> {
        authorization.set_sensitive(true);
        let http = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| invalid("could not create Stalwart HTTP client"))?;
        let response = http
            .get(config.session_url.clone())
            .header(AUTHORIZATION, authorization.clone())
            .send()
            .map_err(|_| invalid("Stalwart session request failed"))?;
        let session: Value = serde_json::from_slice(&read_response(response)?)
            .map_err(|_| invalid("invalid Stalwart JMAP session"))?;
        for capability in [CORE, MAIL, SUBMISSION, STALWART] {
            if session
                .get("capabilities")
                .and_then(|caps| caps.get(capability))
                .is_none()
            {
                return Err(invalid(
                    "Stalwart session lacks native-mail JMAP capabilities",
                ));
            }
        }
        let api_url = config
            .session_url
            .join(string(&session, "apiUrl")?)
            .map_err(|_| invalid("invalid Stalwart API URL"))?;
        require_same_origin(&config.session_url, &api_url)?;
        let download_url = string(&session, "downloadUrl")?.to_owned();
        let client = Self {
            config,
            http,
            authorization,
            api_url,
            download_url,
            webhook_verifier: None,
        };
        client.check_domain()?;
        Ok(client)
    }

    pub fn config(&self) -> &StalwartConfig {
        &self.config
    }

    pub fn with_webhook_verifier(mut self, verifier: Arc<dyn StalwartWebhookVerifier>) -> Self {
        self.webhook_verifier = Some(verifier);
        self
    }

    pub fn address_for_identity(&self, identity_ref: EntityId) -> String {
        format!(
            "{}@{}",
            Self::account_name(identity_ref),
            self.config.domain
        )
    }

    fn account_name(identity_ref: EntityId) -> String {
        format!("mail-{}", identity_ref.to_hex())
    }

    /// A read-only readiness check; it sends no message and changes no DNS.
    pub fn check_domain(&self) -> Result<()> {
        let reply = self.call(
            "x:Domain/get",
            json!({
                "accountId": "0", "ids": [&self.config.domain_id],
                "properties": ["id", "name", "isEnabled", "catchAllAddress", "memberTenantId"]
            }),
        )?;
        let domains = array(&reply, "list")?;
        if domains.len() != 1
            || domains[0].get("name").and_then(Value::as_str) != Some(self.config.domain.as_str())
            || domains[0].get("isEnabled").and_then(Value::as_bool) != Some(true)
            || domains[0]
                .get("catchAllAddress")
                .is_some_and(|v| !v.is_null())
            || domains[0]
                .get("memberTenantId")
                .is_some_and(|v| !v.is_null())
        {
            return Err(invalid(
                "Stalwart domain must be enabled, exact, non-catch-all and instance-isolated",
            ));
        }
        Ok(())
    }

    pub(super) fn mailbox(&self, identity_ref: EntityId) -> Result<StalwartMailbox> {
        let address = self.address_for_identity(identity_ref);
        let name = Self::account_name(identity_ref);
        let query = self.call("x:Account/query", json!({
            "accountId": "0", "filter": {"name": &name, "domainId": &self.config.domain_id}, "limit": 2
        }))?;
        let ids = array(&query, "ids")?;
        if ids.len() != 1 {
            return Err(invalid("native mailbox is absent or ambiguous"));
        }
        let account_id = ids[0]
            .as_str()
            .ok_or_else(|| invalid("invalid Stalwart account id"))?
            .to_owned();
        let reply = self.call(
            "x:Account/get",
            json!({
                "accountId": "0", "ids": [&account_id],
                "properties": ["id", "name", "domainId", "@type", "memberTenantId"]
            }),
        )?;
        let accounts = array(&reply, "list")?;
        if accounts.len() != 1
            || accounts[0].get("name").and_then(Value::as_str) != Some(name.as_str())
            || accounts[0].get("domainId").and_then(Value::as_str)
                != Some(self.config.domain_id.as_str())
            || accounts[0].get("@type").and_then(Value::as_str) != Some("User")
            || accounts[0]
                .get("memberTenantId")
                .is_some_and(|v| !v.is_null())
        {
            return Err(invalid(
                "Stalwart account escaped the native mailbox binding",
            ));
        }
        Ok(StalwartMailbox {
            identity_ref,
            address,
            account_id,
        })
    }

    fn provision_mailbox(&self, identity_ref: EntityId) -> Result<StalwartMailbox> {
        self.check_domain()?;
        // Stalwart stores the local part in name and the domain separately.
        let name = Self::account_name(identity_ref);
        let query = self.call("x:Account/query", json!({
            "accountId": "0", "filter": {"name": &name, "domainId": &self.config.domain_id}, "limit": 2
        }))?;
        if array(&query, "ids")?.is_empty() {
            // No mailbox password is needed: the per-instance host credential
            // impersonates this account; the agent never receives a credential.
            let reply = self.call(
                "x:Account/set",
                json!({
                    "accountId": "0", "create": {"mailbox": {
                        "@type": "User", "name": &name, "domainId": &self.config.domain_id
                    }}
                }),
            )?;
            if reply
                .pointer("/created/mailbox/id")
                .and_then(Value::as_str)
                .is_none()
            {
                return Err(invalid("Stalwart refused native mailbox provisioning"));
            }
        }
        self.mailbox(identity_ref)
    }

    pub(super) fn raw_call(&self, method: &str, arguments: Value) -> Result<Value> {
        let response = self
            .http
            .post(self.api_url.clone())
            .header(AUTHORIZATION, self.authorization.clone())
            .json(&json!({
                "using": [CORE, MAIL, SUBMISSION, STALWART],
                "methodCalls": [[method, arguments, "mail"]]
            }))
            .send()
            .map_err(|_| invalid("Stalwart JMAP request failed"))?;
        serde_json::from_slice(&read_response(response)?)
            .map_err(|_| invalid("invalid Stalwart JMAP response"))
    }

    pub(super) fn call(&self, method: &str, arguments: Value) -> Result<Value> {
        method_result(&self.raw_call(method, arguments)?, method).cloned()
    }

    pub(super) fn download_blob(&self, account_id: &str, blob_id: &str) -> Result<Vec<u8>> {
        let encode = |value: &str| -> String {
            value.bytes().fold(String::new(), |mut encoded, byte| {
                if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
                    encoded.push(char::from(byte));
                } else {
                    encoded.push_str(&format!("%{byte:02X}"));
                }
                encoded
            })
        };
        let path = self
            .download_url
            .replace("{accountId}", &encode(account_id))
            .replace("{blobId}", &encode(blob_id))
            .replace("{type}", "message%2Frfc822")
            .replace("{name}", "message.eml");
        let url = self
            .config
            .session_url
            .join(&path)
            .map_err(|_| invalid("invalid Stalwart download URL"))?;
        require_same_origin(&self.config.session_url, &url)?;
        let response = self
            .http
            .get(url)
            .header(AUTHORIZATION, self.authorization.clone())
            .send()
            .map_err(|_| invalid("Stalwart message download failed"))?;
        read_response(response)
    }

    pub(super) fn mailboxes(&self, mailbox: &StalwartMailbox) -> Result<Vec<Value>> {
        let reply = self.call(
            "Mailbox/get",
            json!({
                "accountId": &mailbox.account_id, "properties": ["id", "role"]
            }),
        )?;
        Ok(array(&reply, "list")?.clone())
    }
}

impl NativeMailHost for StalwartClient {
    fn provision(&self, intent: &ProvisionIntent, mode: NativeMailRunMode) -> Result<String> {
        if mode != self.config.mode {
            return Err(invalid(
                "native mail run mode differs from the Stalwart instance",
            ));
        }
        validate_provision_intent(
            intent,
            "email",
            &self.address_for_identity(intent.identity_id),
            ChannelIdentityFulfillment::Api,
        )?;
        let mailbox = self.provision_mailbox(intent.identity_id)?;
        Ok(format!(
            "stalwart:{}:{}",
            self.config.instance_ref, mailbox.account_id
        ))
    }

    fn verify_webhook(
        &self,
        body: &[u8],
        headers: &BTreeMap<String, String>,
    ) -> Result<EmailProviderInbound> {
        let mail = self
            .webhook_verifier
            .as_ref()
            .ok_or_else(|| {
                invalid("native mail webhook verifier is not configured; use JMAP polling")
            })?
            .verify(body, headers)?;
        if mail.payload_ref.as_deref().is_none_or(str::is_empty) {
            return Err(invalid(
                "verified native mail webhook lacks a quarantine reference",
            ));
        }
        Ok(mail)
    }
}

pub(super) fn method_result<'a>(reply: &'a Value, method: &str) -> Result<&'a Value> {
    let responses = array(reply, "methodResponses")?;
    let response = responses
        .iter()
        .find(|r| r.get(2).and_then(Value::as_str) == Some("mail"))
        .ok_or_else(|| invalid("Stalwart omitted the JMAP method response"))?;
    if response.get(0).and_then(Value::as_str) != Some(method) {
        return Err(invalid("Stalwart rejected the JMAP method"));
    }
    response
        .get(1)
        .filter(|v| v.is_object())
        .ok_or_else(|| invalid("invalid Stalwart method result"))
}

pub(super) fn array<'a>(value: &'a Value, key: &str) -> Result<&'a Vec<Value>> {
    value
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("Stalwart response omitted an array"))
}

pub(super) fn string<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| invalid("Stalwart response omitted an identifier"))
}

fn require_same_origin(base: &reqwest::Url, url: &reqwest::Url) -> Result<()> {
    if base.origin() != url.origin() || !url.username().is_empty() || url.password().is_some() {
        return Err(invalid("Stalwart session URL escaped its instance"));
    }
    Ok(())
}

fn read_response(response: Response) -> Result<Vec<u8>> {
    if !response.status().is_success() {
        return Err(invalid("Stalwart HTTP request was refused"));
    }
    let mut bytes = Vec::new();
    response
        .take(MAX_RESPONSE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_RESPONSE_BYTES {
        return Err(invalid(
            "Stalwart response exceeds the native mail byte limit",
        ));
    }
    Ok(bytes)
}

pub(super) fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(reason.into())
}
