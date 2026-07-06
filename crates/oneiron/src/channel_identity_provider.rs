//! Provider-adapter seam for ChannelIdentity fulfillment (OF-347 CID-3).
//!
//! The engine emits CID-2 lifecycle intents through the ExternalEffect door.
//! Host-side adapters consume those intents, fulfill provider work, and report
//! the resulting state transition back through the CID-2 fulfillment path.

use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::channel_identity::{
    ChannelIdentity, ChannelIdentityBinding, ChannelIdentityFulfillment, ChannelIdentityShape,
};
use crate::channel_identity_lifecycle::{
    ChannelIdentityFulfillmentInput, ChannelIdentityLifecycleActor, ChannelIdentityLifecycleVerb,
    ProvisionIntent,
};
use crate::error::{Error, Result};
use crate::surface_event::{InboundSurfaceEventInput, SurfaceCounterpartyStamp};
use crate::types::{EntityId, bytes_to_hex_lower};

/// Stable provider adapter contract version.
pub const CHANNEL_IDENTITY_PROVIDER_ADAPTER_VERSION: &str = "channel_identity.provider_adapter.v1";

/// Stable key for the built-in dev-safe email adapter.
pub const DEV_EMAIL_PROVIDER_KEY: &str = "dev_email";

/// Stable key for the built-in Slack shared-presence adapter.
pub const SLACK_SHARED_PRESENCE_PROVIDER_KEY: &str = "slack_shared_presence";

/// Stable key for the LINE Official Account adapter.
pub const LINE_OFFICIAL_ACCOUNT_PROVIDER_KEY: &str = "line_oa";

/// Stable channel key for email identities.
pub const EMAIL_CHANNEL: &str = "email";

/// Stable channel key for Slack shared-presence identities.
pub const SLACK_CHANNEL: &str = "slack";

/// Stable channel key for LINE Official Account identities.
pub const LINE_CHANNEL: &str = "line";

/// Default deterministic local-part prefix for dev-safe email identities.
pub const DEFAULT_EMAIL_LOCAL_PART_PREFIX: &str = "agent";

/// Default LINE monthly push allowance for the free Messaging API plan.
pub const DEFAULT_LINE_PUSH_MONTHLY_ALLOWANCE: u32 = 200;

const SIGNATURE_HEX_BYTES: usize = 6;
const SIGNATURE_HEX_LEN: usize = SIGNATURE_HEX_BYTES * 2;
const MAX_EMAIL_ADDRESS_BYTES: usize = 254;
const MAX_EMAIL_LOCAL_PART_BYTES: usize = 64;
const MAX_EMAIL_DOMAIN_BYTES: usize = 253;
const MAX_EMAIL_PROVIDER_EVENT_ID_BYTES: usize = 128;
const MAX_EMAIL_PAYLOAD_REF_BYTES: usize = 512;
const MAX_LINE_PROVIDER_EVENT_ID_BYTES: usize = 128;
const MAX_LINE_COMPONENT_BYTES: usize = 128;
const MAX_LINE_REPLY_TOKEN_BYTES: usize = 256;
const MAX_LINE_PAYLOAD_REF_BYTES: usize = 512;
const IDENTITY_HEX_LEN: usize = 32;
const LOCAL_PART_SEPARATOR_BYTES: usize = 2;
const MAX_LOCAL_PART_PREFIX_BYTES: usize =
    MAX_EMAIL_LOCAL_PART_BYTES - IDENTITY_HEX_LEN - SIGNATURE_HEX_LEN - LOCAL_PART_SEPARATOR_BYTES;
const MAX_SLACK_ID_BYTES: usize = 128;
const MAX_SLACK_PERSONA_HANDLE_BYTES: usize = 80;
const MAX_SLACK_DISPLAY_NAME_BYTES: usize = 80;
const MAX_SLACK_URL_BYTES: usize = 512;
const MAX_SLACK_TEXT_BYTES: usize = 40_000;
const MAX_SLACK_EVENT_ID_BYTES: usize = 128;
const MAX_SLACK_PAYLOAD_REF_BYTES: usize = 512;

/// Provider-normalized inbound payload before engine routing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "channel", rename_all = "snake_case")]
#[non_exhaustive]
pub enum ChannelIdentityProviderInbound {
    Email(EmailProviderInbound),
    Slack(SlackProviderInbound),
    Line(LineOfficialAccountInbound),
}

/// Email webhook payload fields the adapter needs for fail-closed routing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmailProviderInbound {
    pub provider_event_id: String,
    pub envelope_to: String,
    pub envelope_from: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload_ref: Option<String>,
    pub received_at: u64,
}

impl EmailProviderInbound {
    /// Builds an inbound email provider payload.
    #[must_use]
    pub fn new(
        provider_event_id: impl Into<String>,
        envelope_to: impl Into<String>,
        envelope_from: impl Into<String>,
        received_at: u64,
    ) -> Self {
        Self {
            provider_event_id: provider_event_id.into(),
            envelope_to: envelope_to.into(),
            envelope_from: envelope_from.into(),
            payload_ref: None,
            received_at,
        }
    }

    /// Attaches an adapter-local payload reference.
    #[must_use]
    pub fn with_payload_ref(mut self, payload_ref: impl Into<String>) -> Self {
        self.payload_ref = Some(payload_ref.into());
        self
    }
}

/// Slack Events API payload fields needed for shared-presence routing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlackProviderInbound {
    pub provider_event_id: String,
    pub workspace_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enterprise_id: Option<String>,
    pub channel_id: String,
    pub user_id: String,
    pub persona_handle: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload_ref: Option<String>,
    pub received_at: u64,
}

impl SlackProviderInbound {
    /// Builds a Slack inbound event after the host has resolved the persona.
    #[must_use]
    pub fn new(
        provider_event_id: impl Into<String>,
        workspace_id: impl Into<String>,
        channel_id: impl Into<String>,
        user_id: impl Into<String>,
        persona_handle: impl Into<String>,
        received_at: u64,
    ) -> Self {
        Self {
            provider_event_id: provider_event_id.into(),
            workspace_id: workspace_id.into(),
            enterprise_id: None,
            channel_id: channel_id.into(),
            user_id: user_id.into(),
            persona_handle: persona_handle.into(),
            payload_ref: None,
            received_at,
        }
    }

    /// Attaches an Enterprise Grid org id when Slack supplies one.
    #[must_use]
    pub fn with_enterprise_id(mut self, enterprise_id: impl Into<String>) -> Self {
        self.enterprise_id = Some(enterprise_id.into());
        self
    }

    /// Attaches an adapter-local payload reference.
    #[must_use]
    pub fn with_payload_ref(mut self, payload_ref: impl Into<String>) -> Self {
        self.payload_ref = Some(payload_ref.into());
        self
    }
}

/// LINE Messaging API webhook event fields used by the adapter.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineOfficialAccountInbound {
    pub provider_event_id: String,
    /// LINE webhook `destination` value for the product OA.
    pub destination: String,
    /// Provider-native LINE user id from the event source.
    pub source_user_id: String,
    #[serde(default, skip_serializing)]
    pub reply_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload_ref: Option<String>,
    pub received_at: u64,
}

impl fmt::Debug for LineOfficialAccountInbound {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LineOfficialAccountInbound")
            .field("provider_event_id", &self.provider_event_id)
            .field("destination", &self.destination)
            .field("source_user_id", &self.source_user_id)
            .field(
                "reply_token",
                &self.reply_token.as_ref().map(|_| "[redacted]"),
            )
            .field("payload_ref", &self.payload_ref)
            .field("received_at", &self.received_at)
            .finish()
    }
}

impl LineOfficialAccountInbound {
    /// Builds a LINE OA webhook event payload.
    #[must_use]
    pub fn new(
        provider_event_id: impl Into<String>,
        destination: impl Into<String>,
        source_user_id: impl Into<String>,
        received_at: u64,
    ) -> Self {
        Self {
            provider_event_id: provider_event_id.into(),
            destination: destination.into(),
            source_user_id: source_user_id.into(),
            reply_token: None,
            payload_ref: None,
            received_at,
        }
    }

    /// Attaches the provider reply token without exposing it to SurfaceEvent stamps.
    #[must_use]
    pub fn with_reply_token(mut self, reply_token: impl Into<String>) -> Self {
        self.reply_token = Some(reply_token.into());
        self
    }

    /// Attaches an adapter-local payload reference.
    #[must_use]
    pub fn with_payload_ref(mut self, payload_ref: impl Into<String>) -> Self {
        self.payload_ref = Some(payload_ref.into());
        self
    }
}

/// Provider result that can be reported back through CID-2 fulfillment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelIdentityProviderProvision {
    pub provider_key: String,
    pub identity_id: EntityId,
    pub channel: String,
    pub address_or_handle: String,
    pub fulfillment_mode: ChannelIdentityFulfillment,
    pub provider_identity_ref: String,
    pub fulfilled_at: u64,
}

impl ChannelIdentityProviderProvision {
    /// Converts provider success into the CID-2 fulfillment input.
    #[must_use]
    pub fn fulfillment_input(
        &self,
        actor: ChannelIdentityLifecycleActor,
    ) -> ChannelIdentityFulfillmentInput {
        ChannelIdentityFulfillmentInput {
            actor,
            identity_id: self.identity_id,
            fulfilled_at: self.fulfilled_at,
        }
    }
}

/// Host-side adapter contract for fulfilling identity lifecycle work.
pub trait ChannelIdentityProviderAdapter {
    /// Stable provider key for receipts, host logs, and adapter selection.
    fn provider_key(&self) -> &'static str;

    /// Declares how this adapter fulfills a lifecycle verb.
    fn fulfillment_mode(
        &self,
        verb: ChannelIdentityLifecycleVerb,
    ) -> Option<ChannelIdentityFulfillment>;

    /// Fulfills a CID-2 ProvisionIntent and returns the state-transition input.
    fn provision(
        &self,
        intent: &ProvisionIntent,
        fulfilled_at: u64,
    ) -> Result<ChannelIdentityProviderProvision>;

    /// Parses provider inbound webhook data into engine SurfaceEvent input.
    fn parse_inbound(
        &self,
        inbound: ChannelIdentityProviderInbound,
    ) -> Result<InboundSurfaceEventInput>;
}

/// Minimal mock adapter used by conformance tests and host tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MockChannelIdentityProviderAdapter {
    provider_key: &'static str,
    channel: String,
    allowed_address_or_handle: String,
    provision_mode: ChannelIdentityFulfillment,
}

impl MockChannelIdentityProviderAdapter {
    /// Builds an email-shaped mock adapter for one exact address.
    #[must_use]
    pub fn email(allowed_address: impl Into<String>) -> Self {
        Self {
            provider_key: "mock",
            channel: EMAIL_CHANNEL.to_owned(),
            allowed_address_or_handle: allowed_address.into(),
            provision_mode: ChannelIdentityFulfillment::Api,
        }
    }
}

impl ChannelIdentityProviderAdapter for MockChannelIdentityProviderAdapter {
    fn provider_key(&self) -> &'static str {
        self.provider_key
    }

    fn fulfillment_mode(
        &self,
        verb: ChannelIdentityLifecycleVerb,
    ) -> Option<ChannelIdentityFulfillment> {
        match verb {
            ChannelIdentityLifecycleVerb::Provision => Some(self.provision_mode),
            ChannelIdentityLifecycleVerb::Bind
            | ChannelIdentityLifecycleVerb::Rotate
            | ChannelIdentityLifecycleVerb::Release
            | ChannelIdentityLifecycleVerb::RouteInbound => None,
        }
    }

    fn provision(
        &self,
        intent: &ProvisionIntent,
        fulfilled_at: u64,
    ) -> Result<ChannelIdentityProviderProvision> {
        validate_provision_intent(
            intent,
            &self.channel,
            &self.allowed_address_or_handle,
            self.provision_mode,
        )?;
        Ok(ChannelIdentityProviderProvision {
            provider_key: self.provider_key().to_owned(),
            identity_id: intent.identity_id,
            channel: intent.identity.channel.clone(),
            address_or_handle: intent.identity.address_or_handle.clone(),
            fulfillment_mode: self.provision_mode,
            provider_identity_ref: format!("mock:{}", intent.identity_id.to_hex()),
            fulfilled_at,
        })
    }

    fn parse_inbound(
        &self,
        inbound: ChannelIdentityProviderInbound,
    ) -> Result<InboundSurfaceEventInput> {
        let email = match inbound {
            ChannelIdentityProviderInbound::Email(email) => email,
            ChannelIdentityProviderInbound::Slack(_) | ChannelIdentityProviderInbound::Line(_) => {
                return Err(Error::InvalidConfig(
                    "email adapter rejects non-email inbound".to_owned(),
                ));
            }
        };
        validate_email_inbound_metadata(&email)?;
        let (_, sender_domain) = split_email_address(&email.envelope_from)?;
        let normalized_from = normalize_email_address(&email.envelope_from, &sender_domain)?;
        if email.envelope_to != self.allowed_address_or_handle {
            return Err(Error::InvalidConfig(
                "mock adapter rejects unknown receiving identity".to_owned(),
            ));
        }
        let mut input = InboundSurfaceEventInput::new(
            email.provider_event_id,
            self.channel.clone(),
            email.envelope_to,
            SurfaceCounterpartyStamp::unknown(format!("email:{normalized_from}")),
            email.received_at,
            true,
        );
        input.payload_ref = email.payload_ref;
        Ok(input)
    }
}

/// Configuration for deterministic dev-safe email identities.
#[derive(Clone, PartialEq, Eq)]
pub struct DevEmailIdentityAdapterConfig {
    domain: String,
    local_part_prefix: String,
    signing_secret: String,
}

impl fmt::Debug for DevEmailIdentityAdapterConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DevEmailIdentityAdapterConfig")
            .field("domain", &self.domain)
            .field("local_part_prefix", &self.local_part_prefix)
            .field("signing_secret", &"[redacted]")
            .finish()
    }
}

impl DevEmailIdentityAdapterConfig {
    /// Builds config with the default `agent` local-part prefix.
    pub fn new(domain: impl Into<String>, signing_secret: impl Into<String>) -> Result<Self> {
        Self::with_prefix(domain, DEFAULT_EMAIL_LOCAL_PART_PREFIX, signing_secret)
    }

    /// Builds config with an explicit local-part prefix.
    pub fn with_prefix(
        domain: impl Into<String>,
        local_part_prefix: impl Into<String>,
        signing_secret: impl Into<String>,
    ) -> Result<Self> {
        let domain = normalize_domain(&domain.into())?;
        let local_part_prefix = normalize_local_part_prefix(&local_part_prefix.into())?;
        let signing_secret = signing_secret.into();
        validate_non_blank(
            &signing_secret,
            "email adapter signing secret must be non-empty",
        )?;
        Ok(Self {
            domain,
            local_part_prefix,
            signing_secret,
        })
    }

    /// Returns the normalized product domain.
    #[must_use]
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// Returns the normalized deterministic local-part prefix.
    #[must_use]
    pub fn local_part_prefix(&self) -> &str {
        &self.local_part_prefix
    }
}

/// Dev-safe email adapter with deterministic signed local-parts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DevEmailIdentityAdapter {
    config: DevEmailIdentityAdapterConfig,
}

impl DevEmailIdentityAdapter {
    /// Builds a deterministic email adapter.
    #[must_use]
    pub const fn new(config: DevEmailIdentityAdapterConfig) -> Self {
        Self { config }
    }

    /// Returns the adapter config.
    #[must_use]
    pub fn config(&self) -> &DevEmailIdentityAdapterConfig {
        &self.config
    }

    /// Deterministically derives the per-identity email address.
    #[must_use]
    pub fn address_for_identity(&self, identity_id: EntityId) -> String {
        let local_part = self.local_part_for_identity(identity_id);
        format!("{local_part}@{}", self.config.domain)
    }

    /// Builds the requested ChannelIdentity row that a CID-2 ProvisionIntent should carry.
    #[must_use]
    pub fn requested_identity(
        &self,
        identity_id: EntityId,
        agent_ref: EntityId,
        requested_at: u64,
    ) -> ChannelIdentity {
        ChannelIdentity::requested(
            EMAIL_CHANNEL,
            self.address_for_identity(identity_id),
            ChannelIdentityShape::DedicatedAddress,
            ChannelIdentityBinding::agent(agent_ref),
            requested_at,
        )
    }

    fn local_part_for_identity(&self, identity_id: EntityId) -> String {
        format!(
            "{}-{}-{}",
            self.config.local_part_prefix,
            identity_id.to_hex(),
            self.signature_hex(identity_id)
        )
    }

    fn signature_hex(&self, identity_id: EntityId) -> String {
        let key = blake3::hash(self.config.signing_secret.as_bytes());
        let mut hasher = blake3::Hasher::new_keyed(key.as_bytes());
        hasher.update(b"oneiron.cid3.email.local_part.v1");
        hasher.update(identity_id.as_bytes());
        hasher.update(self.config.domain.as_bytes());
        let digest = hasher.finalize();
        bytes_to_hex_lower(&digest.as_bytes()[..SIGNATURE_HEX_BYTES])
    }

    fn identity_from_local_part(&self, local_part: &str) -> Result<EntityId> {
        let expected_prefix = format!("{}-", self.config.local_part_prefix);
        let rest = local_part
            .strip_prefix(&expected_prefix)
            .ok_or_else(|| Error::InvalidConfig("email local-part prefix mismatch".to_owned()))?;
        let (identity_hex, signature) = rest.split_once('-').ok_or_else(|| {
            Error::InvalidConfig("email local-part missing identity signature".to_owned())
        })?;
        if identity_hex.len() != IDENTITY_HEX_LEN || signature.len() != SIGNATURE_HEX_LEN {
            return Err(Error::InvalidConfig(
                "email local-part has invalid deterministic shape".to_owned(),
            ));
        }
        let identity_id = EntityId::from_hex(identity_hex)?;
        let expected = self.local_part_for_identity(identity_id);
        if local_part != expected {
            return Err(Error::InvalidConfig(
                "email local-part signature mismatch".to_owned(),
            ));
        }
        Ok(identity_id)
    }
}

impl ChannelIdentityProviderAdapter for DevEmailIdentityAdapter {
    fn provider_key(&self) -> &'static str {
        DEV_EMAIL_PROVIDER_KEY
    }

    fn fulfillment_mode(
        &self,
        verb: ChannelIdentityLifecycleVerb,
    ) -> Option<ChannelIdentityFulfillment> {
        match verb {
            ChannelIdentityLifecycleVerb::Provision => Some(ChannelIdentityFulfillment::Api),
            ChannelIdentityLifecycleVerb::Bind
            | ChannelIdentityLifecycleVerb::Rotate
            | ChannelIdentityLifecycleVerb::Release
            | ChannelIdentityLifecycleVerb::RouteInbound => None,
        }
    }

    fn provision(
        &self,
        intent: &ProvisionIntent,
        fulfilled_at: u64,
    ) -> Result<ChannelIdentityProviderProvision> {
        let expected_address = self.address_for_identity(intent.identity_id);
        validate_provision_intent(
            intent,
            EMAIL_CHANNEL,
            &expected_address,
            ChannelIdentityFulfillment::Api,
        )?;
        Ok(ChannelIdentityProviderProvision {
            provider_key: self.provider_key().to_owned(),
            identity_id: intent.identity_id,
            channel: EMAIL_CHANNEL.to_owned(),
            address_or_handle: expected_address,
            fulfillment_mode: ChannelIdentityFulfillment::Api,
            provider_identity_ref: format!("dev-email:{}", intent.identity_id.to_hex()),
            fulfilled_at,
        })
    }

    fn parse_inbound(
        &self,
        inbound: ChannelIdentityProviderInbound,
    ) -> Result<InboundSurfaceEventInput> {
        let email = match inbound {
            ChannelIdentityProviderInbound::Email(email) => email,
            ChannelIdentityProviderInbound::Slack(_) | ChannelIdentityProviderInbound::Line(_) => {
                return Err(Error::InvalidConfig(
                    "email adapter rejects non-email inbound".to_owned(),
                ));
            }
        };
        validate_email_inbound_metadata(&email)?;
        let (local_part, domain) = split_email_address(&email.envelope_to)?;
        if domain != self.config.domain {
            return Err(Error::InvalidConfig(
                "email inbound domain is not managed by this adapter".to_owned(),
            ));
        }
        self.identity_from_local_part(&local_part)?;
        let (_, sender_domain) = split_email_address(&email.envelope_from)?;
        let normalized_from = normalize_email_address(&email.envelope_from, &sender_domain)?;
        let normalized_to = format!("{local_part}@{domain}");

        let mut input = InboundSurfaceEventInput::new(
            email.provider_event_id,
            EMAIL_CHANNEL,
            normalized_to,
            SurfaceCounterpartyStamp::unknown(format!("email:{normalized_from}")),
            email.received_at,
            true,
        );
        input.payload_ref = email.payload_ref;
        Ok(input)
    }
}

/// Slack app manifest config used with `apps.manifest.create`.
#[derive(Clone, PartialEq, Eq)]
pub struct SlackSharedPresenceAdapterConfig {
    app_name: String,
    bot_display_name: String,
    event_request_url: String,
    redirect_urls: Vec<String>,
}

impl fmt::Debug for SlackSharedPresenceAdapterConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SlackSharedPresenceAdapterConfig")
            .field("app_name", &self.app_name)
            .field("bot_display_name", &self.bot_display_name)
            .field("event_request_url", &self.event_request_url)
            .field("redirect_urls", &self.redirect_urls)
            .finish()
    }
}

impl SlackSharedPresenceAdapterConfig {
    /// Builds config for the one product-level Slack app manifest.
    pub fn new(
        app_name: impl Into<String>,
        bot_display_name: impl Into<String>,
        event_request_url: impl Into<String>,
        redirect_urls: Vec<String>,
    ) -> Result<Self> {
        let app_name =
            normalize_slack_display_name(&app_name.into(), "slack app name must be non-empty")?;
        let bot_display_name = normalize_slack_display_name(
            &bot_display_name.into(),
            "slack bot display name must be non-empty",
        )?;
        let event_request_url =
            normalize_slack_url(&event_request_url.into(), "slack event request url")?;
        if redirect_urls.is_empty() {
            return Err(Error::InvalidConfig(
                "slack manifest requires at least one OAuth redirect URL".to_owned(),
            ));
        }
        let redirect_urls = redirect_urls
            .into_iter()
            .map(|url| normalize_slack_url(&url, "slack OAuth redirect URL"))
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            app_name,
            bot_display_name,
            event_request_url,
            redirect_urls,
        })
    }

    /// Product-level app display name.
    #[must_use]
    pub fn app_name(&self) -> &str {
        &self.app_name
    }

    /// Slack bot user display name for the shared app identity.
    #[must_use]
    pub fn bot_display_name(&self) -> &str {
        &self.bot_display_name
    }
}

/// Persona metadata applied to outbound Slack messages.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlackPersonaAttribution {
    pub persona_handle: String,
    pub display_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icon_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icon_emoji: Option<String>,
}

impl SlackPersonaAttribution {
    /// Builds a Slack persona stamp for outbound authorship.
    pub fn new(persona_handle: impl Into<String>, display_name: impl Into<String>) -> Result<Self> {
        Ok(Self {
            persona_handle: normalize_slack_persona_handle(&persona_handle.into())?,
            display_name: normalize_slack_display_name(
                &display_name.into(),
                "slack persona display name must be non-empty",
            )?,
            icon_url: None,
            icon_emoji: None,
        })
    }

    /// Uses a hosted avatar URL for Slack `chat.postMessage`.
    pub fn with_icon_url(mut self, icon_url: impl Into<String>) -> Result<Self> {
        if self.icon_emoji.is_some() {
            return Err(Error::InvalidConfig(
                "slack persona may set icon_url or icon_emoji, not both".to_owned(),
            ));
        }
        self.icon_url = Some(normalize_slack_url(
            &icon_url.into(),
            "slack persona icon_url",
        )?);
        Ok(self)
    }

    /// Uses a Slack emoji shortcode for Slack `chat.postMessage`.
    pub fn with_icon_emoji(mut self, icon_emoji: impl Into<String>) -> Result<Self> {
        if self.icon_url.is_some() {
            return Err(Error::InvalidConfig(
                "slack persona may set icon_url or icon_emoji, not both".to_owned(),
            ));
        }
        self.icon_emoji = Some(normalize_slack_icon_emoji(&icon_emoji.into())?);
        Ok(self)
    }
}

/// Outbound Slack message before persona attribution is applied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlackOutboundMessage {
    pub workspace_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enterprise_id: Option<String>,
    pub channel_id: String,
    pub text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thread_ts: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload_ref: Option<String>,
}

impl SlackOutboundMessage {
    /// Builds a Slack `chat.postMessage` intent.
    pub fn new(
        workspace_id: impl Into<String>,
        channel_id: impl Into<String>,
        text: impl Into<String>,
    ) -> Result<Self> {
        Ok(Self {
            workspace_id: normalize_slack_id(&workspace_id.into(), "slack workspace id")?,
            enterprise_id: None,
            channel_id: normalize_slack_id(&channel_id.into(), "slack channel id")?,
            text: normalize_slack_text(&text.into())?,
            thread_ts: None,
            payload_ref: None,
        })
    }

    /// Attaches an Enterprise Grid org id when posting into a grid workspace.
    pub fn with_enterprise_id(mut self, enterprise_id: impl Into<String>) -> Result<Self> {
        self.enterprise_id = Some(normalize_slack_id(
            &enterprise_id.into(),
            "slack enterprise id",
        )?);
        Ok(self)
    }

    /// Posts as a threaded reply.
    pub fn with_thread_ts(mut self, thread_ts: impl Into<String>) -> Result<Self> {
        self.thread_ts = Some(normalize_slack_ts(&thread_ts.into())?);
        Ok(self)
    }

    /// Attaches an adapter-local payload reference.
    pub fn with_payload_ref(mut self, payload_ref: impl Into<String>) -> Result<Self> {
        self.payload_ref = Some(normalize_slack_payload_ref(&payload_ref.into())?);
        Ok(self)
    }
}

/// Slack Web API call body after persona attribution.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SlackPersonaOutbound {
    pub method: String,
    pub workspace_ref: String,
    pub identity_key: String,
    pub persona_handle: String,
    pub body: Value,
}

/// Oneiron-first Slack shared-presence adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlackSharedPresenceAdapter {
    config: SlackSharedPresenceAdapterConfig,
}

impl SlackSharedPresenceAdapter {
    /// Builds a Slack shared-presence adapter.
    #[must_use]
    pub const fn new(config: SlackSharedPresenceAdapterConfig) -> Self {
        Self { config }
    }

    /// Returns the adapter config.
    #[must_use]
    pub fn config(&self) -> &SlackSharedPresenceAdapterConfig {
        &self.config
    }

    /// Returns the Slack manifest body passed as the `manifest` argument.
    #[must_use]
    pub fn app_manifest(&self) -> Value {
        json!({
            "display_information": {
                "name": &self.config.app_name,
            },
            "features": {
                "bot_user": {
                    "display_name": &self.config.bot_display_name,
                    "always_online": false,
                },
            },
            "oauth_config": {
                "redirect_urls": &self.config.redirect_urls,
                "scopes": {
                    "bot": [
                        "app_mentions:read",
                        "channels:history",
                        "chat:write",
                        "chat:write.customize",
                        "commands",
                        "im:history",
                        "im:write",
                    ],
                },
            },
            "settings": {
                "event_subscriptions": {
                    "request_url": self.config.event_request_url,
                    "bot_events": [
                        "app_mention",
                        "message.im",
                    ],
                },
                "interactivity": {
                    "is_enabled": true,
                    "request_url": self.config.event_request_url,
                },
                "org_deploy_enabled": false,
                "socket_mode_enabled": false,
                "token_rotation_enabled": true,
            },
        })
    }

    /// Returns the `apps.manifest.create` request body.
    #[must_use]
    pub fn apps_manifest_create_payload(&self) -> Value {
        json!({
            "manifest": self.app_manifest().to_string(),
        })
    }

    /// Builds the requested ChannelIdentity row for one agent persona in a workspace.
    pub fn requested_identity(
        &self,
        agent_ref: EntityId,
        workspace_id: impl Into<String>,
        persona_handle: impl Into<String>,
        requested_at: u64,
    ) -> Result<ChannelIdentity> {
        let workspace_id = workspace_id.into();
        let persona_handle = persona_handle.into();
        self.requested_identity_from_parts(
            agent_ref,
            &workspace_id,
            None,
            &persona_handle,
            requested_at,
        )
    }

    /// Builds the requested ChannelIdentity row for one Enterprise Grid workspace persona.
    pub fn requested_enterprise_identity(
        &self,
        agent_ref: EntityId,
        enterprise_id: impl Into<String>,
        workspace_id: impl Into<String>,
        persona_handle: impl Into<String>,
        requested_at: u64,
    ) -> Result<ChannelIdentity> {
        let enterprise_id = enterprise_id.into();
        let workspace_id = workspace_id.into();
        let persona_handle = persona_handle.into();
        self.requested_identity_from_parts(
            agent_ref,
            &workspace_id,
            Some(&enterprise_id),
            &persona_handle,
            requested_at,
        )
    }

    /// Returns the canonical Slack workspace stamp used by requested, inbound, and outbound paths.
    pub fn workspace_ref(workspace_id: &str, enterprise_id: Option<&str>) -> Result<String> {
        slack_workspace_ref(workspace_id, enterprise_id)
    }

    /// Returns the canonical Slack persona ChannelIdentity key.
    pub fn persona_identity_key(
        workspace_id: &str,
        enterprise_id: Option<&str>,
        persona_handle: &str,
    ) -> Result<String> {
        slack_identity_key(workspace_id, enterprise_id, persona_handle)
    }

    fn requested_identity_from_parts(
        &self,
        agent_ref: EntityId,
        workspace_id: &str,
        enterprise_id: Option<&str>,
        persona_handle: &str,
        requested_at: u64,
    ) -> Result<ChannelIdentity> {
        let address_or_handle =
            Self::persona_identity_key(workspace_id, enterprise_id, persona_handle)?;
        Ok(ChannelIdentity::requested(
            SLACK_CHANNEL,
            address_or_handle,
            ChannelIdentityShape::SharedPresence,
            ChannelIdentityBinding::agent(agent_ref),
            requested_at,
        ))
    }

    /// Builds the Slack Web API payload plus sidecar persona attribution.
    pub fn persona_outbound(
        &self,
        attribution: &SlackPersonaAttribution,
        message: &SlackOutboundMessage,
    ) -> Result<SlackPersonaOutbound> {
        self.persona_outbound_body(attribution, message, false)
    }

    /// Builds a Slack Web API payload that also includes Slack message metadata.
    ///
    /// Slack requires message metadata to be sent with an app-level token. Bot-token callers should
    /// use [`Self::persona_outbound`] and read the identity stamps from [`SlackPersonaOutbound`].
    pub fn persona_outbound_with_metadata(
        &self,
        attribution: &SlackPersonaAttribution,
        message: &SlackOutboundMessage,
    ) -> Result<SlackPersonaOutbound> {
        self.persona_outbound_body(attribution, message, true)
    }

    fn persona_outbound_body(
        &self,
        attribution: &SlackPersonaAttribution,
        message: &SlackOutboundMessage,
        include_slack_metadata: bool,
    ) -> Result<SlackPersonaOutbound> {
        let workspace_ref =
            slack_workspace_ref(&message.workspace_id, message.enterprise_id.as_deref())?;
        let identity_key = slack_identity_key(
            &message.workspace_id,
            message.enterprise_id.as_deref(),
            &attribution.persona_handle,
        )?;
        let mut body = json!({
            "channel": &message.channel_id,
            "text": &message.text,
            "username": &attribution.display_name,
        });
        if include_slack_metadata {
            body["metadata"] = json!({
                "event_type": "oneiron_persona_message",
                "event_payload": {
                    "workspace_ref": &workspace_ref,
                    "identity_key": &identity_key,
                    "persona_handle": &attribution.persona_handle,
                },
            });
            if let Some(payload_ref) = &message.payload_ref {
                body["metadata"]["event_payload"]["payload_ref"] = Value::from(payload_ref.clone());
            }
        }
        if let Some(thread_ts) = &message.thread_ts {
            body["thread_ts"] = Value::from(thread_ts.clone());
        }
        if let Some(icon_url) = &attribution.icon_url {
            body["icon_url"] = Value::from(icon_url.clone());
        }
        if let Some(icon_emoji) = &attribution.icon_emoji {
            body["icon_emoji"] = Value::from(icon_emoji.clone());
        }
        Ok(SlackPersonaOutbound {
            method: "chat.postMessage".to_owned(),
            workspace_ref,
            identity_key,
            persona_handle: attribution.persona_handle.clone(),
            body,
        })
    }
}

impl ChannelIdentityProviderAdapter for SlackSharedPresenceAdapter {
    fn provider_key(&self) -> &'static str {
        SLACK_SHARED_PRESENCE_PROVIDER_KEY
    }

    fn fulfillment_mode(
        &self,
        verb: ChannelIdentityLifecycleVerb,
    ) -> Option<ChannelIdentityFulfillment> {
        match verb {
            ChannelIdentityLifecycleVerb::Provision => Some(ChannelIdentityFulfillment::Api),
            ChannelIdentityLifecycleVerb::Bind
            | ChannelIdentityLifecycleVerb::Rotate
            | ChannelIdentityLifecycleVerb::Release
            | ChannelIdentityLifecycleVerb::RouteInbound => None,
        }
    }

    fn provision(
        &self,
        intent: &ProvisionIntent,
        fulfilled_at: u64,
    ) -> Result<ChannelIdentityProviderProvision> {
        validate_slack_provision_intent(intent)?;
        Ok(ChannelIdentityProviderProvision {
            provider_key: self.provider_key().to_owned(),
            identity_id: intent.identity_id,
            channel: SLACK_CHANNEL.to_owned(),
            address_or_handle: intent.identity.address_or_handle.clone(),
            fulfillment_mode: ChannelIdentityFulfillment::Api,
            provider_identity_ref: format!(
                "slack-shared-presence:{}",
                intent.identity.address_or_handle
            ),
            fulfilled_at,
        })
    }

    fn parse_inbound(
        &self,
        inbound: ChannelIdentityProviderInbound,
    ) -> Result<InboundSurfaceEventInput> {
        let slack = match inbound {
            ChannelIdentityProviderInbound::Slack(slack) => slack,
            ChannelIdentityProviderInbound::Email(_) | ChannelIdentityProviderInbound::Line(_) => {
                return Err(Error::InvalidConfig(
                    "slack adapter rejects non-slack inbound".to_owned(),
                ));
            }
        };
        let normalized = normalize_slack_inbound(slack)?;
        let mut input = InboundSurfaceEventInput::new(
            normalized.provider_event_id.clone(),
            SLACK_CHANNEL,
            normalized.identity_key.clone(),
            SurfaceCounterpartyStamp::unknown(normalized.counterparty_key),
            normalized.received_at,
            true,
        )
        .with_workspace_ref(normalized.workspace_ref);
        input.payload_ref = Some(normalized.payload_ref);
        Ok(input)
    }
}

struct NormalizedSlackInbound {
    provider_event_id: String,
    workspace_ref: String,
    identity_key: String,
    counterparty_key: String,
    payload_ref: String,
    received_at: u64,
}

fn normalize_slack_inbound(slack: SlackProviderInbound) -> Result<NormalizedSlackInbound> {
    let provider_event_id = normalize_slack_payload_ref(&slack.provider_event_id)?;
    validate_max_bytes(
        &provider_event_id,
        MAX_SLACK_EVENT_ID_BYTES,
        "slack event id exceeds maximum length",
    )?;
    let workspace_id = normalize_slack_id(&slack.workspace_id, "slack workspace id")?;
    let enterprise_id = slack
        .enterprise_id
        .as_deref()
        .map(|enterprise_id| normalize_slack_id(enterprise_id, "slack enterprise id"))
        .transpose()?;
    let channel_id = normalize_slack_id(&slack.channel_id, "slack channel id")?;
    let user_id = normalize_slack_id(&slack.user_id, "slack user id")?;
    let persona_handle = normalize_slack_persona_handle(&slack.persona_handle)?;
    let workspace_ref = slack_workspace_ref(&workspace_id, enterprise_id.as_deref())?;
    let identity_key =
        slack_identity_key(&workspace_id, enterprise_id.as_deref(), &persona_handle)?;
    let counterparty_key = format!("{workspace_ref}:user:{user_id}");
    let payload_ref = slack
        .payload_ref
        .as_deref()
        .map(normalize_slack_payload_ref)
        .transpose()?
        .unwrap_or_else(|| {
            format!("{workspace_ref}:channel:{channel_id}:event:{provider_event_id}")
        });
    Ok(NormalizedSlackInbound {
        provider_event_id,
        workspace_ref,
        identity_key,
        counterparty_key,
        payload_ref,
        received_at: slack.received_at,
    })
}

fn validate_slack_provision_intent(intent: &ProvisionIntent) -> Result<()> {
    if intent.fulfillment_mode != ChannelIdentityFulfillment::Api {
        return Err(Error::InvalidConfig(
            "slack adapter fulfillment mode does not match ProvisionIntent".to_owned(),
        ));
    }
    if intent.identity.channel != SLACK_CHANNEL {
        return Err(Error::InvalidConfig(
            "slack adapter channel does not match ProvisionIntent".to_owned(),
        ));
    }
    if intent.identity.shape != ChannelIdentityShape::SharedPresence {
        return Err(Error::InvalidConfig(
            "slack adapter requires shared_presence identities".to_owned(),
        ));
    }
    if !matches!(
        intent.identity.binding,
        ChannelIdentityBinding::Agent { .. }
    ) {
        return Err(Error::InvalidConfig(
            "slack adapter requires agent-scoped personas".to_owned(),
        ));
    }
    validate_slack_identity_key(&intent.identity.address_or_handle)?;
    intent.identity.validate()
}

fn slack_workspace_ref(workspace_id: &str, enterprise_id: Option<&str>) -> Result<String> {
    let workspace_id = normalize_slack_id(workspace_id, "slack workspace id")?;
    match enterprise_id {
        Some(enterprise_id) => {
            let enterprise_id = normalize_slack_id(enterprise_id, "slack enterprise id")?;
            Ok(format!(
                "slack:enterprise:{enterprise_id}:workspace:{workspace_id}"
            ))
        }
        None => Ok(format!("slack:workspace:{workspace_id}")),
    }
}

fn slack_identity_key(
    workspace_id: &str,
    enterprise_id: Option<&str>,
    persona_handle: &str,
) -> Result<String> {
    let workspace_ref = slack_workspace_ref(workspace_id, enterprise_id)?;
    let persona_handle = normalize_slack_persona_handle(persona_handle)?;
    Ok(format!("{workspace_ref}:persona:{persona_handle}"))
}

fn validate_slack_identity_key(identity_key: &str) -> Result<()> {
    let parts = identity_key.split(':').collect::<Vec<_>>();
    let expected = match parts.as_slice() {
        [
            "slack",
            "workspace",
            workspace_id,
            "persona",
            persona_handle,
        ] => slack_identity_key(workspace_id, None, persona_handle)?,
        [
            "slack",
            "enterprise",
            enterprise_id,
            "workspace",
            workspace_id,
            "persona",
            persona_handle,
        ] => slack_identity_key(workspace_id, Some(enterprise_id), persona_handle)?,
        _ => {
            return Err(Error::InvalidConfig(
                "slack identity key must include workspace and persona".to_owned(),
            ));
        }
    };
    if expected != identity_key {
        return Err(Error::InvalidConfig(
            "slack identity key is not normalized".to_owned(),
        ));
    }
    Ok(())
}

fn normalize_slack_id(value: &str, field: &'static str) -> Result<String> {
    let value = value.trim();
    validate_non_blank(value, field)?;
    validate_max_bytes(value, MAX_SLACK_ID_BYTES, "slack id exceeds maximum length")?;
    if !value.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
        return Err(Error::InvalidConfig(format!(
            "{field} must contain only ascii letters and digits"
        )));
    }
    Ok(value.to_owned())
}

fn normalize_slack_persona_handle(value: &str) -> Result<String> {
    let value = value.trim().trim_start_matches('@').to_ascii_lowercase();
    validate_non_blank(&value, "slack persona handle must be non-empty")?;
    validate_max_bytes(
        &value,
        MAX_SLACK_PERSONA_HANDLE_BYTES,
        "slack persona handle exceeds maximum length",
    )?;
    if !value
        .bytes()
        .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.'))
    {
        return Err(Error::InvalidConfig(
            "slack persona handle must be ascii lowercase letters, digits, hyphen, underscore, or dot".to_owned(),
        ));
    }
    Ok(value)
}

fn normalize_slack_display_name(value: &str, reason: &'static str) -> Result<String> {
    let value = value.trim();
    validate_non_blank(value, reason)?;
    validate_max_bytes(
        value,
        MAX_SLACK_DISPLAY_NAME_BYTES,
        "slack display name exceeds maximum length",
    )?;
    if value.chars().any(char::is_control) {
        return Err(Error::InvalidConfig(
            "slack display name must not contain control characters".to_owned(),
        ));
    }
    Ok(value.to_owned())
}

fn normalize_slack_url(value: &str, field: &'static str) -> Result<String> {
    let value = value.trim();
    validate_non_blank(value, field)?;
    validate_max_bytes(
        value,
        MAX_SLACK_URL_BYTES,
        "slack URL exceeds maximum length",
    )?;
    if !value.starts_with("https://") || value.chars().any(char::is_whitespace) {
        return Err(Error::InvalidConfig(format!(
            "{field} must be an https URL without whitespace"
        )));
    }
    Ok(value.to_owned())
}

fn normalize_slack_icon_emoji(value: &str) -> Result<String> {
    let value = value.trim();
    validate_non_blank(value, "slack persona icon_emoji must be non-empty")?;
    validate_max_bytes(
        value,
        MAX_SLACK_DISPLAY_NAME_BYTES,
        "slack persona icon_emoji exceeds maximum length",
    )?;
    if value.len() <= 2
        || !value.starts_with(':')
        || !value.ends_with(':')
        || !value.bytes().all(|byte| byte.is_ascii())
    {
        return Err(Error::InvalidConfig(
            "slack persona icon_emoji must be a Slack emoji shortcode".to_owned(),
        ));
    }
    Ok(value.to_owned())
}

fn normalize_slack_text(value: &str) -> Result<String> {
    validate_non_blank(value, "slack outbound text must be non-empty")?;
    validate_max_bytes(
        value,
        MAX_SLACK_TEXT_BYTES,
        "slack outbound text exceeds maximum length",
    )?;
    Ok(value.to_owned())
}

fn normalize_slack_ts(value: &str) -> Result<String> {
    let value = value.trim();
    validate_non_blank(value, "slack thread timestamp must be non-empty")?;
    validate_max_bytes(
        value,
        MAX_SLACK_ID_BYTES,
        "slack thread timestamp exceeds maximum length",
    )?;
    if !value.bytes().all(|byte| matches!(byte, b'0'..=b'9' | b'.')) {
        return Err(Error::InvalidConfig(
            "slack thread timestamp must contain only digits and dot".to_owned(),
        ));
    }
    Ok(value.to_owned())
}

fn normalize_slack_payload_ref(value: &str) -> Result<String> {
    let value = value.trim();
    validate_non_blank(value, "slack payload ref must be non-empty")?;
    validate_max_bytes(
        value,
        MAX_SLACK_PAYLOAD_REF_BYTES,
        "slack payload ref exceeds maximum length",
    )?;
    Ok(value.to_owned())
}

/// LINE Messaging API plan tier used for quota-aware runtime manifests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LineOfficialAccountPlanTier {
    Free,
    Paid,
    Enterprise,
}

impl LineOfficialAccountPlanTier {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Free => "free",
            Self::Paid => "paid",
            Self::Enterprise => "enterprise",
        }
    }
}

/// Non-secret LINE Official Account adapter configuration.
#[derive(Clone, PartialEq, Eq)]
pub struct LineOfficialAccountAdapterConfig {
    messaging_api_destination: String,
    plan_tier: LineOfficialAccountPlanTier,
    monthly_push_allowance: u32,
}

impl fmt::Debug for LineOfficialAccountAdapterConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LineOfficialAccountAdapterConfig")
            .field("messaging_api_destination", &self.messaging_api_destination)
            .field("plan_tier", &self.plan_tier)
            .field("monthly_push_allowance", &self.monthly_push_allowance)
            .finish()
    }
}

impl LineOfficialAccountAdapterConfig {
    /// Builds LINE OA config for a console-minted Messaging API channel.
    pub fn new(
        messaging_api_destination: impl Into<String>,
        plan_tier: LineOfficialAccountPlanTier,
    ) -> Result<Self> {
        Self::with_monthly_push_allowance(
            messaging_api_destination,
            plan_tier,
            DEFAULT_LINE_PUSH_MONTHLY_ALLOWANCE,
        )
    }

    /// Builds LINE OA config with an explicit monthly push allowance.
    pub fn with_monthly_push_allowance(
        messaging_api_destination: impl Into<String>,
        plan_tier: LineOfficialAccountPlanTier,
        monthly_push_allowance: u32,
    ) -> Result<Self> {
        if monthly_push_allowance == 0 {
            return Err(Error::InvalidConfig(
                "LINE OA monthly push allowance must be greater than zero".to_owned(),
            ));
        }
        let messaging_api_destination = normalize_line_component(
            &messaging_api_destination.into(),
            "LINE OA Messaging API destination",
            MAX_LINE_COMPONENT_BYTES,
        )?;
        Ok(Self {
            messaging_api_destination,
            plan_tier,
            monthly_push_allowance,
        })
    }

    /// Returns the LINE webhook destination this adapter accepts.
    #[must_use]
    pub fn messaging_api_destination(&self) -> &str {
        &self.messaging_api_destination
    }

    /// Returns the configured LINE plan tier.
    #[must_use]
    pub const fn plan_tier(&self) -> LineOfficialAccountPlanTier {
        self.plan_tier
    }

    /// Returns the configured monthly push allowance.
    #[must_use]
    pub const fn monthly_push_allowance(&self) -> u32 {
        self.monthly_push_allowance
    }
}

/// LINE Official Account adapter for console-minted OA binding plus API runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LineOfficialAccountAdapter {
    config: LineOfficialAccountAdapterConfig,
}

impl LineOfficialAccountAdapter {
    /// Builds a LINE OA adapter.
    #[must_use]
    pub const fn new(config: LineOfficialAccountAdapterConfig) -> Self {
        Self { config }
    }

    /// Returns the adapter config.
    #[must_use]
    pub fn config(&self) -> &LineOfficialAccountAdapterConfig {
        &self.config
    }

    /// Builds the per-LINE-user shared_presence route key.
    pub fn address_for_line_user(&self, source_user_id: impl AsRef<str>) -> Result<String> {
        let source_user_id = normalize_line_component(
            source_user_id.as_ref(),
            "LINE source user id",
            MAX_LINE_COMPONENT_BYTES,
        )?;
        Ok(line_shared_presence_address(
            &self.config.messaging_api_destination,
            &source_user_id,
        ))
    }

    /// Builds a requested per-user persona identity on the shared product OA.
    pub fn requested_identity(
        &self,
        _identity_id: EntityId,
        agent_ref: EntityId,
        source_user_id: impl AsRef<str>,
        requested_at: u64,
    ) -> Result<ChannelIdentity> {
        let address_or_handle = self.address_for_line_user(source_user_id)?;
        Ok(ChannelIdentity::requested(
            LINE_CHANNEL,
            address_or_handle,
            ChannelIdentityShape::SharedPresence,
            ChannelIdentityBinding::agent(agent_ref),
            requested_at,
        ))
    }

    fn provider_identity_ref(&self) -> String {
        format!("line-oa:{}", self.config.messaging_api_destination)
    }
}

impl ChannelIdentityProviderAdapter for LineOfficialAccountAdapter {
    fn provider_key(&self) -> &'static str {
        LINE_OFFICIAL_ACCOUNT_PROVIDER_KEY
    }

    fn fulfillment_mode(
        &self,
        verb: ChannelIdentityLifecycleVerb,
    ) -> Option<ChannelIdentityFulfillment> {
        match verb {
            ChannelIdentityLifecycleVerb::Provision | ChannelIdentityLifecycleVerb::Bind => {
                Some(ChannelIdentityFulfillment::Manual)
            }
            ChannelIdentityLifecycleVerb::Rotate
            | ChannelIdentityLifecycleVerb::Release
            | ChannelIdentityLifecycleVerb::RouteInbound => None,
        }
    }

    fn provision(
        &self,
        intent: &ProvisionIntent,
        fulfilled_at: u64,
    ) -> Result<ChannelIdentityProviderProvision> {
        validate_line_provision_intent(intent, &self.config.messaging_api_destination)?;
        Ok(ChannelIdentityProviderProvision {
            provider_key: self.provider_key().to_owned(),
            identity_id: intent.identity_id,
            channel: LINE_CHANNEL.to_owned(),
            address_or_handle: intent.identity.address_or_handle.clone(),
            fulfillment_mode: ChannelIdentityFulfillment::Manual,
            provider_identity_ref: self.provider_identity_ref(),
            fulfilled_at,
        })
    }

    fn parse_inbound(
        &self,
        inbound: ChannelIdentityProviderInbound,
    ) -> Result<InboundSurfaceEventInput> {
        let line = expect_line_inbound(inbound)?;
        validate_line_inbound_metadata(&line)?;
        let destination = normalize_line_component(
            &line.destination,
            "LINE OA Messaging API destination",
            MAX_LINE_COMPONENT_BYTES,
        )?;
        if destination != self.config.messaging_api_destination {
            return Err(Error::InvalidConfig(
                "LINE inbound destination is not managed by this adapter".to_owned(),
            ));
        }
        let source_user_id = normalize_line_component(
            &line.source_user_id,
            "LINE source user id",
            MAX_LINE_COMPONENT_BYTES,
        )?;
        let receiving_address_or_handle =
            line_shared_presence_address(&destination, &source_user_id);
        let mut input = InboundSurfaceEventInput::new(
            line.provider_event_id,
            LINE_CHANNEL,
            receiving_address_or_handle,
            SurfaceCounterpartyStamp::unknown(format!("line:user:{source_user_id}")),
            line.received_at,
            true,
        );
        input.payload_ref = line.payload_ref;
        Ok(input)
    }
}

fn validate_provision_intent(
    intent: &ProvisionIntent,
    expected_channel: &str,
    expected_address_or_handle: &str,
    expected_mode: ChannelIdentityFulfillment,
) -> Result<()> {
    if intent.fulfillment_mode != expected_mode {
        return Err(Error::InvalidConfig(
            "provider adapter fulfillment mode does not match ProvisionIntent".to_owned(),
        ));
    }
    if intent.identity.channel != expected_channel {
        return Err(Error::InvalidConfig(
            "provider adapter channel does not match ProvisionIntent".to_owned(),
        ));
    }
    if intent.identity.address_or_handle != expected_address_or_handle {
        return Err(Error::InvalidConfig(
            "provider adapter address does not match deterministic identity address".to_owned(),
        ));
    }
    if intent.identity.shape != ChannelIdentityShape::DedicatedAddress {
        return Err(Error::InvalidConfig(
            "email provider adapter requires dedicated_address identities".to_owned(),
        ));
    }
    if !matches!(
        intent.identity.binding,
        ChannelIdentityBinding::Agent { .. }
    ) {
        return Err(Error::InvalidConfig(
            "email provider adapter requires agent-scoped identities".to_owned(),
        ));
    }
    intent.identity.validate()
}

fn validate_line_provision_intent(
    intent: &ProvisionIntent,
    expected_destination: &str,
) -> Result<()> {
    if intent.fulfillment_mode != ChannelIdentityFulfillment::Manual {
        return Err(Error::InvalidConfig(
            "LINE OA adapter requires manual fulfillment".to_owned(),
        ));
    }
    if intent.identity.channel != LINE_CHANNEL {
        return Err(Error::InvalidConfig(
            "LINE OA adapter channel does not match ProvisionIntent".to_owned(),
        ));
    }
    if intent.identity.shape != ChannelIdentityShape::SharedPresence {
        return Err(Error::InvalidConfig(
            "LINE OA adapter requires shared_presence identities".to_owned(),
        ));
    }
    if !matches!(
        intent.identity.binding,
        ChannelIdentityBinding::Agent { .. }
    ) {
        return Err(Error::InvalidConfig(
            "LINE OA adapter requires agent-scoped identities".to_owned(),
        ));
    }
    validate_line_shared_presence_address(
        &intent.identity.address_or_handle,
        expected_destination,
    )?;
    intent.identity.validate()
}

fn expect_line_inbound(
    inbound: ChannelIdentityProviderInbound,
) -> Result<LineOfficialAccountInbound> {
    match inbound {
        ChannelIdentityProviderInbound::Line(line) => Ok(line),
        ChannelIdentityProviderInbound::Email(_) | ChannelIdentityProviderInbound::Slack(_) => Err(
            Error::InvalidConfig("LINE OA adapter received non-LINE inbound".to_owned()),
        ),
    }
}

fn normalize_domain(domain: &str) -> Result<String> {
    let domain = domain.trim().trim_end_matches('.');
    validate_non_blank(domain, "email adapter domain must be non-empty")?;
    validate_max_bytes(
        domain,
        MAX_EMAIL_DOMAIN_BYTES,
        "email adapter domain exceeds maximum length",
    )?;
    let domain = domain.to_ascii_lowercase();
    if domain.contains('@') || domain.contains('*') || domain.contains("..") {
        return Err(Error::InvalidConfig(
            "email adapter domain must be an exact non-wildcard domain".to_owned(),
        ));
    }
    if domain.starts_with('.') || domain.ends_with('.') {
        return Err(Error::InvalidConfig(
            "email adapter domain must not start or end with a dot".to_owned(),
        ));
    }
    if !domain
        .bytes()
        .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.'))
    {
        return Err(Error::InvalidConfig(
            "email adapter domain must be ascii hostname characters".to_owned(),
        ));
    }
    for label in domain.split('.') {
        if label.is_empty() || label.starts_with('-') || label.ends_with('-') {
            return Err(Error::InvalidConfig(
                "email adapter domain contains an invalid label".to_owned(),
            ));
        }
    }
    Ok(domain)
}

fn normalize_local_part_prefix(prefix: &str) -> Result<String> {
    let prefix = prefix.trim().to_ascii_lowercase();
    validate_non_blank(&prefix, "email local-part prefix must be non-empty")?;
    if prefix.len() > MAX_LOCAL_PART_PREFIX_BYTES {
        return Err(Error::InvalidConfig(format!(
            "email local-part prefix must be at most {MAX_LOCAL_PART_PREFIX_BYTES} bytes"
        )));
    }
    if prefix.starts_with('-') || prefix.ends_with('-') {
        return Err(Error::InvalidConfig(
            "email local-part prefix must not start or end with hyphen".to_owned(),
        ));
    }
    if !prefix
        .bytes()
        .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'-'))
    {
        return Err(Error::InvalidConfig(
            "email local-part prefix must be ascii lowercase letters, digits, or hyphen".to_owned(),
        ));
    }
    Ok(prefix)
}

fn split_email_address(address: &str) -> Result<(String, String)> {
    let address = address.trim();
    validate_non_blank(address, "email address must be non-empty")?;
    validate_max_bytes(
        address,
        MAX_EMAIL_ADDRESS_BYTES,
        "email address exceeds maximum length",
    )?;
    if address.contains('*') {
        return Err(Error::InvalidConfig(
            "email adapter rejects wildcard or catch-all addresses".to_owned(),
        ));
    }
    let (local_part, domain) = address
        .split_once('@')
        .ok_or_else(|| Error::InvalidConfig("email address must contain @".to_owned()))?;
    if local_part.is_empty() || local_part.contains('@') || domain.contains('@') {
        return Err(Error::InvalidConfig(
            "email address must contain one non-empty local-part and domain".to_owned(),
        ));
    }
    validate_max_bytes(
        local_part,
        MAX_EMAIL_LOCAL_PART_BYTES,
        "email local-part exceeds maximum length",
    )?;
    let domain = normalize_domain(domain)?;
    if !local_part.bytes().all(|byte| {
        matches!(
            byte,
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'+'
        )
    }) {
        return Err(Error::InvalidConfig(
            "email local-part contains unsupported characters".to_owned(),
        ));
    }
    Ok((local_part.to_ascii_lowercase(), domain))
}

fn validate_email_inbound_metadata(email: &EmailProviderInbound) -> Result<()> {
    validate_non_blank(
        &email.provider_event_id,
        "provider event id must be non-empty",
    )?;
    validate_max_bytes(
        &email.provider_event_id,
        MAX_EMAIL_PROVIDER_EVENT_ID_BYTES,
        "provider event id exceeds maximum length",
    )?;
    if let Some(payload_ref) = &email.payload_ref {
        validate_non_blank(payload_ref, "email payload_ref must be non-empty")?;
        validate_max_bytes(
            payload_ref,
            MAX_EMAIL_PAYLOAD_REF_BYTES,
            "email payload_ref exceeds maximum length",
        )?;
    }
    Ok(())
}

fn validate_line_inbound_metadata(line: &LineOfficialAccountInbound) -> Result<()> {
    validate_non_blank(
        &line.provider_event_id,
        "provider event id must be non-empty",
    )?;
    validate_max_bytes(
        &line.provider_event_id,
        MAX_LINE_PROVIDER_EVENT_ID_BYTES,
        "provider event id exceeds maximum length",
    )?;
    if let Some(reply_token) = &line.reply_token {
        validate_non_blank(reply_token, "LINE reply token must be non-empty")?;
        validate_max_bytes(
            reply_token,
            MAX_LINE_REPLY_TOKEN_BYTES,
            "LINE reply token exceeds maximum length",
        )?;
        if line.payload_ref.is_none() {
            return Err(Error::InvalidConfig(
                "LINE reply token requires payload_ref host-local handle".to_owned(),
            ));
        }
    }
    if let Some(payload_ref) = &line.payload_ref {
        validate_non_blank(payload_ref, "LINE payload_ref must be non-empty")?;
        validate_max_bytes(
            payload_ref,
            MAX_LINE_PAYLOAD_REF_BYTES,
            "LINE payload_ref exceeds maximum length",
        )?;
    }
    Ok(())
}

fn normalize_line_component(value: &str, label: &'static str, max: usize) -> Result<String> {
    let value = value.trim();
    validate_non_blank(value, "LINE component must be non-empty")?;
    validate_line_component_max_bytes(value, max, label)?;
    if !value.bytes().all(|byte| {
        matches!(
            byte,
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'@'
        )
    }) {
        return Err(Error::InvalidConfig(format!(
            "{label} must use LINE id-safe characters"
        )));
    }
    Ok(value.to_owned())
}

fn validate_line_component_max_bytes(value: &str, max: usize, label: &'static str) -> Result<()> {
    if value.len() > max {
        return Err(Error::InvalidConfig(format!(
            "{label} exceeds maximum length: {max} bytes"
        )));
    }
    Ok(())
}

fn line_shared_presence_address(destination: &str, source_user_id: &str) -> String {
    format!("line:oa:{destination}:user:{source_user_id}")
}

fn validate_line_shared_presence_address(address: &str, expected_destination: &str) -> Result<()> {
    validate_non_blank(address, "LINE shared_presence address must be non-empty")?;
    let prefix = format!("line:oa:{expected_destination}:user:");
    let Some(source_user_id) = address.strip_prefix(&prefix) else {
        return Err(Error::InvalidConfig(
            "LINE shared_presence address does not match adapter destination".to_owned(),
        ));
    };
    let source_user_id = normalize_line_component(
        source_user_id,
        "LINE source user id",
        MAX_LINE_COMPONENT_BYTES,
    )?;
    if address != line_shared_presence_address(expected_destination, &source_user_id) {
        return Err(Error::InvalidConfig(
            "LINE shared_presence address is not normalized".to_owned(),
        ));
    }
    Ok(())
}

fn normalize_email_address(address: &str, normalized_domain: &str) -> Result<String> {
    let (local_part, domain) = split_email_address(address)?;
    if domain != normalized_domain {
        return Err(Error::InvalidConfig(
            "email normalization domain mismatch".to_owned(),
        ));
    }
    Ok(format!("{local_part}@{domain}"))
}

fn validate_non_blank(value: &str, reason: &'static str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(Error::InvalidConfig(reason.to_owned()));
    }
    Ok(())
}

fn validate_max_bytes(value: &str, max: usize, reason: &'static str) -> Result<()> {
    if value.len() > max {
        return Err(Error::InvalidConfig(format!("{reason}: {max} bytes")));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel_identity::ChannelIdentityState;
    use crate::surface_event::{InboundSurfaceRouteOutcome, SurfaceCounterpartyStamp};
    use crate::{Vault, VaultConfig};

    fn entity(seed: u8) -> EntityId {
        EntityId::from_bytes([seed; 16]).expect("valid test id")
    }

    fn temp_vault() -> (tempfile::TempDir, Vault) {
        let tmp = tempfile::tempdir().expect("temp dir");
        let mut cfg = VaultConfig::device();
        cfg.map_size = 16 * 1024 * 1024;
        cfg.dimensions = 4;
        cfg.embedding_model = None;
        let vault = Vault::open(tmp.path(), cfg).expect("open vault");
        (tmp, vault)
    }

    fn activate_line_identity(
        adapter: &LineOfficialAccountAdapter,
        vault: &Vault,
        identity_id: EntityId,
        agent_ref: EntityId,
        source_user_id: &str,
        requested_at: u64,
    ) -> Result<ChannelIdentity> {
        let identity =
            adapter.requested_identity(identity_id, agent_ref, source_user_id, requested_at)?;
        vault.create_channel_identity(&identity_id, &identity)?;
        vault.transition_channel_identity(
            &identity_id,
            ChannelIdentityState::PendingFulfillment,
            Some(ChannelIdentityFulfillment::Manual),
            requested_at + 1,
            None,
        )?;
        let provision = adapter.provision(
            &ProvisionIntent {
                identity_id,
                identity: identity.clone(),
                fulfillment_mode: ChannelIdentityFulfillment::Manual,
            },
            requested_at + 2,
        )?;
        vault.fulfill_channel_identity(
            provision.fulfillment_input(ChannelIdentityLifecycleActor::agent(agent_ref)),
        )?;
        Ok(identity)
    }

    fn assert_provider_conformance<A: ChannelIdentityProviderAdapter>(
        adapter: &A,
        intent: ProvisionIntent,
        inbound: ChannelIdentityProviderInbound,
    ) -> Result<()> {
        assert_eq!(
            adapter.fulfillment_mode(ChannelIdentityLifecycleVerb::Provision),
            Some(ChannelIdentityFulfillment::Api)
        );
        assert_eq!(
            adapter.fulfillment_mode(ChannelIdentityLifecycleVerb::Bind),
            None
        );
        let provision = adapter.provision(&intent, 2_000)?;
        assert_eq!(provision.identity_id, intent.identity_id);
        assert_eq!(provision.channel, intent.identity.channel);
        assert_eq!(
            provision.address_or_handle,
            intent.identity.address_or_handle
        );
        assert_eq!(provision.fulfillment_mode, ChannelIdentityFulfillment::Api);
        assert_eq!(
            provision
                .fulfillment_input(ChannelIdentityLifecycleActor::agent(entity(0xA1)))
                .identity_id,
            intent.identity_id
        );
        let parsed = adapter.parse_inbound(inbound)?;
        assert_eq!(parsed.channel, EMAIL_CHANNEL);
        assert_eq!(
            parsed.receiving_address_or_handle,
            intent.identity.address_or_handle
        );
        assert!(parsed.foreign_inbound);
        Ok(())
    }

    #[test]
    fn mock_adapter_conformance_suite_consumes_provision_and_inbound() -> Result<()> {
        let identity_id = entity(0x11);
        let agent_ref = entity(0xA1);
        let address = "agent@example.test";
        let identity = ChannelIdentity::requested(
            EMAIL_CHANNEL,
            address,
            ChannelIdentityShape::DedicatedAddress,
            ChannelIdentityBinding::agent(agent_ref),
            1_000,
        );
        let adapter = MockChannelIdentityProviderAdapter::email(address);
        assert_provider_conformance(
            &adapter,
            ProvisionIntent {
                identity_id,
                identity,
                fulfillment_mode: ChannelIdentityFulfillment::Api,
            },
            ChannelIdentityProviderInbound::Email(EmailProviderInbound::new(
                "evt-1",
                address,
                "sender@example.test",
                2_001,
            )),
        )
    }

    #[test]
    fn dev_email_adapter_derives_signed_per_identity_addresses() -> Result<()> {
        let adapter = DevEmailIdentityAdapter::new(DevEmailIdentityAdapterConfig::new(
            "Agents.Example.Test",
            "dev-secret",
        )?);
        let identity_id = entity(0x21);
        let agent_ref = entity(0xA2);
        let address = adapter.address_for_identity(identity_id);

        assert!(address.ends_with("@agents.example.test"));
        assert!(address.starts_with("agent-21212121212121212121212121212121-"));

        let identity = adapter.requested_identity(identity_id, agent_ref, 1_000);
        assert_eq!(identity.address_or_handle, address);
        assert_eq!(identity.state, ChannelIdentityState::Requested);

        assert_provider_conformance(
            &adapter,
            ProvisionIntent {
                identity_id,
                identity,
                fulfillment_mode: ChannelIdentityFulfillment::Api,
            },
            ChannelIdentityProviderInbound::Email(EmailProviderInbound::new(
                "evt-dev",
                address,
                "Friend@Example.Test",
                2_002,
            )),
        )
    }

    #[test]
    fn dev_email_adapter_rejects_catch_all_and_unsigned_local_parts() -> Result<()> {
        let adapter = DevEmailIdentityAdapter::new(DevEmailIdentityAdapterConfig::new(
            "agents.example.test",
            "dev-secret",
        )?);

        for address in ["*@agents.example.test", "random@agents.example.test"] {
            assert!(
                adapter
                    .parse_inbound(ChannelIdentityProviderInbound::Email(
                        EmailProviderInbound::new(
                            "evt-reject",
                            address,
                            "sender@example.test",
                            2_003
                        )
                    ))
                    .is_err(),
                "{address} should be rejected"
            );
        }
        Ok(())
    }

    #[test]
    fn email_adapters_reject_oversized_inbound_fields_before_routing() -> Result<()> {
        let adapter = DevEmailIdentityAdapter::new(DevEmailIdentityAdapterConfig::new(
            "agents.example.test",
            "dev-secret",
        )?);
        let address = adapter.address_for_identity(entity(0x29));

        for inbound in [
            EmailProviderInbound::new(
                "e".repeat(MAX_EMAIL_PROVIDER_EVENT_ID_BYTES + 1),
                address.clone(),
                "sender@example.test",
                2_004,
            ),
            EmailProviderInbound::new(
                "evt-long-payload",
                address.clone(),
                "sender@example.test",
                2_004,
            )
            .with_payload_ref("p".repeat(MAX_EMAIL_PAYLOAD_REF_BYTES + 1)),
            EmailProviderInbound::new(
                "evt-long-from",
                address,
                format!(
                    "{}@example.test",
                    "s".repeat(MAX_EMAIL_LOCAL_PART_BYTES + 1)
                ),
                2_004,
            ),
            EmailProviderInbound::new(
                "evt-long-to",
                format!(
                    "{}@agents.example.test",
                    "r".repeat(MAX_EMAIL_LOCAL_PART_BYTES + 1)
                ),
                "sender@example.test",
                2_004,
            ),
        ] {
            assert!(
                adapter
                    .parse_inbound(ChannelIdentityProviderInbound::Email(inbound))
                    .is_err(),
                "oversized inbound field should be rejected"
            );
        }

        let mock = MockChannelIdentityProviderAdapter::email("agent@example.test");
        assert!(
            mock.parse_inbound(ChannelIdentityProviderInbound::Email(
                EmailProviderInbound::new(
                    "evt-mock-long-from",
                    "agent@example.test",
                    format!(
                        "{}@example.test",
                        "s".repeat(MAX_EMAIL_LOCAL_PART_BYTES + 1)
                    ),
                    2_004,
                )
            ))
            .is_err(),
            "mock adapter must also bound persisted counterparty addresses"
        );
        Ok(())
    }

    #[test]
    fn dev_email_adapter_prefix_limit_keeps_local_part_smtp_sized() -> Result<()> {
        let valid_prefix = "p".repeat(MAX_LOCAL_PART_PREFIX_BYTES);
        let adapter = DevEmailIdentityAdapter::new(DevEmailIdentityAdapterConfig::with_prefix(
            "agents.example.test",
            &valid_prefix,
            "dev-secret",
        )?);
        let address = adapter.address_for_identity(entity(0x41));
        let (local_part, _) = address
            .split_once('@')
            .expect("adapter emits email address");
        assert_eq!(local_part.len(), MAX_EMAIL_LOCAL_PART_BYTES);

        let too_long_prefix = "p".repeat(MAX_LOCAL_PART_PREFIX_BYTES + 1);
        assert!(
            DevEmailIdentityAdapterConfig::with_prefix(
                "agents.example.test",
                too_long_prefix,
                "dev-secret"
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn dev_email_adapter_requires_agent_scoped_dedicated_address() -> Result<()> {
        let adapter = DevEmailIdentityAdapter::new(DevEmailIdentityAdapterConfig::new(
            "agents.example.test",
            "dev-secret",
        )?);
        let identity_id = entity(0x31);
        let mut identity = adapter.requested_identity(identity_id, entity(0xA3), 1_000);
        identity.binding = ChannelIdentityBinding::vault(42);

        let err = adapter
            .provision(
                &ProvisionIntent {
                    identity_id,
                    identity,
                    fulfillment_mode: ChannelIdentityFulfillment::Api,
                },
                2_000,
            )
            .expect_err("vault-scoped email identity must be rejected");
        assert!(matches!(err, Error::InvalidConfig(_)));
        Ok(())
    }

    fn slack_adapter() -> Result<SlackSharedPresenceAdapter> {
        Ok(SlackSharedPresenceAdapter::new(
            SlackSharedPresenceAdapterConfig::new(
                "Oneiron",
                "Oneiron",
                "https://oneiron.example.test/slack/events",
                vec!["https://oneiron.example.test/slack/oauth/callback".to_owned()],
            )?,
        ))
    }

    #[test]
    fn slack_manifest_payload_is_ready_for_apps_manifest_create() -> Result<()> {
        let adapter = slack_adapter()?;
        let payload = adapter.apps_manifest_create_payload();
        let manifest_arg = payload["manifest"]
            .as_str()
            .expect("apps.manifest.create manifest argument is a string");
        let manifest: Value = serde_json::from_str(manifest_arg)
            .map_err(|err| Error::InvalidConfig(format!("invalid manifest json: {err}")))?;

        assert_eq!(manifest["display_information"]["name"], "Oneiron");
        assert_eq!(
            manifest["settings"]["event_subscriptions"]["request_url"],
            "https://oneiron.example.test/slack/events"
        );
        assert_eq!(
            manifest["settings"]["token_rotation_enabled"],
            Value::Bool(true)
        );
        let scopes = manifest["oauth_config"]["scopes"]["bot"]
            .as_array()
            .expect("bot scopes");
        assert!(scopes.contains(&Value::from("chat:write")));
        assert!(scopes.contains(&Value::from("chat:write.customize")));
        assert!(scopes.contains(&Value::from("app_mentions:read")));
        Ok(())
    }

    #[test]
    fn slack_shared_presence_identities_distinguish_agents_in_one_workspace() -> Result<()> {
        let adapter = slack_adapter()?;
        let agent_a = entity(0xB1);
        let agent_b = entity(0xB2);
        let identity_a = adapter.requested_identity(agent_a, "T123ABC", "@eiri", 1_000)?;
        let identity_b = adapter.requested_identity(agent_b, "T123ABC", "herald", 1_000)?;

        assert_eq!(identity_a.channel, SLACK_CHANNEL);
        assert_eq!(identity_a.shape, ChannelIdentityShape::SharedPresence);
        assert_eq!(identity_a.binding, ChannelIdentityBinding::agent(agent_a));
        assert_eq!(
            identity_a.address_or_handle,
            "slack:workspace:T123ABC:persona:eiri"
        );
        assert_eq!(
            identity_b.address_or_handle,
            "slack:workspace:T123ABC:persona:herald"
        );

        let identity_id = entity(0x61);
        let provision = adapter.provision(
            &ProvisionIntent {
                identity_id,
                identity: identity_a,
                fulfillment_mode: ChannelIdentityFulfillment::Api,
            },
            2_000,
        )?;
        assert_eq!(provision.provider_key, SLACK_SHARED_PRESENCE_PROVIDER_KEY);
        assert_eq!(provision.channel, SLACK_CHANNEL);
        assert_eq!(provision.fulfillment_mode, ChannelIdentityFulfillment::Api);
        assert!(
            provision
                .provider_identity_ref
                .contains("slack:workspace:T123ABC:persona:eiri")
        );
        Ok(())
    }

    #[test]
    fn slack_enterprise_identity_matches_inbound_and_outbound_keys() -> Result<()> {
        let adapter = slack_adapter()?;
        let expected_workspace_ref = "slack:enterprise:E123ABC:workspace:T123ABC";
        let expected_identity_key = "slack:enterprise:E123ABC:workspace:T123ABC:persona:eiri";
        let identity = adapter.requested_enterprise_identity(
            entity(0xB3),
            "E123ABC",
            "T123ABC",
            "@Eiri",
            1_000,
        )?;

        assert_eq!(identity.channel, SLACK_CHANNEL);
        assert_eq!(identity.shape, ChannelIdentityShape::SharedPresence);
        assert_eq!(identity.address_or_handle, expected_identity_key);
        assert_eq!(
            SlackSharedPresenceAdapter::workspace_ref("T123ABC", Some("E123ABC"))?,
            expected_workspace_ref
        );
        assert_eq!(
            SlackSharedPresenceAdapter::persona_identity_key("T123ABC", Some("E123ABC"), "@Eiri")?,
            expected_identity_key
        );

        let parsed = adapter.parse_inbound(ChannelIdentityProviderInbound::Slack(
            SlackProviderInbound::new("EvGrid", "T123ABC", "C123ABC", "U123ABC", "eiri", 2_001)
                .with_enterprise_id("E123ABC"),
        ))?;
        assert_eq!(
            parsed.workspace_ref.as_deref(),
            Some(expected_workspace_ref)
        );
        assert_eq!(parsed.receiving_address_or_handle, expected_identity_key);
        assert_eq!(
            parsed.counterparty,
            SurfaceCounterpartyStamp::unknown(
                "slack:enterprise:E123ABC:workspace:T123ABC:user:U123ABC"
            )
        );

        let attribution = SlackPersonaAttribution::new("eiri", "Eiri")?;
        let message = SlackOutboundMessage::new("T123ABC", "C123ABC", "Grid hello")?
            .with_enterprise_id("E123ABC")?;
        let outbound = adapter.persona_outbound(&attribution, &message)?;
        assert_eq!(outbound.workspace_ref, expected_workspace_ref);
        assert_eq!(outbound.identity_key, expected_identity_key);
        assert!(outbound.body.get("metadata").is_none());

        let outbound_with_metadata =
            adapter.persona_outbound_with_metadata(&attribution, &message)?;
        assert_eq!(
            outbound_with_metadata.body["metadata"]["event_payload"]["workspace_ref"],
            expected_workspace_ref
        );
        assert_eq!(
            outbound_with_metadata.body["metadata"]["event_payload"]["identity_key"],
            expected_identity_key
        );
        Ok(())
    }

    #[test]
    fn slack_adapter_rejects_non_shared_presence_provision() -> Result<()> {
        let adapter = slack_adapter()?;
        let mut identity = adapter.requested_identity(entity(0xB1), "T123ABC", "eiri", 1_000)?;
        identity.shape = ChannelIdentityShape::DedicatedHandle;

        let err = adapter
            .provision(
                &ProvisionIntent {
                    identity_id: entity(0x62),
                    identity,
                    fulfillment_mode: ChannelIdentityFulfillment::Api,
                },
                2_000,
            )
            .expect_err("slack adapter must require shared_presence");
        assert!(matches!(err, Error::InvalidConfig(_)));
        Ok(())
    }

    #[test]
    fn slack_inbound_stamps_workspace_and_persona_identity() -> Result<()> {
        let adapter = slack_adapter()?;
        let parsed = adapter.parse_inbound(ChannelIdentityProviderInbound::Slack(
            SlackProviderInbound::new("Ev123", "T123ABC", "C123ABC", "U123ABC", "@Eiri", 2_001)
                .with_payload_ref("slack:event:Ev123"),
        ))?;

        assert_eq!(parsed.channel, SLACK_CHANNEL);
        assert_eq!(
            parsed.receiving_address_or_handle,
            "slack:workspace:T123ABC:persona:eiri"
        );
        assert_eq!(
            parsed.workspace_ref.as_deref(),
            Some("slack:workspace:T123ABC")
        );
        assert_eq!(parsed.payload_ref.as_deref(), Some("slack:event:Ev123"));
        assert_eq!(
            parsed.counterparty,
            SurfaceCounterpartyStamp::unknown("slack:workspace:T123ABC:user:U123ABC")
        );
        assert!(parsed.foreign_inbound);
        Ok(())
    }

    #[test]
    fn slack_outbound_payload_carries_persona_attribution() -> Result<()> {
        let adapter = slack_adapter()?;
        let attribution =
            SlackPersonaAttribution::new("@Eiri", "Eiri")?.with_icon_emoji(":sparkles:")?;
        let message = SlackOutboundMessage::new("T123ABC", "C123ABC", "I can take this.")?
            .with_thread_ts("1719860000.000100")?
            .with_payload_ref("outbound:one")?;

        let outbound = adapter.persona_outbound(&attribution, &message)?;

        assert_eq!(outbound.method, "chat.postMessage");
        assert_eq!(outbound.workspace_ref, "slack:workspace:T123ABC");
        assert_eq!(
            outbound.identity_key,
            "slack:workspace:T123ABC:persona:eiri"
        );
        assert_eq!(outbound.body["channel"], "C123ABC");
        assert_eq!(outbound.body["username"], "Eiri");
        assert_eq!(outbound.body["icon_emoji"], ":sparkles:");
        assert!(outbound.body.get("metadata").is_none());

        let outbound_with_metadata =
            adapter.persona_outbound_with_metadata(&attribution, &message)?;
        assert_eq!(
            outbound_with_metadata.body["metadata"]["event_payload"]["identity_key"],
            "slack:workspace:T123ABC:persona:eiri"
        );
        assert_eq!(
            outbound_with_metadata.body["metadata"]["event_payload"]["payload_ref"],
            "outbound:one"
        );
        Ok(())
    }
    #[test]
    fn line_oa_adapter_manual_fulfillment_and_inbound_stamping() -> Result<()> {
        let config = LineOfficialAccountAdapterConfig::new(
            "Uproductoa123",
            LineOfficialAccountPlanTier::Free,
        )?;
        let adapter = LineOfficialAccountAdapter::new(config);
        let identity_id = entity(0x61);
        let agent_ref = entity(0xA6);
        let source_user_id = "UlineUserA";
        let address = adapter.address_for_line_user(source_user_id)?;

        assert_eq!(
            adapter.fulfillment_mode(ChannelIdentityLifecycleVerb::Provision),
            Some(ChannelIdentityFulfillment::Manual)
        );
        assert_eq!(
            adapter.fulfillment_mode(ChannelIdentityLifecycleVerb::Bind),
            Some(ChannelIdentityFulfillment::Manual)
        );
        assert_eq!(
            adapter.fulfillment_mode(ChannelIdentityLifecycleVerb::RouteInbound),
            None
        );

        let identity = adapter.requested_identity(identity_id, agent_ref, source_user_id, 1_000)?;
        assert_eq!(identity.channel, LINE_CHANNEL);
        assert_eq!(identity.address_or_handle, address);
        assert_eq!(identity.shape, ChannelIdentityShape::SharedPresence);
        assert!(matches!(
            identity.binding,
            ChannelIdentityBinding::Agent { agent_ref: bound } if bound == agent_ref
        ));

        let provision = adapter.provision(
            &ProvisionIntent {
                identity_id,
                identity: identity.clone(),
                fulfillment_mode: ChannelIdentityFulfillment::Manual,
            },
            1_002,
        )?;
        assert_eq!(provision.provider_key, LINE_OFFICIAL_ACCOUNT_PROVIDER_KEY);
        assert_eq!(
            provision.fulfillment_mode,
            ChannelIdentityFulfillment::Manual
        );
        assert_eq!(provision.provider_identity_ref, "line-oa:Uproductoa123");

        let (_tmp, vault) = temp_vault();
        vault.create_channel_identity(&identity_id, &identity)?;
        vault.transition_channel_identity(
            &identity_id,
            ChannelIdentityState::PendingFulfillment,
            Some(ChannelIdentityFulfillment::Manual),
            1_001,
            None,
        )?;
        vault.fulfill_channel_identity(
            provision.fulfillment_input(ChannelIdentityLifecycleActor::agent(agent_ref)),
        )?;

        let parsed = adapter.parse_inbound(ChannelIdentityProviderInbound::Line(
            LineOfficialAccountInbound::new("line-event-1", "Uproductoa123", source_user_id, 1_003)
                .with_reply_token("reply-token-redacted")
                .with_payload_ref("provider:line-event-1"),
        ))?;

        assert_eq!(parsed.channel, LINE_CHANNEL);
        assert_eq!(parsed.receiving_address_or_handle, address);
        assert_eq!(
            parsed.counterparty,
            SurfaceCounterpartyStamp::unknown("line:user:UlineUserA")
        );
        assert!(parsed.foreign_inbound);

        let receipt = vault.route_inbound_surface_event(parsed)?;
        assert_eq!(receipt.outcome, InboundSurfaceRouteOutcome::Routed);
        assert_eq!(receipt.receiving_identity_ref, Some(identity_id.to_hex()));
        assert_eq!(receipt.agent_ref, Some(agent_ref.to_hex()));
        let surface_event = receipt.surface_event.expect("routed event");
        assert_eq!(surface_event.receiving_identity_ref, identity_id.to_hex());
        assert_eq!(surface_event.agent_ref, agent_ref.to_hex());
        assert_eq!(
            surface_event.payload_ref.as_deref(),
            Some("provider:line-event-1")
        );
        assert!(surface_event.claims_not_instructions);

        let serialized = serde_json::to_value(ChannelIdentityProviderInbound::Line(
            LineOfficialAccountInbound::new(
                "line-event-serialized",
                "Uproductoa123",
                source_user_id,
                1_004,
            )
            .with_reply_token("reply-token-secret")
            .with_payload_ref("provider:line-event-serialized"),
        ))
        .expect("serialize LINE inbound");
        assert!(serialized.get("reply_token").is_none());
        assert_eq!(
            serialized
                .get("payload_ref")
                .and_then(serde_json::Value::as_str),
            Some("provider:line-event-serialized")
        );

        let missing_handle_err = adapter
            .parse_inbound(ChannelIdentityProviderInbound::Line(
                LineOfficialAccountInbound::new(
                    "line-event-missing-handle",
                    "Uproductoa123",
                    source_user_id,
                    1_005,
                )
                .with_reply_token("reply-token-without-host-handle"),
            ))
            .expect_err("LINE reply token without payload_ref must fail closed");
        assert!(matches!(
            missing_handle_err,
            Error::InvalidConfig(reason)
                if reason == "LINE reply token requires payload_ref host-local handle"
        ));
        Ok(())
    }

    #[test]
    fn line_oa_shared_presence_routes_users_to_separate_personas() -> Result<()> {
        let adapter = LineOfficialAccountAdapter::new(LineOfficialAccountAdapterConfig::new(
            "Uproductoa123",
            LineOfficialAccountPlanTier::Paid,
        )?);
        let (_tmp, vault) = temp_vault();

        let identity_a = entity(0x71);
        let identity_b = entity(0x72);
        let agent_a = entity(0xA7);
        let agent_b = entity(0xB7);
        activate_line_identity(&adapter, &vault, identity_a, agent_a, "UlineUserA", 2_000)?;
        activate_line_identity(&adapter, &vault, identity_b, agent_b, "UlineUserB", 2_100)?;

        let parsed_a = adapter.parse_inbound(ChannelIdentityProviderInbound::Line(
            LineOfficialAccountInbound::new("line-event-a", "Uproductoa123", "UlineUserA", 2_200),
        ))?;
        let parsed_b = adapter.parse_inbound(ChannelIdentityProviderInbound::Line(
            LineOfficialAccountInbound::new("line-event-b", "Uproductoa123", "UlineUserB", 2_201),
        ))?;
        assert_ne!(
            parsed_a.receiving_address_or_handle,
            parsed_b.receiving_address_or_handle
        );

        let receipt_a = vault.route_inbound_surface_event(parsed_a)?;
        let receipt_b = vault.route_inbound_surface_event(parsed_b)?;
        assert_eq!(receipt_a.receiving_identity_ref, Some(identity_a.to_hex()));
        assert_eq!(receipt_a.agent_ref, Some(agent_a.to_hex()));
        assert_eq!(receipt_b.receiving_identity_ref, Some(identity_b.to_hex()));
        assert_eq!(receipt_b.agent_ref, Some(agent_b.to_hex()));
        Ok(())
    }

    #[test]
    fn line_oa_adapter_rejects_wrong_destination_and_non_shared_presence() -> Result<()> {
        let adapter = LineOfficialAccountAdapter::new(LineOfficialAccountAdapterConfig::new(
            "Uproductoa123",
            LineOfficialAccountPlanTier::Free,
        )?);
        let inbound_err = adapter
            .parse_inbound(ChannelIdentityProviderInbound::Line(
                LineOfficialAccountInbound::new(
                    "line-event-wrong",
                    "Uotheroa",
                    "UlineUserA",
                    3_000,
                ),
            ))
            .expect_err("wrong OA destination must fail closed");
        assert!(matches!(inbound_err, Error::InvalidConfig(_)));

        let identity_id = entity(0x81);
        let mut identity =
            adapter.requested_identity(identity_id, entity(0xA8), "UlineUserA", 3_100)?;
        identity.shape = ChannelIdentityShape::DedicatedHandle;
        let provision_err = adapter
            .provision(
                &ProvisionIntent {
                    identity_id,
                    identity,
                    fulfillment_mode: ChannelIdentityFulfillment::Manual,
                },
                3_101,
            )
            .expect_err("dedicated per-companion OA is out of v1 shared_presence scope");
        assert!(matches!(provision_err, Error::InvalidConfig(_)));

        let overlong_user_id = "U".repeat(MAX_LINE_COMPONENT_BYTES + 1);
        let length_err = adapter
            .address_for_line_user(&overlong_user_id)
            .expect_err("overlong LINE source user id must fail clearly");
        assert!(matches!(
            length_err,
            Error::InvalidConfig(reason)
                if reason == format!(
                    "LINE source user id exceeds maximum length: {MAX_LINE_COMPONENT_BYTES} bytes"
                )
        ));
        Ok(())
    }
}
