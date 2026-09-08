//! Slack shared-presence adapter: config, persona/outbound types, impls, and inbound normalizer.

use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::inbound_types::{
    ChannelIdentityProviderAdapter, ChannelIdentityProviderInbound,
    ChannelIdentityProviderProvision, SlackProviderInbound,
};
use super::shared_validate::{
    MAX_SLACK_EVENT_ID_BYTES, SLACK_CHANNEL, SLACK_SHARED_PRESENCE_PROVIDER_KEY, validate_max_bytes,
};
use super::slack_validate::{
    normalize_slack_display_name, normalize_slack_icon_emoji, normalize_slack_id,
    normalize_slack_payload_ref, normalize_slack_persona_handle, normalize_slack_text,
    normalize_slack_ts, normalize_slack_url, slack_identity_key, slack_workspace_ref,
    validate_slack_provision_intent,
};
use crate::channel_identity::{
    ChannelIdentity, ChannelIdentityBinding, ChannelIdentityFulfillment, SelfHeldShape,
};
use crate::channel_identity_lifecycle::{ChannelIdentityLifecycleVerb, ProvisionIntent};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::surface_event::{InboundSurfaceEventInput, SurfaceCounterpartyStamp};

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
            SelfHeldShape::SharedPresence,
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
