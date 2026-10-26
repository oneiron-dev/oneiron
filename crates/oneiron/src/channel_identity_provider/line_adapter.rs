//! LINE Official Account adapter: plan tier, config, and trait impl.

use std::fmt;

use serde::{Deserialize, Serialize};

use super::inbound_types::{
    ChannelIdentityProviderAdapter, ChannelIdentityProviderInbound,
    ChannelIdentityProviderProvision, LineChat, LineChatKind,
};
use super::shared_validate::{
    DEFAULT_LINE_PUSH_MONTHLY_ALLOWANCE, LINE_CHANNEL, LINE_OFFICIAL_ACCOUNT_PROVIDER_KEY,
    MAX_LINE_COMPONENT_BYTES, expect_line_inbound, line_chat_address, line_shared_presence_address,
    normalize_line_chat_id, normalize_line_user_like_id, validate_line_inbound_metadata,
    validate_line_provision_intent,
};
use crate::channel_identity::{
    ChannelIdentity, ChannelIdentityBinding, ChannelIdentityFulfillment, SelfHeldShape,
};
use crate::channel_identity_lifecycle::{ChannelIdentityLifecycleVerb, ProvisionIntent};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::surface_event::{InboundSurfaceEventInput, SurfaceCounterpartyStamp};

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
    /// Builds free-plan LINE OA config for a console-minted Messaging API channel.
    ///
    /// Paid and enterprise OA bindings must pass the account-specific monthly
    /// allowance through [`Self::with_monthly_push_allowance`].
    pub fn new(
        messaging_api_destination: impl Into<String>,
        plan_tier: LineOfficialAccountPlanTier,
    ) -> Result<Self> {
        if plan_tier != LineOfficialAccountPlanTier::Free {
            return Err(Error::InvalidConfig(
                "LINE OA non-free plan requires explicit monthly push allowance".to_owned(),
            ));
        }
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
        let messaging_api_destination = normalize_line_user_like_id(
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
        let source_user_id = normalize_line_user_like_id(
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
            SelfHeldShape::SharedPresence,
            ChannelIdentityBinding::agent(agent_ref),
            requested_at,
        ))
    }

    /// Builds a group or room's own shared_presence route key: every member's
    /// message in that chat routes to the one agent bound to it.
    pub fn address_for_line_chat(&self, chat: &LineChat) -> Result<String> {
        let chat_id = normalize_line_chat_id(&chat.id, chat.kind)?;
        Ok(line_chat_address(
            &self.config.messaging_api_destination,
            chat.kind,
            &chat_id,
        ))
    }

    /// Builds a requested chat-level persona identity on the shared product
    /// OA, for the owner to bind a group or room to one agent.
    pub fn requested_chat_identity(
        &self,
        agent_ref: EntityId,
        chat: &LineChat,
        requested_at: u64,
    ) -> Result<ChannelIdentity> {
        let address_or_handle = self.address_for_line_chat(chat)?;
        Ok(ChannelIdentity::requested(
            LINE_CHANNEL,
            address_or_handle,
            SelfHeldShape::SharedPresence,
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
            address_or_handle: intent.identity.address_or_handle().to_owned(),
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
        let destination = normalize_line_user_like_id(
            &line.destination,
            "LINE OA Messaging API destination",
            MAX_LINE_COMPONENT_BYTES,
        )?;
        if destination != self.config.messaging_api_destination {
            return Err(Error::InvalidConfig(
                "LINE inbound destination is not managed by this adapter".to_owned(),
            ));
        }
        let source_user_id = line
            .source_user_id
            .as_deref()
            .map(|user| {
                normalize_line_user_like_id(user, "LINE source user id", MAX_LINE_COMPONENT_BYTES)
            })
            .transpose()?;
        let routed_chat = line.chat.as_ref().map(normalized_line_chat).transpose()?;
        // A per-sender message's chat only names the reply's audience; an id
        // LINE would never send falls back to the sender, and the sink still
        // answers only the audience the reply is admitted on.
        let reply_chat = line
            .reply_chat
            .as_ref()
            .and_then(|chat| normalized_line_chat(chat).ok());
        let receiving_address_or_handle = match (&routed_chat, &source_user_id) {
            (Some(chat), _) => line_chat_address(&destination, chat.kind, &chat.id),
            (None, Some(user)) => line_shared_presence_address(&destination, user),
            (None, None) => {
                return Err(Error::InvalidConfig(
                    "LINE inbound names neither its sender nor a group or room".to_owned(),
                ));
            }
        };
        // A message's party is the chat it is answered in, so a reply is
        // admitted on that audience, not on whoever wrote: a chat-routed
        // message, and an unbound chat's message that routes per sender
        // (FIX 2838). A 1:1 message's party is its sender.
        let audience = routed_chat.as_ref().or(reply_chat.as_ref());
        let counterparty_key =
            line_audience_key(audience, source_user_id.as_deref()).ok_or_else(|| {
                Error::InvalidConfig(
                    "LINE inbound names neither its sender nor a group or room".to_owned(),
                )
            })?;
        let mut input = InboundSurfaceEventInput::new(
            line.provider_event_id,
            LINE_CHANNEL,
            receiving_address_or_handle,
            SurfaceCounterpartyStamp::unknown(counterparty_key),
            line.received_at,
            true,
        );
        // An unbound chat's message is answered in the chat, and its typed
        // source stays the member who wrote it (FIX 10809).
        if routed_chat.is_none()
            && reply_chat.is_some()
            && let Some(sender) = line_audience_key(None, source_user_id.as_deref())
        {
            input.source.user_ref = sender;
        }
        input.payload_ref = line.payload_ref;
        Ok(input)
    }
}

/// The audience a LINE message is answered to (FIX 2838): the group or
/// room it was written in (`line:group:<C…>`, `line:room:<R…>`), else its
/// sender (`line:user:<U…>`). The one spelling of the reply target the
/// adapter freezes and of the archived event the sink answers, so a reply
/// never answers an audience it was not admitted on. `None` names nobody.
#[must_use]
pub fn line_audience_key(chat: Option<&LineChat>, user_id: Option<&str>) -> Option<String> {
    match (chat, user_id) {
        (Some(chat), _) => Some(format!("line:{}:{}", chat.kind.as_str(), chat.id)),
        (None, Some(user)) => Some(format!("line:user:{user}")),
        (None, None) => None,
    }
}

/// Whether `key` names a group or room audience in [`line_audience_key`]'s
/// spelling (`line:group:<C…>`, `line:room:<R…>`).
#[must_use]
pub fn is_line_chat_audience_key(key: &str) -> bool {
    key.strip_prefix("line:")
        .and_then(|rest| rest.split_once(':'))
        .and_then(|(kind, _)| LineChatKind::parse(kind))
        .is_some()
}

/// [`line_audience_key`] over a provider event's raw source ids, normalized
/// as intake normalizes them, so an archived event and the reply target
/// intake froze spell one audience alike. A chat id intake would not take
/// falls back to the sender, as intake does; a sender intake would not take
/// names nobody.
#[must_use]
pub fn line_source_audience_key(chat: Option<&LineChat>, user_id: Option<&str>) -> Option<String> {
    let chat = chat.and_then(|chat| normalized_line_chat(chat).ok());
    let user = user_id.and_then(|user| {
        normalize_line_user_like_id(user, "LINE source user id", MAX_LINE_COMPONENT_BYTES).ok()
    });
    line_audience_key(chat.as_ref(), user.as_deref())
}

fn normalized_line_chat(chat: &LineChat) -> Result<LineChat> {
    Ok(LineChat::new(
        chat.kind,
        normalize_line_chat_id(&chat.id, chat.kind)?,
    ))
}
