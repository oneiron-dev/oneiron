//! LINE Official Account adapter: plan tier, config, and trait impl.

use std::fmt;

use serde::{Deserialize, Serialize};

use super::inbound_types::{
    ChannelIdentityProviderAdapter, ChannelIdentityProviderInbound,
    ChannelIdentityProviderProvision,
};
use super::shared_validate::{
    DEFAULT_LINE_PUSH_MONTHLY_ALLOWANCE, LINE_CHANNEL, LINE_OFFICIAL_ACCOUNT_PROVIDER_KEY,
    MAX_LINE_COMPONENT_BYTES, expect_line_inbound, line_shared_presence_address,
    normalize_line_user_like_id, validate_line_inbound_metadata, validate_line_provision_intent,
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
        let source_user_id = normalize_line_user_like_id(
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
