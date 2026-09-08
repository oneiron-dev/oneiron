//! Dev-safe and mock email adapters: config, inherent constructors, and trait impls.

use std::fmt;

use super::inbound_types::{
    ChannelIdentityProviderAdapter, ChannelIdentityProviderInbound,
    ChannelIdentityProviderProvision,
};
use super::shared_validate::{
    DEFAULT_EMAIL_LOCAL_PART_PREFIX, DEV_EMAIL_PROVIDER_KEY, EMAIL_CHANNEL, IDENTITY_HEX_LEN,
    SIGNATURE_HEX_BYTES, SIGNATURE_HEX_LEN, normalize_domain, normalize_email_address,
    normalize_local_part_prefix, split_email_address, validate_email_inbound_metadata,
    validate_non_blank, validate_provision_intent,
};
use crate::channel_identity::{
    ChannelIdentity, ChannelIdentityBinding, ChannelIdentityFulfillment, SelfHeldShape,
};
use crate::channel_identity_lifecycle::{ChannelIdentityLifecycleVerb, ProvisionIntent};
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};
use crate::surface_event::{InboundSurfaceEventInput, SurfaceCounterpartyStamp};

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
            SelfHeldShape::DedicatedAddress,
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
