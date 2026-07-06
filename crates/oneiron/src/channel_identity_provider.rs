//! Provider-adapter seam for ChannelIdentity fulfillment (OF-347 CID-3).
//!
//! The engine emits CID-2 lifecycle intents through the ExternalEffect door.
//! Host-side adapters consume those intents, fulfill provider work, and report
//! the resulting state transition back through the CID-2 fulfillment path.

use std::fmt;

use serde::{Deserialize, Serialize};

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

/// Stable channel key for email identities.
pub const EMAIL_CHANNEL: &str = "email";

/// Default deterministic local-part prefix for dev-safe email identities.
pub const DEFAULT_EMAIL_LOCAL_PART_PREFIX: &str = "agent";

const SIGNATURE_HEX_BYTES: usize = 6;
const SIGNATURE_HEX_LEN: usize = SIGNATURE_HEX_BYTES * 2;
const MAX_EMAIL_ADDRESS_BYTES: usize = 254;
const MAX_EMAIL_LOCAL_PART_BYTES: usize = 64;
const MAX_EMAIL_DOMAIN_BYTES: usize = 253;
const MAX_EMAIL_PROVIDER_EVENT_ID_BYTES: usize = 128;
const MAX_EMAIL_PAYLOAD_REF_BYTES: usize = 512;
const IDENTITY_HEX_LEN: usize = 32;
const LOCAL_PART_SEPARATOR_BYTES: usize = 2;
const MAX_LOCAL_PART_PREFIX_BYTES: usize =
    MAX_EMAIL_LOCAL_PART_BYTES - IDENTITY_HEX_LEN - SIGNATURE_HEX_LEN - LOCAL_PART_SEPARATOR_BYTES;

/// Provider-normalized inbound payload before engine routing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "channel", rename_all = "snake_case")]
#[non_exhaustive]
pub enum ChannelIdentityProviderInbound {
    Email(EmailProviderInbound),
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
        let ChannelIdentityProviderInbound::Email(email) = inbound;
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
        let ChannelIdentityProviderInbound::Email(email) = inbound;
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

    fn entity(seed: u8) -> EntityId {
        EntityId::from_bytes([seed; 16]).expect("valid test id")
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
}
