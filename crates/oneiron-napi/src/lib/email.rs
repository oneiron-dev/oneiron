//! Email identity adapter conversion and inbound surface-event parsing.

use napi::bindgen_prelude::*;
use napi_derive::napi;
use oneiron::{
    ChannelIdentityProviderAdapter, ChannelIdentityProviderInbound, DevEmailIdentityAdapter,
    DevEmailIdentityAdapterConfig, EmailProviderInbound,
};

use super::boundary::{parse_entity_id, to_napi_err, ts_to_u64};
use super::types::{NapiEmailIdentityAdapterConfig, NapiEmailInboundEvent};

pub(super) fn core_email_adapter(
    input: NapiEmailIdentityAdapterConfig,
) -> napi::Result<DevEmailIdentityAdapter> {
    let config = match input.local_part_prefix {
        Some(prefix) => {
            DevEmailIdentityAdapterConfig::with_prefix(input.domain, prefix, input.signing_secret)
        }
        None => DevEmailIdentityAdapterConfig::new(input.domain, input.signing_secret),
    }
    .map_err(to_napi_err)?;
    Ok(DevEmailIdentityAdapter::new(config))
}

pub(super) fn core_email_inbound(input: NapiEmailInboundEvent) -> EmailProviderInbound {
    let inbound = EmailProviderInbound::new(
        input.provider_event_id,
        input.envelope_to,
        input.envelope_from,
        ts_to_u64(input.received_at),
    );
    if let Some(payload_ref) = input.payload_ref {
        inbound.with_payload_ref(payload_ref)
    } else {
        inbound
    }
}

/// Derive the deterministic per-identity email address for a ChannelIdentity.
#[napi]
pub fn channel_identity_email_address(
    identity_id: Buffer,
    agent_ref: Buffer,
    config: NapiEmailIdentityAdapterConfig,
    requested_at: Option<i64>,
) -> napi::Result<String> {
    let identity_id = parse_entity_id(&identity_id)?;
    let agent_ref = parse_entity_id(&agent_ref)?;
    let adapter = core_email_adapter(config)?;
    let requested_at = requested_at.map_or(0, ts_to_u64);
    Ok(adapter
        .requested_identity(identity_id, agent_ref, requested_at)
        .address_or_handle)
}

/// Parse inbound email webhook data into a SurfaceEvent input JSON string.
#[napi]
pub fn parse_email_inbound_surface_event(
    config: NapiEmailIdentityAdapterConfig,
    inbound: NapiEmailInboundEvent,
) -> napi::Result<String> {
    let adapter = core_email_adapter(config)?;
    let input = adapter
        .parse_inbound(ChannelIdentityProviderInbound::Email(core_email_inbound(
            inbound,
        )))
        .map_err(to_napi_err)?;
    serde_json::to_string(&input)
        .map_err(|e| napi::Error::from_reason(format!("surface event input json: {e}")))
}
