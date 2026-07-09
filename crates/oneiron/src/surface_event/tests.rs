use super::*;
use crate::channel_identity::{
    CHANNEL_IDENTITY_MIN_QUARANTINE_SECS, ChannelIdentity, ChannelIdentityFulfillment,
    ChannelIdentityShape,
};
use crate::config::VaultConfig;
use crate::test_util::open_test_vault_with;

fn entity(seed: u8) -> EntityId {
    EntityId::from_bytes([seed; 16]).expect("valid entity id")
}

fn test_vault() -> (tempfile::TempDir, Vault) {
    let mut cfg = VaultConfig::device();
    cfg.map_size = 16 * 1024 * 1024;
    cfg.dimensions = 4;
    cfg.embedding_model = None;
    open_test_vault_with(cfg)
}

fn identity(address: &str, agent_ref: EntityId, state: ChannelIdentityState) -> ChannelIdentity {
    let mut identity = ChannelIdentity::requested(
        "email",
        address,
        ChannelIdentityShape::DedicatedAddress,
        ChannelIdentityBinding::agent(agent_ref),
        1_800_000_000,
    );
    identity.state = state;
    identity.pending_fulfillment = None;
    identity.quarantine_until = None;
    if state == ChannelIdentityState::Quarantine {
        identity.quarantine_until =
            Some(identity.state_changed_at + CHANNEL_IDENTITY_MIN_QUARANTINE_SECS);
    }
    identity
}

fn input(address: &str, counterparty: SurfaceCounterpartyStamp) -> InboundSurfaceEventInput {
    InboundSurfaceEventInput::new(
        format!("evt-{address}"),
        "email",
        address,
        counterparty,
        1_800_000_123,
        true,
    )
    .with_payload_ref(format!("payload:{address}"))
}

#[test]
fn inbound_routes_active_identity_and_stamps_receiving_identity() -> Result<()> {
    let (_dir, vault) = test_vault();
    let identity_ref = entity(0x11);
    let agent_ref = entity(0xA1);
    vault.create_channel_identity(
        &identity_ref,
        &identity("agent@example.com", agent_ref, ChannelIdentityState::Active),
    )?;

    let receipt = vault.route_inbound_surface_event(input(
        "agent@example.com",
        SurfaceCounterpartyStamp::known(entity(0xC1)),
    ))?;

    assert_eq!(receipt.outcome, InboundSurfaceRouteOutcome::Routed);
    assert_eq!(receipt.receiving_identity_ref, Some(identity_ref.to_hex()));
    assert_eq!(receipt.agent_ref, Some(agent_ref.to_hex()));
    assert!(!receipt.identity_retiring);
    assert!(receipt.claims_not_instructions);
    let event = receipt.surface_event.expect("routed surface event");
    assert_eq!(event.receiving_identity_ref, identity_ref.to_hex());
    assert_eq!(event.agent_ref, agent_ref.to_hex());
    assert!(!event.identity_retiring);
    assert!(event.claims_not_instructions);
    Ok(())
}

#[test]
fn inbound_routes_quarantined_identity_for_known_and_unknown_counterparties() -> Result<()> {
    let (_dir, vault) = test_vault();
    let identity_ref = entity(0x12);
    let agent_ref = entity(0xA2);
    vault.create_channel_identity(
        &identity_ref,
        &identity(
            "retiring@example.com",
            agent_ref,
            ChannelIdentityState::Quarantine,
        ),
    )?;

    for counterparty in [
        SurfaceCounterpartyStamp::known(entity(0xC2)),
        SurfaceCounterpartyStamp::unknown("provider:user:unknown"),
    ] {
        let receipt =
            vault.route_inbound_surface_event(input("retiring@example.com", counterparty))?;

        assert_eq!(receipt.outcome, InboundSurfaceRouteOutcome::Routed);
        assert_eq!(receipt.receiving_identity_ref, Some(identity_ref.to_hex()));
        assert_eq!(receipt.agent_ref, Some(agent_ref.to_hex()));
        assert!(receipt.identity_retiring);
        assert!(receipt.claims_not_instructions);
        let event = receipt.surface_event.expect("quarantine still routes");
        assert!(event.identity_retiring);
        assert_eq!(event.receiving_identity_ref, identity_ref.to_hex());
    }
    Ok(())
}

#[test]
fn inbound_tombstone_rejects_with_receipt_for_known_and_unknown_counterparties() -> Result<()> {
    let (_dir, vault) = test_vault();
    let identity_ref = entity(0x13);
    let agent_ref = entity(0xA3);
    vault.create_channel_identity(
        &identity_ref,
        &identity(
            "dead@example.com",
            agent_ref,
            ChannelIdentityState::Tombstone,
        ),
    )?;

    for counterparty in [
        SurfaceCounterpartyStamp::known(entity(0xC3)),
        SurfaceCounterpartyStamp::unknown("provider:user:new"),
    ] {
        let receipt = vault.route_inbound_surface_event(input("dead@example.com", counterparty))?;

        assert_eq!(receipt.outcome, InboundSurfaceRouteOutcome::Rejected);
        assert_eq!(
            receipt.rejection_reason,
            Some(InboundSurfaceRejectionReason::TombstonedReceivingIdentity)
        );
        assert_eq!(receipt.receiving_identity_ref, Some(identity_ref.to_hex()));
        assert_eq!(receipt.agent_ref, Some(agent_ref.to_hex()));
        assert!(receipt.surface_event.is_none());
        assert!(receipt.claims_not_instructions);
    }
    Ok(())
}

#[test]
fn inbound_unknown_address_has_no_catch_all_route() -> Result<()> {
    let (_dir, vault) = test_vault();
    vault.create_channel_identity(
        &entity(0x14),
        &identity(
            "agent@example.com",
            entity(0xA4),
            ChannelIdentityState::Active,
        ),
    )?;

    let receipt = vault.route_inbound_surface_event(input(
        "not-agent@example.com",
        SurfaceCounterpartyStamp::unknown("provider:user:unknown"),
    ))?;

    assert_eq!(receipt.outcome, InboundSurfaceRouteOutcome::Rejected);
    assert_eq!(
        receipt.rejection_reason,
        Some(InboundSurfaceRejectionReason::UnknownReceivingIdentity)
    );
    assert!(receipt.receiving_identity_ref.is_none());
    assert!(receipt.agent_ref.is_none());
    assert!(receipt.surface_event.is_none());
    Ok(())
}

#[test]
fn inbound_requested_and_pending_fulfillment_reject_as_inactive() -> Result<()> {
    let (_dir, vault) = test_vault();

    let requested_ref = entity(0x15);
    let requested_agent = entity(0xA5);
    vault.create_channel_identity(
        &requested_ref,
        &identity(
            "requested@example.com",
            requested_agent,
            ChannelIdentityState::Requested,
        ),
    )?;

    let pending_ref = entity(0x16);
    let pending_agent = entity(0xA6);
    let mut pending = identity(
        "pending@example.com",
        pending_agent,
        ChannelIdentityState::PendingFulfillment,
    );
    pending.pending_fulfillment = Some(ChannelIdentityFulfillment::Manual);
    vault.create_channel_identity(&pending_ref, &pending)?;

    for (address, identity_ref, agent_ref) in [
        ("requested@example.com", requested_ref, requested_agent),
        ("pending@example.com", pending_ref, pending_agent),
    ] {
        let receipt = vault.route_inbound_surface_event(input(
            address,
            SurfaceCounterpartyStamp::known(entity(0xC5)),
        ))?;

        assert_eq!(receipt.outcome, InboundSurfaceRouteOutcome::Rejected);
        assert_eq!(
            receipt.rejection_reason,
            Some(InboundSurfaceRejectionReason::InactiveReceivingIdentity)
        );
        assert_eq!(receipt.receiving_identity_ref, Some(identity_ref.to_hex()));
        assert_eq!(receipt.agent_ref, Some(agent_ref.to_hex()));
        assert!(!receipt.identity_retiring);
        assert!(receipt.surface_event.is_none());
    }
    Ok(())
}

#[test]
fn inbound_vault_bound_identity_rejects_as_non_agent_bound() -> Result<()> {
    let (_dir, vault) = test_vault();
    let identity_ref = entity(0x17);
    let mut vault_bound = ChannelIdentity::requested(
        "email",
        "vault-bound@example.com",
        ChannelIdentityShape::DedicatedAddress,
        ChannelIdentityBinding::vault(7),
        1_800_000_000,
    );
    vault_bound.state = ChannelIdentityState::Active;
    vault.create_channel_identity(&identity_ref, &vault_bound)?;

    let receipt = vault.route_inbound_surface_event(input(
        "vault-bound@example.com",
        SurfaceCounterpartyStamp::known(entity(0xC7)),
    ))?;

    assert_eq!(receipt.outcome, InboundSurfaceRouteOutcome::Rejected);
    assert_eq!(
        receipt.rejection_reason,
        Some(InboundSurfaceRejectionReason::NonAgentBoundIdentity)
    );
    assert_eq!(receipt.receiving_identity_ref, Some(identity_ref.to_hex()));
    assert!(receipt.agent_ref.is_none());
    assert!(receipt.surface_event.is_none());
    Ok(())
}
