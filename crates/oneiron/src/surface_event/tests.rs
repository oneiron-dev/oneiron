use super::*;
use crate::channel_identity::{
    CHANNEL_IDENTITY_MIN_QUARANTINE_SECS, ChannelIdentity, ChannelIdentityFulfillment,
    ChannelIdentityShape,
};
use crate::config::VaultConfig;
use crate::test_util::open_test_vault_with;

use crate::test_util::entity;

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
    let identity_ref = entity(0x60);
    let agent_ref = entity(0x51);
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
    let agent_ref = entity(0x52);
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
    let agent_ref = entity(0x53);
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
            entity(0x54),
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
    let requested_agent = entity(0x55);
    vault.create_channel_identity(
        &requested_ref,
        &identity(
            "requested@example.com",
            requested_agent,
            ChannelIdentityState::Requested,
        ),
    )?;

    let pending_ref = entity(0x16);
    let pending_agent = entity(0xD6);
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
fn routed_event_carries_closed_source_action_and_correlation_stamps() -> Result<()> {
    let (_dir, vault) = test_vault();
    let identity_ref = entity(0x18);
    let agent_ref = entity(0x58);
    vault.create_channel_identity(
        &identity_ref,
        &identity(
            "stamped@example.com",
            agent_ref,
            ChannelIdentityState::Active,
        ),
    )?;

    let receipt = vault.route_inbound_surface_event(input(
        "stamped@example.com",
        SurfaceCounterpartyStamp::unknown("email:sender@example.com"),
    ))?;

    let event = receipt.surface_event.expect("routed surface event");
    assert_eq!(event.schema_version, SURFACE_EVENT_SCHEMA_VERSION);
    assert_eq!(event.source.app, SurfaceSourceApp::Email);
    assert_eq!(event.source.user_ref, "email:sender@example.com");
    assert_eq!(event.action, SurfaceEventAction::Message);
    assert_eq!(event.correlation_id, "evt-stamped@example.com");
    assert_eq!(event.receiving_identity_ref, identity_ref.to_hex());
    assert_eq!(event.agent_ref, agent_ref.to_hex());
    assert!(event.claims_not_instructions);
    assert!(!event.identity_retiring);

    let encoded = serde_json::to_value(&event).expect("surface event serializes");
    assert_eq!(encoded["source"]["app"], "email");
    assert_eq!(encoded["action"]["kind"], "message");
    assert_eq!(encoded["correlation_id"], "evt-stamped@example.com");
    Ok(())
}

#[test]
fn source_app_round_trips_every_ruled_channel_key() {
    for (channel, app) in [
        ("email", SurfaceSourceApp::Email),
        ("slack", SurfaceSourceApp::Slack),
        ("discord", SurfaceSourceApp::Discord),
        ("web", SurfaceSourceApp::Web),
        ("voice", SurfaceSourceApp::Voice),
        ("imessage", SurfaceSourceApp::IMessage),
        ("line", SurfaceSourceApp::Line),
        ("telegram", SurfaceSourceApp::Telegram),
        ("linkedin", SurfaceSourceApp::LinkedIn),
    ] {
        assert_eq!(
            SurfaceSourceApp::from_channel_key(channel),
            Some(app),
            "{channel} must map to a closed source app"
        );
        let encoded = serde_json::to_value(app).expect("source app serializes");
        assert_eq!(
            encoded,
            serde_json::Value::from(channel),
            "{channel} wire spelling must equal its channel key"
        );
        let decoded: SurfaceSourceApp =
            serde_json::from_value(encoded).expect("source app deserializes");
        assert_eq!(decoded, app);
    }

    assert_eq!(SurfaceSourceApp::from_channel_key("carrier-pigeon"), None);
}

#[test]
fn interaction_actions_decode_and_route_to_observed_source_enrichment() {
    for (kind, wire) in [
        (SurfaceInteractionKind::Reaction, "reaction"),
        (SurfaceInteractionKind::CardCompletion, "card_completion"),
        (SurfaceInteractionKind::Dwell, "dwell"),
        (SurfaceInteractionKind::Tap, "tap"),
    ] {
        let action = SurfaceEventAction::Interaction {
            interaction: kind,
            target_ref: Some("msg-1".to_owned()),
        };
        let encoded = serde_json::to_value(&action).expect("action serializes");
        assert_eq!(encoded["kind"], "interaction");
        assert_eq!(encoded["interaction"], wire);
        assert_eq!(encoded["target_ref"], "msg-1");
        let decoded: SurfaceEventAction =
            serde_json::from_value(encoded).expect("action deserializes");
        assert_eq!(decoded, action);
        assert_eq!(
            action.dispatch_route(),
            SurfaceEventDispatchRoute::ObservedSourceEnrichment
        );
    }

    assert_eq!(
        SurfaceEventAction::Message.dispatch_route(),
        SurfaceEventDispatchRoute::ActorSelf
    );
}

#[test]
fn run_id_is_verbatim_under_the_cap_and_digested_above_it() {
    let short = "evt-provider-1";
    assert_eq!(surface_event_run_id(short), short);

    let boundary = "b".repeat(128);
    assert_eq!(surface_event_run_id(&boundary), boundary);

    let long = "c".repeat(129);
    let run_id = surface_event_run_id(&long);
    assert_eq!(run_id, surface_event_run_id(&long), "derivation is stable");
    assert_ne!(run_id, long);
    let digest = run_id
        .strip_prefix("sha256:")
        .expect("long provider ids fold to a sha256 run id");
    assert_eq!(digest.len(), 64);
    assert!(
        digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "digest must be lowercase hex: {digest}"
    );
    assert!(run_id.len() <= 128, "derived run id must fit the queue cap");
    assert_ne!(
        surface_event_run_id(&"d".repeat(129)),
        run_id,
        "distinct provider ids derive distinct run ids"
    );
}

#[test]
fn builders_override_the_defaults_new_derives() {
    let derived = input(
        "agent@example.com",
        SurfaceCounterpartyStamp::unknown("email:sender@example.com"),
    );
    assert_eq!(derived.source.app, SurfaceSourceApp::Email);
    assert_eq!(derived.source.user_ref, "email:sender@example.com");
    assert_eq!(derived.correlation_id, derived.event_id);
    assert_eq!(derived.action, SurfaceEventAction::Message);

    let overridden = derived
        .with_source(SurfaceEventSource::new(
            SurfaceSourceApp::Telegram,
            "telegram:user:77",
        ))
        .with_action(SurfaceEventAction::Interaction {
            interaction: SurfaceInteractionKind::Tap,
            target_ref: None,
        })
        .with_correlation_id("provider-correlation-9");
    assert_eq!(overridden.source.app, SurfaceSourceApp::Telegram);
    assert_eq!(overridden.source.user_ref, "telegram:user:77");
    assert_eq!(overridden.correlation_id, "provider-correlation-9");
    assert_ne!(overridden.correlation_id, overridden.event_id);
}

#[test]
fn blank_source_and_correlation_stamps_are_rejected() -> Result<()> {
    let (_dir, vault) = test_vault();
    vault.create_channel_identity(
        &entity(0x19),
        &identity(
            "blank@example.com",
            entity(0x59),
            ChannelIdentityState::Active,
        ),
    )?;

    let blank_correlation = input(
        "blank@example.com",
        SurfaceCounterpartyStamp::unknown("email:sender@example.com"),
    )
    .with_correlation_id("   ");
    assert!(
        vault
            .route_inbound_surface_event(blank_correlation)
            .is_err()
    );

    let blank_user_ref = input(
        "blank@example.com",
        SurfaceCounterpartyStamp::unknown("email:sender@example.com"),
    )
    .with_source(SurfaceEventSource::new(SurfaceSourceApp::Email, "  "));
    assert!(vault.route_inbound_surface_event(blank_user_ref).is_err());
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
