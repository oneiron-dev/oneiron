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

// ─── Ack-first handoff ───────────────────────────────────────────────────────

use crate::attempt_queue::AttemptQueue;
use std::cell::RefCell;

/// Test dispatcher: records every request it saw and replies with a scripted
/// disposition. Production worker wiring belongs to the surface-serving ticket.
#[derive(Default)]
struct FakeDispatcher {
    disposition: Option<SurfaceEventDispatchDisposition>,
    seen: RefCell<Vec<(String, String, SurfaceEventDispatchRoute)>>,
}

impl FakeDispatcher {
    fn new(disposition: SurfaceEventDispatchDisposition) -> Self {
        Self {
            disposition: Some(disposition),
            seen: RefCell::new(Vec::new()),
        }
    }

    fn calls(&self) -> usize {
        self.seen.borrow().len()
    }
}

impl SurfaceEventDispatcher for FakeDispatcher {
    fn dispatch(
        &self,
        request: SurfaceEventDispatchRequest<'_>,
    ) -> SurfaceEventDispatchDisposition {
        self.seen.borrow_mut().push((
            request.correlation_id.to_owned(),
            request.agent_ref.to_owned(),
            request.route,
        ));
        assert_eq!(
            request.idempotency_key, request.correlation_id,
            "downstream idempotency key is exactly the correlation id"
        );
        self.disposition
            .clone()
            .expect("fake dispatcher was scripted")
    }
}

fn admitting_vault(
    address: &str,
    seed: u8,
    agent_seed: u8,
) -> (tempfile::TempDir, Vault, EntityId) {
    let (dir, vault) = test_vault();
    let identity_ref = entity(seed);
    let agent_ref = entity(agent_seed);
    vault
        .create_channel_identity(
            &identity_ref,
            &identity(address, agent_ref, ChannelIdentityState::Active),
        )
        .expect("seed active identity");
    (dir, vault, agent_ref)
}

fn accepted(admission: SurfaceEventAdmission) -> SurfaceEventAck {
    match admission {
        SurfaceEventAdmission::Accepted(ack) => ack,
        SurfaceEventAdmission::Rejected(receipt) => {
            panic!("expected admission, got rejection {:?}", receipt.outcome)
        }
    }
}

#[test]
fn surface_event_ack_precedes_dispatch() -> Result<()> {
    let (_dir, vault, agent_ref) = admitting_vault("ack@example.com", 0x1A, 0x5A);
    let dispatcher = FakeDispatcher::new(SurfaceEventDispatchDisposition::Complete);

    let ack = accepted(vault.enqueue_inbound_surface_event(
        input(
            "ack@example.com",
            SurfaceCounterpartyStamp::unknown("email:sender@example.com"),
        ),
        1_800_000_500,
    )?);

    // The ack is durable and the dispatcher has not run.
    assert_eq!(dispatcher.calls(), 0);
    assert_eq!(ack.state, SurfaceEventHandoffState::Queued);
    assert!(!ack.replayed);
    assert_eq!(ack.correlation_id, "evt-ack@example.com");
    assert_eq!(ack.accepted_at, 1_800_000_500);
    assert_eq!(ack.attempt_ref.as_str().len(), 32);
    assert_eq!(
        ack.status_path,
        "/v1/core/surface-events/evt-ack%40example.com"
    );

    // The status path's resource is queryable immediately.
    let status = vault
        .surface_event_handoff_status(&ack.correlation_id)?
        .expect("committed attempt is readable");
    assert_eq!(status.attempt_ref, ack.attempt_ref);
    assert_eq!(status.state, SurfaceEventHandoffState::Queued);
    assert_eq!(status.attempt_count, 0);
    assert!(status.last_error.is_none());
    assert_eq!(status.created_at, 1_800_000_500);

    // Only then does a worker claim it and reach the dispatcher.
    let outcome = vault.dispatch_next_surface_event("test-worker", 1_800_000_600, &dispatcher)?;
    assert_eq!(dispatcher.calls(), 1);
    let SurfaceEventWorkerOutcome::Completed(completed) = outcome else {
        panic!("expected completion");
    };
    assert_eq!(completed.attempt_ref, ack.attempt_ref);
    assert_eq!(completed.state, SurfaceEventHandoffState::Completed);
    assert_eq!(
        dispatcher.seen.borrow()[0],
        (
            "evt-ack@example.com".to_owned(),
            agent_ref.to_hex(),
            SurfaceEventDispatchRoute::ActorSelf
        )
    );
    Ok(())
}

#[test]
fn surface_event_once_per_correlation_survives_terminal_state() -> Result<()> {
    let (_dir, vault, _) = admitting_vault("once@example.com", 0x1B, 0x5B);
    let submit = |now| {
        vault.enqueue_inbound_surface_event(
            input(
                "once@example.com",
                SurfaceCounterpartyStamp::unknown("email:sender@example.com"),
            ),
            now,
        )
    };

    let first = accepted(submit(1_800_001_000)?);
    assert!(!first.replayed);
    assert_eq!(first.accepted_at, 1_800_001_000);

    // Concurrent-shaped resubmission before any worker runs.
    let second = accepted(submit(1_800_001_001)?);
    assert!(second.replayed);
    assert_eq!(second.attempt_ref, first.attempt_ref);
    assert_eq!(surface_event_attempt_rows(&vault), 1);
    // A replay admitted nothing, so it is dated by the admission it found,
    // not by its own clock.
    assert_eq!(second.accepted_at, first.accepted_at);

    // Replay after a terminal completion.
    let dispatcher = FakeDispatcher::new(SurfaceEventDispatchDisposition::Complete);
    vault.dispatch_next_surface_event("test-worker", 1_800_001_100, &dispatcher)?;
    let after_complete = accepted(submit(1_800_001_200)?);
    assert!(after_complete.replayed);
    assert_eq!(after_complete.attempt_ref, first.attempt_ref);
    assert_eq!(after_complete.state, SurfaceEventHandoffState::Completed);
    assert_eq!(surface_event_attempt_rows(&vault), 1);
    assert_eq!(after_complete.accepted_at, first.accepted_at);

    // The ack and the status snapshot describe one attempt, so their
    // admission timestamps cannot disagree.
    let status = vault
        .surface_event_handoff_status(&first.correlation_id)?
        .expect("admitted correlation id has a status snapshot");
    assert_eq!(status.created_at, after_complete.accepted_at);

    // A replay never re-offers the row to a worker.
    let replay_dispatcher = FakeDispatcher::new(SurfaceEventDispatchDisposition::Complete);
    assert_eq!(
        vault.dispatch_next_surface_event("test-worker", 1_800_001_300, &replay_dispatcher)?,
        SurfaceEventWorkerOutcome::Empty
    );
    assert_eq!(replay_dispatcher.calls(), 0);

    Ok(())
}

#[test]
fn concurrent_submissions_of_one_correlation_id_produce_one_attempt() -> Result<()> {
    let (_dir, vault, _) = admitting_vault("race@example.com", 0x25, 0x65);
    let submit = || {
        vault.enqueue_inbound_surface_event(
            input(
                "race@example.com",
                SurfaceCounterpartyStamp::unknown("email:sender@example.com"),
            ),
            1_800_008_000,
        )
    };

    // Real threads on one vault: LMDB serializes the writers, and the loser
    // must observe the winner's row rather than inserting a second one.
    let (first, second) = std::thread::scope(|scope| {
        let left = scope.spawn(submit);
        let right = scope.spawn(submit);
        (
            left.join().expect("left submitter"),
            right.join().expect("right submitter"),
        )
    });

    let first = accepted(first?);
    let second = accepted(second?);
    assert_eq!(
        first.attempt_ref, second.attempt_ref,
        "both submitters resolve to one durable attempt"
    );
    assert_ne!(
        first.replayed, second.replayed,
        "exactly one submitter created the row"
    );
    assert_eq!(surface_event_attempt_rows(&vault), 1);
    Ok(())
}

#[test]
fn surface_event_failure_is_queryable() -> Result<()> {
    let (_dir, vault, _) = admitting_vault("fail@example.com", 0x1C, 0x5C);
    let ack = accepted(vault.enqueue_inbound_surface_event(
        input(
            "fail@example.com",
            SurfaceCounterpartyStamp::unknown("email:sender@example.com"),
        ),
        1_800_002_000,
    )?);

    let dispatcher = FakeDispatcher::new(SurfaceEventDispatchDisposition::Fail {
        reason: "downstream refused".to_owned(),
    });
    let SurfaceEventWorkerOutcome::Failed(failed) =
        vault.dispatch_next_surface_event("test-worker", 1_800_002_100, &dispatcher)?
    else {
        panic!("expected terminal failure");
    };
    assert_eq!(failed.state, SurfaceEventHandoffState::Failed);
    assert_eq!(failed.last_error.as_deref(), Some("downstream refused"));

    let status = vault
        .surface_event_handoff_status(&ack.correlation_id)?
        .expect("failed attempt stays queryable");
    assert_eq!(status.state, SurfaceEventHandoffState::Failed);
    assert_eq!(status.last_error.as_deref(), Some("downstream refused"));
    assert_eq!(status.attempt_ref, ack.attempt_ref);
    assert_eq!(status.attempt_count, 1);
    assert_eq!(status.updated_at, 1_800_002_100);

    // Replay after a terminal failure derives the same attempt.
    let replayed = accepted(vault.enqueue_inbound_surface_event(
        input(
            "fail@example.com",
            SurfaceCounterpartyStamp::unknown("email:sender@example.com"),
        ),
        1_800_002_200,
    )?);
    assert!(replayed.replayed);
    assert_eq!(replayed.attempt_ref, ack.attempt_ref);
    assert_eq!(replayed.state, SurfaceEventHandoffState::Failed);
    assert_eq!(surface_event_attempt_rows(&vault), 1);
    Ok(())
}

#[test]
fn surface_event_retry_reuses_attempt() -> Result<()> {
    let (_dir, vault, _) = admitting_vault("retry@example.com", 0x1D, 0x5D);
    let ack = accepted(vault.enqueue_inbound_surface_event(
        input(
            "retry@example.com",
            SurfaceCounterpartyStamp::unknown("email:sender@example.com"),
        ),
        1_800_003_000,
    )?);
    let payload_before = sole_attempt(&vault).payload;

    let retrying = FakeDispatcher::new(SurfaceEventDispatchDisposition::Retry {
        backoff_until: 1_800_003_050,
        reason: "downstream busy".to_owned(),
    });
    let SurfaceEventWorkerOutcome::Retried(retried) =
        vault.dispatch_next_surface_event("test-worker", 1_800_003_100, &retrying)?
    else {
        panic!("expected retry");
    };
    assert_eq!(retried.attempt_ref, ack.attempt_ref);
    assert_eq!(retried.state, SurfaceEventHandoffState::Queued);
    assert_eq!(retried.last_error.as_deref(), Some("downstream busy"));
    assert_eq!(surface_event_attempt_rows(&vault), 1);

    // The row keeps its payload, correlation id, and downstream key.
    let row = sole_attempt(&vault);
    assert_eq!(row.payload, payload_before);
    assert_eq!(row.dedupe_key.as_deref(), Some("evt-retry@example.com"));
    assert_eq!(row.run_id.as_deref(), Some("evt-retry@example.com"));
    let decoded = decode_surface_event_attempt_payload(&row.payload)?;
    assert_eq!(decoded.dispatch_idempotency_key, "evt-retry@example.com");
    assert_eq!(decoded.event.correlation_id, "evt-retry@example.com");

    // The second attempt completes the same row.
    let completing = FakeDispatcher::new(SurfaceEventDispatchDisposition::Complete);
    let SurfaceEventWorkerOutcome::Completed(completed) =
        vault.dispatch_next_surface_event("test-worker", 1_800_003_200, &completing)?
    else {
        panic!("expected completion after retry");
    };
    assert_eq!(completed.attempt_ref, ack.attempt_ref);
    assert_eq!(completed.attempt_count, 2);
    assert_eq!(surface_event_attempt_rows(&vault), 1);
    Ok(())
}

#[test]
fn surface_event_interaction_never_creates_turn() -> Result<()> {
    let (_dir, vault, _) = admitting_vault("react@example.com", 0x1E, 0x5E);
    let turns_before = vault.count_entities_by_type(crate::registry::ENTITY_TYPE_TURN)?;

    for (index, interaction) in [
        SurfaceInteractionKind::Reaction,
        SurfaceInteractionKind::CardCompletion,
        SurfaceInteractionKind::Dwell,
        SurfaceInteractionKind::Tap,
    ]
    .into_iter()
    .enumerate()
    {
        let ack = accepted(
            vault.enqueue_inbound_surface_event(
                input(
                    "react@example.com",
                    SurfaceCounterpartyStamp::unknown("email:sender@example.com"),
                )
                .with_correlation_id(format!("interaction-{index}"))
                .with_action(SurfaceEventAction::Interaction {
                    interaction,
                    target_ref: Some("msg-1".to_owned()),
                }),
                1_800_004_000 + index as u64,
            )?,
        );

        let row = vault
            .surface_event_handoff_status(&ack.correlation_id)?
            .expect("interaction is admitted like any other event");
        assert_eq!(row.state, SurfaceEventHandoffState::Queued);

        let dispatcher = FakeDispatcher::new(SurfaceEventDispatchDisposition::Complete);
        vault.dispatch_next_surface_event("test-worker", 1_800_004_100, &dispatcher)?;
        assert_eq!(
            dispatcher.seen.borrow()[0].2,
            SurfaceEventDispatchRoute::ObservedSourceEnrichment,
            "{interaction:?} must normalize into observed-source enrichment"
        );
    }

    // No interaction synthesized or requested a TURN.
    assert_eq!(
        vault.count_entities_by_type(crate::registry::ENTITY_TYPE_TURN)?,
        turns_before
    );
    Ok(())
}

#[test]
fn long_provider_correlation_id_is_admitted_under_a_digested_run_id() -> Result<()> {
    let (_dir, vault, _) = admitting_vault("long@example.com", 0x1F, 0x5F);
    let correlation_id = format!("provider-{}", "z".repeat(200));
    let submit = |now| {
        vault.enqueue_inbound_surface_event(
            input(
                "long@example.com",
                SurfaceCounterpartyStamp::unknown("email:sender@example.com"),
            )
            .with_correlation_id(correlation_id.clone()),
            now,
        )
    };

    let ack = accepted(submit(1_800_005_000)?);
    assert_eq!(ack.correlation_id, correlation_id);
    assert!(!ack.replayed);

    let row = sole_attempt(&vault);
    let expected_run_id = surface_event_run_id(&correlation_id);
    assert!(expected_run_id.starts_with("sha256:"));
    assert_eq!(row.run_id.as_deref(), Some(expected_run_id.as_str()));
    // Both queue indexes are keyed by the one bounded derivation.
    assert_eq!(row.dedupe_key.as_deref(), Some(expected_run_id.as_str()));

    // Replay derives the same attempt rather than rejecting on length.
    let replayed = accepted(submit(1_800_005_100)?);
    assert!(replayed.replayed);
    assert_eq!(replayed.attempt_ref, ack.attempt_ref);
    assert_eq!(surface_event_attempt_rows(&vault), 1);

    let status = vault
        .surface_event_handoff_status(&correlation_id)?
        .expect("long correlation ids stay queryable by their public id");
    assert_eq!(status.attempt_ref, ack.attempt_ref);
    Ok(())
}

#[test]
fn correlation_id_beyond_the_dedupe_cap_is_admitted_and_replays_once() -> Result<()> {
    let (_dir, vault, _) = admitting_vault("oversize@example.com", 0x27, 0x67);
    // Past the queue's 512-byte dedupe-key cap. Keying dedupe on the raw
    // provider id rejected this outright, contradicting the ruling that a long
    // provider id is admitted under a derived key.
    let correlation_id = format!("provider-{}", "q".repeat(600));
    assert!(correlation_id.len() > 512);
    let submit = |now| {
        vault.enqueue_inbound_surface_event(
            input(
                "oversize@example.com",
                SurfaceCounterpartyStamp::unknown("email:sender@example.com"),
            )
            .with_correlation_id(correlation_id.clone()),
            now,
        )
    };

    let ack = accepted(submit(1_800_010_000)?);
    assert_eq!(ack.correlation_id, correlation_id);
    assert!(!ack.replayed);
    assert_eq!(ack.state, SurfaceEventHandoffState::Queued);

    // One bounded derivation keys both the run index and the dedupe index.
    let row = sole_attempt(&vault);
    let expected_key = surface_event_run_id(&correlation_id);
    assert!(expected_key.starts_with("sha256:"));
    assert!(expected_key.len() <= 128);
    assert_eq!(row.run_id.as_deref(), Some(expected_key.as_str()));
    assert_eq!(row.dedupe_key.as_deref(), Some(expected_key.as_str()));

    // The raw provider id survives verbatim on the durable envelope and on the
    // downstream idempotency key.
    let decoded = decode_surface_event_attempt_payload(&row.payload)?;
    assert_eq!(decoded.event.correlation_id, correlation_id);
    assert_eq!(decoded.dispatch_idempotency_key, correlation_id);

    // A duplicate submission observes exactly one admission.
    let replayed = accepted(submit(1_800_010_100)?);
    assert!(replayed.replayed);
    assert_eq!(replayed.attempt_ref, ack.attempt_ref);
    assert_eq!(surface_event_attempt_rows(&vault), 1);

    let status = vault
        .surface_event_handoff_status(&correlation_id)?
        .expect("oversized correlation ids stay queryable by their public id");
    assert_eq!(status.attempt_ref, ack.attempt_ref);
    Ok(())
}

#[test]
fn unruled_channel_key_is_refused_before_a_source_app_is_stamped() -> Result<()> {
    let (_dir, vault) = test_vault();
    let identity_ref = entity(0x26);
    let agent_ref = entity(0x66);
    // ChannelIdentity admits any nonempty channel string, so an ACTIVE identity
    // on a key outside the ruled nine is a reachable shape.
    let mut unruled = ChannelIdentity::requested(
        "carrier-pigeon",
        "coop@example.com",
        ChannelIdentityShape::DedicatedAddress,
        ChannelIdentityBinding::agent(agent_ref),
        1_800_000_000,
    );
    unruled.state = ChannelIdentityState::Active;
    unruled.pending_fulfillment = None;
    vault.create_channel_identity(&identity_ref, &unruled)?;

    let inbound = InboundSurfaceEventInput::new(
        "evt-pigeon-1",
        "carrier-pigeon",
        "coop@example.com",
        SurfaceCounterpartyStamp::unknown("pigeon:sender:1"),
        1_800_009_000,
        true,
    );
    // The derived stamp would have been a plausible lie, durably.
    assert_eq!(inbound.source.app, SurfaceSourceApp::Web);

    let error = vault
        .route_inbound_surface_event(inbound.clone())
        .expect_err("an unruled channel key must never stamp a source app");
    assert!(
        error.to_string().contains("carrier-pigeon"),
        "rejection must name the offending channel key: {error}"
    );

    // Admission fails the same way, and queues nothing.
    let error = vault
        .enqueue_inbound_surface_event(inbound.clone(), 1_800_009_100)
        .expect_err("admission inherits the routing refusal");
    assert!(error.to_string().contains("carrier-pigeon"), "{error}");
    assert_eq!(surface_event_attempt_rows(&vault), 0);

    // An explicit source override buys nothing: the closed enum has no variant
    // that could honestly name this channel.
    assert!(
        vault
            .enqueue_inbound_surface_event(
                inbound.with_source(SurfaceEventSource::new(
                    SurfaceSourceApp::Web,
                    "pigeon:sender:1",
                )),
                1_800_009_200,
            )
            .is_err()
    );
    assert_eq!(surface_event_attempt_rows(&vault), 0);
    Ok(())
}

#[test]
fn identity_rejections_never_enqueue() -> Result<()> {
    let (_dir, vault) = test_vault();

    // Unknown receiving identity.
    vault.create_channel_identity(
        &entity(0x20),
        &identity(
            "known@example.com",
            entity(0x61),
            ChannelIdentityState::Active,
        ),
    )?;
    // Non-agent-bound identity.
    let mut vault_bound = ChannelIdentity::requested(
        "email",
        "vault-bound@example.com",
        ChannelIdentityShape::DedicatedAddress,
        ChannelIdentityBinding::vault(7),
        1_800_000_000,
    );
    vault_bound.state = ChannelIdentityState::Active;
    vault.create_channel_identity(&entity(0x21), &vault_bound)?;
    // Inactive + tombstoned identities.
    vault.create_channel_identity(
        &entity(0x22),
        &identity(
            "requested@example.com",
            entity(0x62),
            ChannelIdentityState::Requested,
        ),
    )?;
    vault.create_channel_identity(
        &entity(0x23),
        &identity(
            "dead@example.com",
            entity(0x63),
            ChannelIdentityState::Tombstone,
        ),
    )?;

    for (address, reason) in [
        (
            "missing@example.com",
            InboundSurfaceRejectionReason::UnknownReceivingIdentity,
        ),
        (
            "vault-bound@example.com",
            InboundSurfaceRejectionReason::NonAgentBoundIdentity,
        ),
        (
            "requested@example.com",
            InboundSurfaceRejectionReason::InactiveReceivingIdentity,
        ),
        (
            "dead@example.com",
            InboundSurfaceRejectionReason::TombstonedReceivingIdentity,
        ),
    ] {
        let admission = vault.enqueue_inbound_surface_event(
            input(
                address,
                SurfaceCounterpartyStamp::unknown("email:sender@example.com"),
            ),
            1_800_006_000,
        )?;
        let SurfaceEventAdmission::Rejected(receipt) = admission else {
            panic!("{address} must not be admitted");
        };
        assert_eq!(receipt.outcome, InboundSurfaceRouteOutcome::Rejected);
        assert_eq!(receipt.rejection_reason, Some(reason));
        assert!(receipt.surface_event.is_none());
    }

    assert_eq!(surface_event_attempt_rows(&vault), 0);
    Ok(())
}

#[test]
fn foreign_correlation_kind_collision_is_typed_not_silent() -> Result<()> {
    let (_dir, vault, _) = admitting_vault("collide@example.com", 0x24, 0x64);

    // Another subsystem already owns this run id under its own kind.
    AttemptQueue::new(&vault).enqueue(crate::attempt_queue::EnqueueAttempt {
        kind: "some.other.kind.v1".to_owned(),
        payload: b"other".to_vec(),
        dedupe_key: Some("evt-collide@example.com".to_owned()),
        run_id: Some("evt-collide@example.com".to_owned()),
        now: 1_800_007_000,
    })?;

    let error = vault
        .enqueue_inbound_surface_event(
            input(
                "collide@example.com",
                SurfaceCounterpartyStamp::unknown("email:sender@example.com"),
            ),
            1_800_007_100,
        )
        .expect_err("a foreign kind on the same correlation id is a typed collision");
    assert!(
        error.to_string().contains("another attempt kind"),
        "collision must name the cause: {error}"
    );
    assert_eq!(surface_event_attempt_rows(&vault), 0);

    // The status read fails closed the same way rather than reporting the
    // foreign row as this event's handoff.
    assert!(
        vault
            .surface_event_handoff_status("evt-collide@example.com")
            .is_err()
    );
    Ok(())
}

fn surface_event_attempt_rows(vault: &Vault) -> usize {
    AttemptQueue::new(vault)
        .list()
        .expect("attempt rows readable")
        .into_iter()
        .filter(|record| record.kind == SURFACE_EVENT_ATTEMPT_KIND)
        .count()
}

fn sole_attempt(vault: &Vault) -> crate::attempt_queue::AttemptRecord {
    let mut rows = AttemptQueue::new(vault)
        .list()
        .expect("attempt rows readable")
        .into_iter()
        .filter(|record| record.kind == SURFACE_EVENT_ATTEMPT_KIND)
        .collect::<Vec<_>>();
    assert_eq!(rows.len(), 1, "expected exactly one surface-event attempt");
    rows.pop().expect("one row")
}
