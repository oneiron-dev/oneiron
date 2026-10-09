use super::handoff::{SurfaceEventKey, surface_event_dedupe_key};
use super::*;
use crate::channel_identity::{ChannelIdentity, SelfHeldShape};
use crate::config::VaultConfig;
use crate::test_util::open_test_vault_with;

use crate::test_util::entity;
use std::collections::HashSet;

fn test_vault() -> (tempfile::TempDir, Vault) {
    test_vault_with_clock(crate::ports::StoreClock::default())
}
fn test_vault_with_clock(clock: crate::ports::StoreClock) -> (tempfile::TempDir, Vault) {
    let mut cfg = VaultConfig::device();
    cfg.store_clock = clock;
    cfg.map_size = 16 * 1024 * 1024;
    cfg.dimensions = 4;
    cfg.embedding_model = None;
    open_test_vault_with(cfg)
}

fn subject_owner(vault: &Vault) -> Result<crate::write_envelope::WriteActor> {
    let owner = seed(vault, entity(0xE0), crate::registry::ENTITY_TYPE_PERSON);
    let writer = crate::write_envelope::WriteActor::new(owner, crate::edge::EdgeActorClass::Human);
    // Signed genesis and a live owner binding, not an Agent capability exemption.
    crate::subject_model::tests::authorization::root_owner(vault, writer, 0xE0)?;
    Ok(writer)
}

fn identity(address: &str, agent_ref: EntityId, state: ChannelIdentityState) -> ChannelIdentity {
    identity_bound(address, ChannelIdentityBinding::agent(agent_ref), state)
}

/// [`identity`] on an arbitrary binding: the masked, unmasked, and vault-bound
/// cases the router answers differently.
fn identity_bound(
    address: &str,
    binding: ChannelIdentityBinding,
    state: ChannelIdentityState,
) -> ChannelIdentity {
    identity_on_channel("email", address, binding, state)
}

/// [`identity_bound`] on an arbitrary channel key, including one outside the
/// ruled set.
fn identity_on_channel(
    channel: &str,
    address: &str,
    binding: ChannelIdentityBinding,
    state: ChannelIdentityState,
) -> ChannelIdentity {
    crate::test_util::self_held_identity_in_state(
        channel,
        address,
        SelfHeldShape::DedicatedAddress,
        binding,
        state,
        1_800_000_000,
    )
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
fn surface_event_dedupe_key_uses_all_tuple_fields_without_boundary_collisions() {
    let key = |channel, receiving, correlation_id| {
        surface_event_dedupe_key(SurfaceEventKey {
            channel,
            receiving,
            correlation_id,
        })
    };
    let base = key("email", "identity-1", "provider-id");

    assert!(base.starts_with("sev:v2:"));
    assert_eq!(base.len(), "sev:v2:".len() + 64);
    assert_ne!(base, key("slack", "identity-1", "provider-id"));
    assert_ne!(base, key("email", "identity-2", "provider-id"));
    assert_ne!(base, key("email", "identity-1", "other-id"));
    assert_ne!(
        key("email\0identity", "other", "provider-id"),
        key("email", "identity\0other", "provider-id"),
        "length framing distinguishes NUL-containing tuple members"
    );
}

// ─── Ack-first handoff ───────────────────────────────────────────────────────

use crate::attempt_queue::AttemptQueue;
use crate::error::RegistryError;
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
        let expected_idempotency_key = surface_event_dedupe_key(SurfaceEventKey {
            channel: &request.event.channel,
            receiving: &request.event.receiving_identity_ref,
            correlation_id: request.correlation_id,
        });
        assert_eq!(request.idempotency_key, expected_idempotency_key);
        self.disposition
            .clone()
            .expect("fake dispatcher was scripted")
    }
}

/// Test dispatcher that models a downstream service which accepts each
/// idempotency key only once.
#[derive(Default)]
struct IdempotentDispatcher {
    seen_keys: RefCell<HashSet<String>>,
    delivered_keys: RefCell<Vec<String>>,
}

impl SurfaceEventDispatcher for IdempotentDispatcher {
    fn dispatch(
        &self,
        request: SurfaceEventDispatchRequest<'_>,
    ) -> SurfaceEventDispatchDisposition {
        let key = request.idempotency_key.to_owned();
        if self.seen_keys.borrow_mut().insert(key.clone()) {
            self.delivered_keys.borrow_mut().push(key);
        }
        SurfaceEventDispatchDisposition::Complete
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

fn timed_admitting_vault(
    address: &str,
    seed: u8,
    agent_seed: u8,
    now: u64,
) -> (
    tempfile::TempDir,
    Vault,
    EntityId,
    std::sync::Arc<crate::ports::ManualClock>,
) {
    let clock = crate::ports::ManualClock::new(now);
    let (dir, vault) = test_vault_with_clock(clock.bundle());
    let agent = entity(agent_seed);
    vault
        .create_channel_identity(
            &entity(seed),
            &identity(address, agent, ChannelIdentityState::Active),
        )
        .expect("seed active identity");
    (dir, vault, agent, clock)
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
    let (_dir, vault, agent_ref, clock) =
        timed_admitting_vault("ack@example.com", 0x1A, 0x5A, 1_800_000_500);
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
    let outcome = vault.dispatch_next_surface_event(
        "test-worker",
        {
            clock.set(1_800_000_600);
            1_800_000_600
        },
        &dispatcher,
    )?;
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
    let (_dir, vault, _, clock) =
        timed_admitting_vault("once@example.com", 0x1B, 0x5B, 1_800_001_000);
    let submit = |now| {
        clock.set(now);
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
    vault.dispatch_next_surface_event(
        "test-worker",
        {
            clock.set(1_800_001_100);
            1_800_001_100
        },
        &dispatcher,
    )?;
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
        vault.dispatch_next_surface_event(
            "test-worker",
            {
                clock.set(1_800_001_300);
                1_800_001_300
            },
            &replay_dispatcher
        )?,
        SurfaceEventWorkerOutcome::Empty
    );
    assert_eq!(replay_dispatcher.calls(), 0);

    Ok(())
}

#[test]
fn reused_correlation_id_on_another_receiving_identity_is_admitted() -> Result<()> {
    let (_dir, vault, _) = admitting_vault("first@example.com", 0x82, 0x83);
    let second_identity_ref = entity(0x84);
    vault.create_channel_identity(
        &second_identity_ref,
        &identity(
            "second@example.com",
            entity(0x85),
            ChannelIdentityState::Active,
        ),
    )?;

    let correlation_id = "provider-reused-id";
    let first = accepted(
        vault.enqueue_inbound_surface_event(
            input(
                "first@example.com",
                SurfaceCounterpartyStamp::unknown("email:sender@example.com"),
            )
            .with_correlation_id(correlation_id),
            1_800_001_500,
        )?,
    );
    let second = accepted(
        vault.enqueue_inbound_surface_event(
            input(
                "second@example.com",
                SurfaceCounterpartyStamp::unknown("email:sender@example.com"),
            )
            .with_correlation_id(correlation_id),
            1_800_001_501,
        )?,
    );

    assert!(!first.replayed);
    assert!(
        !second.replayed,
        "another receiving identity is not a replay"
    );
    assert_ne!(first.attempt_ref, second.attempt_ref);
    assert_eq!(surface_event_attempt_rows(&vault), 2);

    let records = AttemptQueue::new(&vault).list()?;
    let rows = records
        .iter()
        .filter(|record| record.kind == SURFACE_EVENT_ATTEMPT_KIND)
        .collect::<Vec<_>>();
    assert_eq!(rows.len(), 2);
    let expected_run_id = surface_event_run_id(correlation_id);
    assert!(
        rows.iter()
            .all(|row| row.run_id.as_deref() == Some(expected_run_id.as_str()))
    );
    assert_ne!(rows[0].dedupe_key, rows[1].dedupe_key);

    // Same tuple still replays to its own row after another identity has used
    // the same public correlation id.
    let first_replay = accepted(
        vault.enqueue_inbound_surface_event(
            input(
                "first@example.com",
                SurfaceCounterpartyStamp::unknown("email:sender@example.com"),
            )
            .with_correlation_id(correlation_id),
            1_800_001_502,
        )?,
    );
    assert!(first_replay.replayed);
    assert_eq!(first_replay.attempt_ref, first.attempt_ref);
    assert_eq!(surface_event_attempt_rows(&vault), 2);

    // The public status route remains correlation-only and therefore fails
    // closed when that id names more than one admitted identity tuple.
    assert!(matches!(
        vault.surface_event_handoff_status(correlation_id),
        Err(Error::CorruptedIndex("surface event correlation run"))
    ));
    Ok(())
}

#[test]
fn reused_correlation_id_delivers_once_per_receiving_identity() -> Result<()> {
    let (_dir, vault, _) = admitting_vault("first@example.com", 0x86, 0x87);
    let second_identity_ref = entity(0x88);
    vault.create_channel_identity(
        &second_identity_ref,
        &identity(
            "second@example.com",
            entity(0x89),
            ChannelIdentityState::Active,
        ),
    )?;

    let correlation_id = "provider-shared-id";
    let first = accepted(
        vault.enqueue_inbound_surface_event(
            input(
                "first@example.com",
                SurfaceCounterpartyStamp::unknown("email:sender@example.com"),
            )
            .with_correlation_id(correlation_id),
            1_800_001_600,
        )?,
    );
    let second = accepted(
        vault.enqueue_inbound_surface_event(
            input(
                "second@example.com",
                SurfaceCounterpartyStamp::unknown("email:sender@example.com"),
            )
            .with_correlation_id(correlation_id),
            1_800_001_601,
        )?,
    );
    assert!(!first.replayed);
    assert!(!second.replayed);
    assert_ne!(first.attempt_ref, second.attempt_ref);

    let dispatcher = IdempotentDispatcher::default();
    for _ in 0..2 {
        assert!(matches!(
            vault.dispatch_next_surface_event("test-worker", 1_800_001_700, &dispatcher)?,
            SurfaceEventWorkerOutcome::Completed(_)
        ));
    }

    // The simulated downstream deduplicates by key. Both receiving identities
    // must therefore carry distinct keys or one accepted event is suppressed.
    let delivered_keys = dispatcher.delivered_keys.borrow();
    assert_eq!(delivered_keys.len(), 2);
    assert_ne!(delivered_keys[0], delivered_keys[1]);

    assert_eq!(surface_event_attempt_rows(&vault), 2);
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
fn surface_event_retry_mints_a_fresh_attempt() -> Result<()> {
    let (_dir, vault, _, clock) =
        timed_admitting_vault("retry@example.com", 0x1D, 0x5D, 1_800_003_000);
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
    let SurfaceEventWorkerOutcome::Retried(retried) = vault.dispatch_next_surface_event(
        "test-worker",
        {
            clock.set(1_800_003_100);
            1_800_003_100
        },
        &retrying,
    )?
    else {
        panic!("expected retry");
    };
    // ONE-1795: a retry is a NEW Scheduled row; the source stays behind as
    // the terminal record of the failed try.
    assert_ne!(retried.attempt_ref, ack.attempt_ref);
    assert_eq!(retried.state, SurfaceEventHandoffState::Paused);
    assert_eq!(retried.last_error, None);
    assert_eq!(surface_event_attempt_rows(&vault), 2);

    // The minted row keeps its payload, correlation id, and downstream key.
    let row = AttemptQueue::new(&vault)
        .list()?
        .into_iter()
        .filter(|record| record.kind == SURFACE_EVENT_ATTEMPT_KIND)
        .find(|record| record.state == crate::attempt_queue::AttemptState::Scheduled)
        .expect("the retry row is scheduled");
    assert_eq!(
        row.retry_of.map(SurfaceEventAttemptRef::from_attempt_id),
        Some(ack.attempt_ref)
    );
    assert_eq!(row.payload, payload_before);
    assert_eq!(row.run_id.as_deref(), Some("evt-retry@example.com"));
    let decoded = decode_surface_event_attempt_payload(&row.payload)?;
    let expected_dedupe_key = surface_event_dedupe_key(SurfaceEventKey {
        channel: &decoded.event.channel,
        receiving: &decoded.event.receiving_identity_ref,
        correlation_id: &decoded.event.correlation_id,
    });
    assert_eq!(
        row.dedupe_key.as_deref(),
        Some(expected_dedupe_key.as_str())
    );
    assert_eq!(decoded.dispatch_idempotency_key, expected_dedupe_key);
    assert_eq!(decoded.event.correlation_id, "evt-retry@example.com");

    // The source row is terminal and carries the retry's reason.
    let source = AttemptQueue::new(&vault)
        .list()?
        .into_iter()
        .filter(|record| record.kind == SURFACE_EVENT_ATTEMPT_KIND)
        .find(|record| record.state == crate::attempt_queue::AttemptState::Failed)
        .expect("the source row finalized as failed");
    assert_eq!(source.last_error.as_deref(), Some("downstream busy"));

    // The second dispatch claims the Scheduled row and completes it.
    let completing = FakeDispatcher::new(SurfaceEventDispatchDisposition::Complete);
    let SurfaceEventWorkerOutcome::Completed(completed) = vault.dispatch_next_surface_event(
        "test-worker",
        {
            clock.set(1_800_003_200);
            1_800_003_200
        },
        &completing,
    )?
    else {
        panic!("expected completion after retry");
    };
    assert_eq!(completed.attempt_ref, retried.attempt_ref);
    assert_eq!(completed.attempt_count, 1);
    assert_eq!(surface_event_attempt_rows(&vault), 2);
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

    // The run id remains bounded and correlation-based while the typed dedupe
    // tuple has its own bounded digest.
    let row = sole_attempt(&vault);
    let expected_run_id = surface_event_run_id(&correlation_id);
    assert!(expected_run_id.starts_with("sha256:"));
    assert!(expected_run_id.len() <= 128);
    assert_eq!(row.run_id.as_deref(), Some(expected_run_id.as_str()));

    // The raw provider id survives verbatim on the durable envelope; the
    // downstream idempotency key remains bounded and receiving-identity scoped.
    let decoded = decode_surface_event_attempt_payload(&row.payload)?;
    let expected_dedupe_key = surface_event_dedupe_key(SurfaceEventKey {
        channel: &decoded.event.channel,
        receiving: &decoded.event.receiving_identity_ref,
        correlation_id: &decoded.event.correlation_id,
    });
    assert_eq!(
        row.dedupe_key.as_deref(),
        Some(expected_dedupe_key.as_str())
    );
    assert_ne!(row.dedupe_key.as_deref(), Some(expected_run_id.as_str()));
    assert_eq!(decoded.event.correlation_id, correlation_id);
    assert_eq!(decoded.dispatch_idempotency_key, expected_dedupe_key);

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
    let unruled = identity_on_channel(
        "carrier-pigeon",
        "coop@example.com",
        ChannelIdentityBinding::agent(agent_ref),
        ChannelIdentityState::Active,
    );
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
    let vault_bound = identity_bound(
        "vault-bound@example.com",
        ChannelIdentityBinding::vault(7),
        ChannelIdentityState::Active,
    );
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
        matches!(
            error,
            Error::Registry(RegistryError::SurfaceEventCorrelationKindCollision {
                ref correlation_id,
                ref holding_kind
            }) if correlation_id == "evt-collide@example.com" && holding_kind == "some.other.kind.v1"
        ),
        "collision must name the cause: {error}"
    );
    assert_eq!(surface_event_attempt_rows(&vault), 0);

    // The status read fails closed the same way rather than reporting the
    // foreign row as this event's handoff.
    let status_error = vault
        .surface_event_handoff_status("evt-collide@example.com")
        .expect_err("the status read must fail closed on the same collision");
    assert!(
        matches!(
            status_error,
            Error::Registry(RegistryError::SurfaceEventCorrelationKindCollision {
                ref correlation_id,
                ref holding_kind
            }) if correlation_id == "evt-collide@example.com" && holding_kind == "some.other.kind.v1"
        ),
        "status read must name the same collision: {status_error}"
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

fn seed(vault: &Vault, id: EntityId, entity_type: u8) -> EntityId {
    if entity_type == crate::registry::ENTITY_TYPE_AGENT_DEF {
        return crate::test_util::seed_agent_definition(vault, id, "surface_event");
    }
    vault
        .put_entity(
            &id,
            entity_type,
            crate::temporal::TimeRange {
                start: 100,
                end: 100,
            },
            100,
            b"surface event fixture",
        )
        .expect("seed entity");
    id
}

#[test]
fn subject_projection_failure_does_not_replace_identity_rejection_receipts() -> Result<()> {
    let (_dir, vault) = test_vault();
    let actor = seed(&vault, entity(0xB8), crate::registry::ENTITY_TYPE_MACHINE);
    let person = seed(&vault, entity(0xB9), crate::registry::ENTITY_TYPE_PERSON);
    let author = subject_owner(&vault)?;
    let id = crate::subject_model::anchor_actor_subject(&vault, actor, person, author, 100)?;
    let mut malformed = vault.get_claim(&id)?.expect("anchor");
    malformed.value = rmpv::Value::from("malformed-subject-ref");
    // Damage the stored row body in place: the checked reserved door refuses a
    // malformed actor.subject_ref, and this test observes the reader, not admission.
    crate::subject_model::tests::corrupt_subject_fixture(&vault, &id, &malformed)?;
    for (identity_id, address, state, expected) in [
        (
            entity(0xBA),
            "inactive@example.com",
            ChannelIdentityState::Requested,
            InboundSurfaceRejectionReason::InactiveReceivingIdentity,
        ),
        (
            entity(0xBB),
            "closed@example.com",
            ChannelIdentityState::Tombstone,
            InboundSurfaceRejectionReason::TombstonedReceivingIdentity,
        ),
    ] {
        vault.create_channel_identity(&identity_id, &identity(address, actor, state))?;
        let receipt = vault.route_inbound_surface_event(input(
            address,
            SurfaceCounterpartyStamp::unknown("sender@elsewhere.example"),
        ))?;
        assert_eq!(receipt.rejection_reason, Some(expected));
        assert!(receipt.surface_event.is_none());
    }
    vault.create_channel_identity(
        &entity(0xBC),
        &identity("active@example.com", actor, ChannelIdentityState::Active),
    )?;
    assert!(
        vault
            .route_inbound_surface_event(input(
                "active@example.com",
                SurfaceCounterpartyStamp::unknown("sender@elsewhere.example"),
            ))
            .is_err(),
        "a corrupt anchor must not route as plumbing",
    );
    Ok(())
}

#[test]
fn subject_stamp_uses_event_received_at_not_processing_time() -> Result<()> {
    for state in [
        ChannelIdentityState::Active,
        ChannelIdentityState::Rotating,
        ChannelIdentityState::Released,
        ChannelIdentityState::Quarantine,
    ] {
        let (_dir, vault) = test_vault();
        let actor = seed(&vault, entity(0xD0), crate::registry::ENTITY_TYPE_AGENT_DEF);
        let person = seed(&vault, entity(0xD1), crate::registry::ENTITY_TYPE_PERSON);
        let facet = seed(&vault, entity(0xD2), crate::registry::ENTITY_TYPE_FACET);
        let owner = subject_owner(&vault)?;
        // The anchor starts at the normal input fixture's received_at and
        // expires two seconds later. Earlier events must not see a future fact.
        let start = 1_800_000_123;
        let id = crate::subject_model::anchor_actor_subject(&vault, actor, person, owner, start)?;
        let mut body = vault.get_claim(&id)?.expect("anchor");
        body.valid_to = Some(start + 2);
        vault.with_write_txn(|txn| {
            vault.put_reserved_claim_in_txn(
                txn,
                &id,
                &body,
                crate::temporal::TimeRange { start, end: start },
                start,
            )
        })?;
        let before = vault.get(&id)?;
        let record = identity_bound(
            "timed@example.com",
            ChannelIdentityBinding::actor_with_facet(actor, facet),
            state,
        );
        vault.create_channel_identity(&entity(0xD3), &record)?;
        for (at, present) in [
            (start + 2, false),
            (start - 1, false),
            (start, true),
            (start + 1, true),
        ] {
            let mut incoming = input(
                "timed@example.com",
                SurfaceCounterpartyStamp::unknown("sender@example.com"),
            );
            incoming.received_at = at;
            let receipt = vault.route_inbound_surface_event(incoming)?;
            assert_eq!(receipt.outcome, InboundSurfaceRouteOutcome::Routed);
            let event = receipt.surface_event.expect("routed event");
            assert_eq!(event.received_at, at);
            assert_eq!(event.actor_ref, actor.to_hex());
            assert_eq!(event.facet_ref, Some(facet.to_hex()));
            assert_eq!(event.subject_ref, present.then(|| person.to_hex()));
        }
        assert_eq!(vault.get(&id)?, before);
    }
    Ok(())
}

mod cc_intake;
