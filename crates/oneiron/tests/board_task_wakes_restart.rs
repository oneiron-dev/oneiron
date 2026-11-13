//! Census L2-38, ARCH-0067 `#stream-narrowed-built`: "No wake is replayed
//! after a restart or for a connection that attaches later."
//!
//! A failed TASK owes its owner a WAKE and a queued consult owes its addressee
//! one. Before L2-38 the board registry's in-memory queue was the only record
//! of that wake: an actor with no live connection got nothing, and a restart
//! emptied every queue. Now the board publisher stages each owed wake in the
//! vault, and the pass an attach starts offers each live staged wake once to
//! each connection of its recipient that may read the TASK.
//!
//! The doors in `oneiron::test_doors::board_task_wakes` run serve's two passes
//! inline: the TASK pass (read, stage, route) and the staged wake pass. On
//! main the TASK pass only routes and nothing is replayed, so the restart,
//! late-connection, admission and consult cases are red there.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test board_task_wakes_restart`.
#![cfg(oneiron_test_support)]

use std::path::Path;

use oneiron::attempt_queue::{ClaimAttempt, ClaimOutcome, FailAttempt};
use oneiron::context_board::{
    BoardRenderMode, BoardStreamRegistry, StreamConnectionId, SubscriptionScope, WakeEnvelope,
};
use oneiron::task_verb::{
    ConsultPayloadRef, TaskAskDefault, TaskAskQuestion, TaskAskSpec, TaskAskTarget, TaskAskWord,
    TaskAssignee, TaskCreateSpec,
};
use oneiron::test_doors::board_task_wakes::{publish_committed_task, publish_staged_task_wakes};
use oneiron::{AttemptQueue, EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The lease owner the fixture's realization worker claims under.
const WORKER: &str = "board-task-wake-worker";

fn open(path: &Path) -> TestResult<Vault> {
    // `open_owned` holds the writer lease the owner's doors ask for.
    Ok(Vault::open_owned(path, VaultConfig::default())?)
}

/// A TASK `owner` creates; its realization is queued.
fn create_task(vault: &Vault, owner: EntityId, intent: &str) -> TestResult<EntityId> {
    let receipt = vault
        .memory(owner, EdgeActorClass::Human)
        .tasks_create(&TaskCreateSpec::new(
            rmpv::Value::from(intent),
            None,
            None,
            None,
        ))?;
    receipt
        .task_ref
        .ok_or_else(|| "tasks.create names its TASK".into())
}

/// Claims the next queued realization and fails it: the TASK it realizes
/// folds to `failed`.
fn fail_next_realization(vault: &Vault) -> TestResult {
    let queue = AttemptQueue::new(vault);
    let now = vault.now_recorded_at();
    let ClaimOutcome::Claimed(leased) = queue.claim_kind(
        "tasks.realize",
        ClaimAttempt {
            lease_owner: WORKER.to_owned(),
            now,
        },
    )?
    else {
        return Err("a realization is queued".into());
    };
    queue.fail(FailAttempt {
        id: leased.id,
        lease_owner: WORKER.to_owned(),
        attempt_count: leased.attempt_count,
        reason: "the worker stopped".to_owned(),
        now,
    })?;
    Ok(())
}

/// A STREAM connection of `actor`, subscribed to every scope it may hear.
fn attach(registry: &mut BoardStreamRegistry, name: &str, actor: EntityId) -> StreamConnectionId {
    let connection = StreamConnectionId(format!("test:{name}"));
    registry.attach_connection(
        connection.clone(),
        BoardRenderMode::Stream,
        actor.to_hex(),
        SubscriptionScope::ALL.into_iter().collect(),
        0,
    );
    connection
}

fn admit_all(_: &StreamConnectionId) -> bool {
    true
}

fn admit_all_staged(_: &StreamConnectionId, _: EntityId) -> bool {
    true
}

fn assert_task_wake(wake: &WakeEnvelope, task: EntityId, actor: EntityId, what: &str) {
    assert_eq!(wake.task_ref, task.to_hex(), "{wake:?}");
    assert_eq!(wake.actor_ref, actor.to_hex(), "{wake:?}");
    let prefix = format!("{}:{what}:", task.to_hex());
    assert!(wake.event_ref.starts_with(&prefix), "{wake:?}");
}

/// A TASK fails while its owner has no connection. The process restarts: the
/// vault is closed and opened again under a new registry. The owner's
/// connection that attaches then is offered the failure once.
#[test]
fn a_failed_wake_with_no_connection_reaches_a_connection_that_attaches_after_a_restart()
-> TestResult {
    let directory = tempfile::tempdir()?;
    let (owner, task) = {
        let vault = open(directory.path())?;
        let owner = vault.ensure_embedded_owner_actor()?;
        let task = create_task(&vault, owner, "fails before anyone listens")?;
        fail_next_realization(&vault)?;
        let mut registry = BoardStreamRegistry::default();
        publish_committed_task(&vault, &mut registry, task, admit_all)?;
        (owner, task)
    };

    let vault = open(directory.path())?;
    let mut registry = BoardStreamRegistry::default();
    let late = attach(&mut registry, "owen-late", owner);
    publish_staged_task_wakes(&vault, &mut registry, admit_all_staged)?;
    let wakes = registry.drain_wakes(&late);
    assert_eq!(
        wakes.len(),
        1,
        "the failure reaches the late connection: {wakes:?}"
    );
    assert_task_wake(&wakes[0], task, owner, "failed");

    // Offered once: the next pass hands the same connection nothing.
    publish_staged_task_wakes(&vault, &mut registry, admit_all_staged)?;
    assert!(registry.drain_wakes(&late).is_empty());
    Ok(())
}

/// A live route and the staged pass offer each connection one wake: the
/// connection the failure was routed to hears it once, a second connection of
/// the owner that attaches later hears it once under the same envelope id,
/// and another actor's connection hears nothing.
#[test]
fn a_live_route_and_the_staged_pass_offer_each_connection_one_wake() -> TestResult {
    let directory = tempfile::tempdir()?;
    let vault = open(directory.path())?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let other = EntityId::from_bytes([0x3c; 16])?;
    let task = create_task(&vault, owner, "fails while one connection listens")?;
    let mut registry = BoardStreamRegistry::default();
    let first = attach(&mut registry, "owen-first", owner);
    let bystander = attach(&mut registry, "yuki", other);

    fail_next_realization(&vault)?;
    publish_committed_task(&vault, &mut registry, task, admit_all)?;
    let routed = registry.drain_wakes(&first);
    assert_eq!(routed.len(), 1, "{routed:?}");
    assert_task_wake(&routed[0], task, owner, "failed");

    publish_staged_task_wakes(&vault, &mut registry, admit_all_staged)?;
    assert!(
        registry.drain_wakes(&first).is_empty(),
        "a routed wake is not offered again"
    );

    let second = attach(&mut registry, "owen-second", owner);
    publish_staged_task_wakes(&vault, &mut registry, admit_all_staged)?;
    let replayed = registry.drain_wakes(&second);
    assert_eq!(
        replayed.len(),
        1,
        "the later connection hears the failure: {replayed:?}"
    );
    assert_eq!(replayed[0].event_ref, routed[0].event_ref);
    assert!(registry.drain_wakes(&first).is_empty());
    assert!(registry.drain_wakes(&bystander).is_empty());
    Ok(())
}

/// A connection whose reader may not read the TASK is not offered its wake,
/// and is offered it at a later pass once its reader may.
#[test]
fn a_connection_that_cannot_read_the_task_is_offered_its_wake_once_it_can() -> TestResult {
    let directory = tempfile::tempdir()?;
    let vault = open(directory.path())?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let task = create_task(&vault, owner, "fails before the reader binds")?;
    fail_next_realization(&vault)?;
    let mut registry = BoardStreamRegistry::default();
    publish_committed_task(&vault, &mut registry, task, admit_all)?;

    let connection = attach(&mut registry, "owen-unbound", owner);
    publish_staged_task_wakes(&vault, &mut registry, |_, _| false)?;
    assert!(registry.drain_wakes(&connection).is_empty());

    publish_staged_task_wakes(&vault, &mut registry, admit_all_staged)?;
    let wakes = registry.drain_wakes(&connection);
    assert_eq!(wakes.len(), 1, "{wakes:?}");
    assert_task_wake(&wakes[0], task, owner, "failed");
    Ok(())
}

/// A consult queued while its addressee has no connection reaches the
/// addressee's connection that attaches after a restart, and no other
/// actor's. Once answered it owes no wake: the staged pass reads the TASK
/// again and settles its row, so a connection that attaches then hears
/// nothing.
#[test]
fn a_consult_wake_reaches_its_addressee_after_a_restart() -> TestResult {
    let directory = tempfile::tempdir()?;
    let (owner, receipt) = {
        let vault = open(directory.path())?;
        let owner = vault.ensure_embedded_owner_actor()?;
        let turn = EntityId::from_bytes([0x3d; 16])?;
        let mut body = Vec::new();
        rmpv::encode::write_value(
            &mut body,
            &rmpv::Value::Map(vec![(
                rmpv::Value::from("role"),
                rmpv::Value::from("question"),
            )]),
        )?;
        vault.put_entity(
            &turn,
            oneiron::registry::ENTITY_TYPE_TURN,
            TimeRange { start: 2, end: 2 },
            2,
            &body,
        )?;
        let reference = ConsultPayloadRef::parse(&vault, &format!("tn_{}", turn.to_hex()))?;
        let ask = TaskAskSpec {
            intent_key: "board-task-wake-consult".into(),
            ..TaskAskSpec::shorthand(
                Some(TaskAskTarget::Responder(TaskAssignee::Human {
                    actor_ref: owner,
                })),
                TaskAskQuestion::new(reference),
                Some(u64::MAX),
                TaskAskDefault::AskMe,
            )
        };
        let receipt = vault.memory(owner, EdgeActorClass::Human).tasks_ask(&ask)?;
        let mut registry = BoardStreamRegistry::default();
        for task in &receipt.task_refs {
            publish_committed_task(&vault, &mut registry, *task, admit_all)?;
        }
        (owner, receipt)
    };
    let consults = &receipt.task_refs;
    assert!(!consults.is_empty(), "the ask lands a consult TASK");

    let vault = open(directory.path())?;
    let mut registry = BoardStreamRegistry::default();
    let addressee = attach(&mut registry, "owen-addressee", owner);
    let bystander = attach(&mut registry, "yuki", EntityId::from_bytes([0x3c; 16])?);
    publish_staged_task_wakes(&vault, &mut registry, admit_all_staged)?;
    let wakes = registry.drain_wakes(&addressee);
    assert_eq!(wakes.len(), consults.len(), "{wakes:?}");
    for (wake, task) in wakes.iter().zip(consults) {
        assert_task_wake(wake, *task, owner, "arrived");
    }
    assert!(registry.drain_wakes(&bystander).is_empty());

    // Answered, the consult owes no wake, even though no TASK pass ran.
    vault
        .memory(owner, EdgeActorClass::Human)
        .tasks_answer(&receipt.handle, &TaskAskWord::new(owner))?;
    let after_answer = attach(&mut registry, "owen-after-answer", owner);
    publish_staged_task_wakes(&vault, &mut registry, admit_all_staged)?;
    assert!(registry.drain_wakes(&after_answer).is_empty());
    publish_staged_task_wakes(&vault, &mut registry, admit_all_staged)?;
    assert!(registry.drain_wakes(&after_answer).is_empty());
    Ok(())
}
