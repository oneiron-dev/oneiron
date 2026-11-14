//! Census L2-38, ARCH-0067 STREAM delivery: "Default subscription: my tasks ·
//! my children · consults to me". Engine RULING L2-38-CHILD-KEY = A (13 Nov
//! 17:34): a child's end comes from the committed attempts, its spawner's
//! actor from the committed parent attempt, and it rides as a
//! `children:<attempt id>` CARRIER line with the child's handle and its end.
//!
//! A plain spawn mints no TASK, so on main nothing produces a child's end:
//! the routing for `ChildDone` exists, and no producer feeds it. The door
//! `oneiron::test_doors::board_child_done` runs serve's pass inline over an
//! engine registry. On main the door has nothing to take, so the cases that
//! expect a child line are red there.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test board_child_done_producer`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;

use oneiron::agent_dispatch::{
    AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher, AgentSpawnContext,
    DEFAULT_BASE_LOGICAL_ID, DispatchAgent, agent_dispatch_actor,
};
use oneiron::attempt_queue::{
    AbandonAttempt, AttemptRecord, AttemptResultRef, ClaimAttempt, ClaimOutcome, CompleteAttempt,
};
use oneiron::context_board::{
    BoardRenderMode, BoardStreamFrame, BoardStreamRegistry, DeltaRow, FrameEnqueueOutcome,
    FrameKind, StreamConnectionId, SubscriptionScope,
};
use oneiron::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND;
use oneiron::test_doors::board_child_done::publish_children_done;
use oneiron::{AttemptId, AttemptQueue, EntityId, Vault, VaultConfig};

type TestError = Box<dyn std::error::Error>;
type TestResult<T = ()> = Result<T, TestError>;

/// The run every attempt of one test's tree belongs to.
const RUN: &str = "run-child-done";
/// The lease owner this test claims rows as.
const WORKER: &str = "board-child-done";

fn open_vault(dir: &std::path::Path) -> TestResult<Vault> {
    let mut config = VaultConfig::device();
    config.map_size = 32 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = None;
    Ok(Vault::open_owned(dir, config)?)
}

fn hex(id: AttemptId) -> String {
    id.as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// A root run of the seeded default agent, with one level of delegation
/// left: its attempt and the actor it runs as.
fn root_run(vault: &Vault, now: u64) -> TestResult<(AttemptId, EntityId)> {
    let (agent, _) = vault
        .get_seeded_agent_definition_by_logical_id(DEFAULT_BASE_LOGICAL_ID)?
        .ok_or("the default agent is seeded")?;
    let AgentDispatchOutcome::Dispatched(status) = AgentDispatcher::new(vault)
        .dispatch_with_context(
            DispatchAgent {
                target: AgentDispatchTarget::Custom(agent),
                parent_attempt: None,
                dedupe_key: None,
                run_id: Some(RUN.to_owned()),
                now,
            },
            AgentSpawnContext::default().with_depth_remaining(1),
        )?
    else {
        return Err("expected one fresh root run".into());
    };
    Ok((
        status.attempt.id,
        agent_dispatch_actor(&status.input)?.entity_ref(),
    ))
}

/// A child of `parent`, spawned as the run's dispatcher spawns one: no TASK.
fn spawn_child(vault: &Vault, parent: AttemptId, key: &str, now: u64) -> TestResult<AttemptId> {
    let AgentDispatchOutcome::Dispatched(status) = AgentDispatcher::new(vault)
        .dispatch_default_base(
            Some(parent),
            Some(key.to_owned()),
            Some(RUN.to_owned()),
            now,
        )?
    else {
        return Err("expected one fresh child".into());
    };
    assert_eq!(status.attempt.task_ref, None, "a plain spawn mints no TASK");
    Ok(status.attempt.id)
}

/// Leases `id` to this test's worker; rows queued before it are claimed past.
fn claim(vault: &Vault, id: AttemptId) -> TestResult<AttemptRecord> {
    let queue = AttemptQueue::new(vault);
    for _ in 0..64 {
        let ClaimOutcome::Claimed(row) = queue.claim_kind(
            DREAMER_RUNNER_ATTEMPT_KIND,
            ClaimAttempt {
                lease_owner: WORKER.to_owned(),
                now: u64::MAX,
            },
        )?
        else {
            break;
        };
        if row.id == id {
            return Ok(queue.get(id)?.ok_or("a claimed row reads back")?);
        }
    }
    Err("the attempt is ready to claim".into())
}

fn complete(vault: &Vault, id: AttemptId) -> TestResult {
    let leased = claim(vault, id)?;
    AttemptQueue::new(vault).complete(CompleteAttempt {
        id,
        lease_owner: WORKER.to_owned(),
        attempt_count: leased.attempt_count,
        now: leased.updated_at,
    })?;
    Ok(())
}

/// A connection of `actor` subscribed to `scopes`, holding a keyframe, so a
/// CARRIER delta can queue on it.
fn attach(
    registry: &mut BoardStreamRegistry,
    name: &str,
    actor: EntityId,
    scopes: BTreeSet<SubscriptionScope>,
) -> StreamConnectionId {
    let connection = StreamConnectionId(format!("test:{name}"));
    registry.attach_connection(
        connection.clone(),
        BoardRenderMode::Resident,
        actor.to_hex(),
        scopes,
        0,
    );
    assert_eq!(
        registry.enqueue(
            &connection,
            BoardStreamFrame {
                epoch: 1,
                kind: FrameKind::Keyframe("k1".to_owned()),
            },
        ),
        FrameEnqueueOutcome::ReplacedWithKeyframe
    );
    assert!(registry.next_carrier_payload(&connection).is_some());
    connection
}

/// Every delta row queued on `connection`'s carrier.
fn delta_rows(
    registry: &mut BoardStreamRegistry,
    connection: &StreamConnectionId,
) -> Vec<DeltaRow> {
    match registry.next_carrier_payload(connection) {
        Some(BoardStreamFrame {
            kind: FrameKind::Delta(rows),
            ..
        }) => rows,
        _ => Vec::new(),
    }
}

fn all_scopes() -> BTreeSet<SubscriptionScope> {
    SubscriptionScope::ALL.into_iter().collect()
}

/// A plain child's end reaches its spawner's subscribed connection as one
/// `children:` line naming the child and `done`. Another actor's connection,
/// and a spawner connection that does not subscribe to its children, hear
/// nothing, and the pass after it has nothing left to send.
#[test]
fn a_taskless_childs_end_reaches_its_spawners_subscribed_connection() -> TestResult {
    let dir = tempfile::tempdir()?;
    let vault = open_vault(dir.path())?;
    let (root, spawner) = root_run(&vault, 1)?;
    let child = spawn_child(&vault, root, "child-one", 2)?;
    let mut registry = BoardStreamRegistry::default();
    let parent = attach(&mut registry, "spawner", spawner, all_scopes());
    let other = attach(
        &mut registry,
        "yuki",
        EntityId::from_bytes([0x3e; 16])?,
        all_scopes(),
    );
    let unsubscribed = attach(
        &mut registry,
        "spawner-no-children",
        spawner,
        BTreeSet::from([SubscriptionScope::MyTasks]),
    );

    complete(&vault, child)?;
    publish_children_done(&vault, &mut registry)?;

    let rows = delta_rows(&mut registry, &parent);
    let key = format!("children:{}", hex(child));
    let line = rows
        .iter()
        .find(|row| row.key == key)
        .map(|row| row.line.clone())
        .ok_or_else(|| format!("the spawner hears its child's end: {rows:?}"))?;
    assert!(line.ends_with(":done"), "{line}");
    assert!(delta_rows(&mut registry, &other).is_empty());
    assert!(delta_rows(&mut registry, &unsubscribed).is_empty());

    publish_children_done(&vault, &mut registry)?;
    assert!(delta_rows(&mut registry, &parent).is_empty());
    Ok(())
}

/// An abandoned child's line names its end as `abandoned`.
#[test]
fn an_abandoned_childs_line_names_its_end() -> TestResult {
    let dir = tempfile::tempdir()?;
    let vault = open_vault(dir.path())?;
    let (root, spawner) = root_run(&vault, 1)?;
    let child = spawn_child(&vault, root, "child-stopped", 2)?;
    let mut registry = BoardStreamRegistry::default();
    let parent = attach(&mut registry, "spawner", spawner, all_scopes());

    let leased = claim(&vault, child)?;
    AttemptQueue::new(&vault).abandon(AbandonAttempt {
        id: child,
        lease_owner: WORKER.to_owned(),
        attempt_count: leased.attempt_count,
        result_ref: AttemptResultRef::new("artifact:child-stopped")?,
        reason: "the worker stopped carrying it".to_owned(),
        now: leased.updated_at,
    })?;
    publish_children_done(&vault, &mut registry)?;

    let rows = delta_rows(&mut registry, &parent);
    let key = format!("children:{}", hex(child));
    let row = rows
        .iter()
        .find(|row| row.key == key)
        .ok_or_else(|| format!("the spawner hears its child's end: {rows:?}"))?;
    assert!(row.line.ends_with(":abandoned"), "{}", row.line);
    Ok(())
}

/// A root run's end is no child's: it sends no `children:` line. (Green on
/// main as well.)
#[test]
fn a_root_runs_end_sends_no_child_line() -> TestResult {
    let dir = tempfile::tempdir()?;
    let vault = open_vault(dir.path())?;
    let (root, spawner) = root_run(&vault, 1)?;
    let mut registry = BoardStreamRegistry::default();
    let connection = attach(&mut registry, "spawner", spawner, all_scopes());

    complete(&vault, root)?;
    publish_children_done(&vault, &mut registry)?;
    let rows = delta_rows(&mut registry, &connection);
    assert!(
        !rows.iter().any(|row| row.key.starts_with("children:")),
        "{rows:?}"
    );
    Ok(())
}
