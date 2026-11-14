#![cfg(oneiron_test_support)]
//! Census L2-38, review round 1 of the ChildDone producer: a `children:`
//! CARRIER line names only its child's attempt and the child's handle, so
//! the gateway's release check, which judged a frame by its `tasks:` keys and
//! the whole ids its bytes name, let the end of a child working in a world
//! kept on this device leave it. The check now judges each child line by
//! where its child works, read from the child's own committed attempt: the
//! world its dispatch froze or its definition runs in, and its TASK. A child
//! that names no world is judged as a run that names none is placed: it goes
//! only while no world stays on this device.
//!
//! The door `oneiron_server::test_doors::mcp_carrier_release` runs the check
//! a queued carrier frame passes before it rides and again at release, toward
//! a destination the test names: off this device with no machine proof, the
//! destination a OneMachine world withholds from. The frames are the ones the
//! engine's child-end pass queues (`oneiron::test_doors::board_child_done`).
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron-server --all-features --features oneiron/test-support
//! --no-fail-fast --test board_child_release`.

use std::collections::BTreeSet;

use oneiron::agent_dispatch::{
    AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher, AgentSpawnContext,
    DEFAULT_BASE_LOGICAL_ID, DispatchAgent, agent_dispatch_actor,
};
use oneiron::attempt_queue::{AttemptRecord, ClaimAttempt, ClaimOutcome, CompleteAttempt};
use oneiron::claim::CallerLocality;
use oneiron::context_board::{
    BoardRenderMode, BoardStreamFrame, BoardStreamRegistry, FrameEnqueueOutcome, FrameKind,
    StreamConnectionId, SubscriptionScope,
};
use oneiron::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND;
use oneiron::llm::Scope;
use oneiron::registry::ENTITY_TYPE_WORLD;
use oneiron::settings::ReadDestination;
use oneiron::test_doors::board_child_done::publish_children_done;
use oneiron::{AttemptId, AttemptQueue, EntityId, TimeRange, Vault, VaultConfig};
use oneiron_server::test_doors::mcp_carrier_release::carrier_releases;

type TestError = Box<dyn std::error::Error>;
type TestResult<T = ()> = Result<T, TestError>;

/// The run every attempt of one test's tree belongs to.
const RUN: &str = "run-child-release";
/// The lease owner this test claims rows as.
const WORKER: &str = "board-child-release";

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

/// A WORLD row this vault holds.
fn world(vault: &Vault) -> TestResult<EntityId> {
    let world = EntityId::now();
    let at = TimeRange { start: 1, end: 1 };
    vault.put_entity(&world, ENTITY_TYPE_WORLD, at, 1, b"world")?;
    Ok(world)
}

fn off_device() -> ReadDestination {
    ReadDestination::from(CallerLocality::OffDevice)
}

fn on_device() -> ReadDestination {
    ReadDestination::from(CallerLocality::OnDevice)
}

/// A root run of the seeded default agent (its definition spans every
/// world), its dispatch frozen to `world` when one is named, with one level
/// of delegation left: its attempt and the actor it runs as.
fn root_run(vault: &Vault, world: Option<EntityId>) -> TestResult<(AttemptId, EntityId)> {
    let (agent, _) = vault
        .get_seeded_agent_definition_by_logical_id(DEFAULT_BASE_LOGICAL_ID)?
        .ok_or("the default agent is seeded")?;
    let context = AgentSpawnContext {
        scope: world.map(|world| Scope {
            world: Some(world),
            ..Scope::default()
        }),
        ..AgentSpawnContext::default().with_depth_remaining(1)
    };
    let AgentDispatchOutcome::Dispatched(status) = AgentDispatcher::new(vault)
        .dispatch_with_context(
            DispatchAgent {
                target: AgentDispatchTarget::Custom(agent),
                parent_attempt: None,
                dedupe_key: None,
                run_id: Some(RUN.to_owned()),
                now: 1,
            },
            context,
        )?
    else {
        return Err("expected one fresh root run".into());
    };
    Ok((
        status.attempt.id,
        agent_dispatch_actor(&status.input)?.entity_ref(),
    ))
}

/// A child of `parent`, spawned as the run's dispatcher spawns one: no TASK,
/// and its parent's frozen scope.
fn spawn_child(vault: &Vault, parent: AttemptId) -> TestResult<AttemptId> {
    let AgentDispatchOutcome::Dispatched(status) = AgentDispatcher::new(vault)
        .dispatch_default_base(
            Some(parent),
            Some("child-one".to_owned()),
            Some(RUN.to_owned()),
            2,
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

/// The frame the spawner's subscribed connection holds once `child` ends
/// done: one carrier delta with the child's `children:` line.
fn child_end_frame(
    vault: &Vault,
    spawner: EntityId,
    child: AttemptId,
) -> TestResult<BoardStreamFrame> {
    let mut registry = BoardStreamRegistry::default();
    let connection = StreamConnectionId("test:spawner".to_owned());
    registry.attach_connection(
        connection.clone(),
        BoardRenderMode::Resident,
        spawner.to_hex(),
        SubscriptionScope::ALL.into_iter().collect::<BTreeSet<_>>(),
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

    let leased = claim(vault, child)?;
    AttemptQueue::new(vault).complete(CompleteAttempt {
        id: child,
        lease_owner: WORKER.to_owned(),
        attempt_count: leased.attempt_count,
        now: leased.updated_at,
    })?;
    publish_children_done(vault, &mut registry)?;

    let frame = registry
        .next_carrier_payload(&connection)
        .ok_or("the spawner's connection holds the child's end")?;
    let key = format!("children:{}", hex(child));
    let FrameKind::Delta(rows) = &frame.kind else {
        return Err(format!("expected a delta: {frame:?}").into());
    };
    assert!(
        rows.iter()
            .any(|row| row.key == key && row.line.ends_with(":done")),
        "{rows:?}"
    );
    Ok(frame)
}

/// The end of a child whose dispatch froze world W stays on this device once
/// the owner keeps W on this machine, while a caller on this device still
/// hears it. Red before the fix: the frame left (the line names only the
/// child's attempt).
#[test]
fn a_childs_end_in_a_world_kept_on_this_device_stays_here() -> TestResult {
    let dir = tempfile::tempdir()?;
    let vault = open_vault(dir.path())?;
    let kept = world(&vault)?;
    let (root, spawner) = root_run(&vault, Some(kept))?;
    let child = spawn_child(&vault, root)?;
    let frame = child_end_frame(&vault, spawner, child)?;
    assert!(
        carrier_releases(&vault, &off_device(), &frame),
        "W goes everywhere yet: the line leaves"
    );

    vault.keep_world_on_this_machine_for_test(kept, true)?;
    assert!(
        !carrier_releases(&vault, &off_device(), &frame),
        "W stays on this machine: the line stays too"
    );
    assert!(carrier_releases(&vault, &on_device(), &frame));
    Ok(())
}

/// The end of a child that names no world (its root froze none, and the
/// default agent spans every world) goes off this device only while no
/// world stays on it, as a run that names no world is placed. Red before
/// the fix: the frame left once a world stayed.
#[test]
fn a_childs_end_naming_no_world_leaves_only_while_no_world_stays_here() -> TestResult {
    let dir = tempfile::tempdir()?;
    let vault = open_vault(dir.path())?;
    let (root, spawner) = root_run(&vault, None)?;
    let child = spawn_child(&vault, root)?;
    let frame = child_end_frame(&vault, spawner, child)?;
    assert!(
        carrier_releases(&vault, &off_device(), &frame),
        "no world stays here: the line leaves"
    );

    let kept = world(&vault)?;
    vault.keep_world_on_this_machine_for_test(kept, true)?;
    assert!(
        !carrier_releases(&vault, &off_device(), &frame),
        "a world stays here: a child that names no world may carry its text"
    );
    assert!(carrier_releases(&vault, &on_device(), &frame));
    Ok(())
}

/// Control (green before the fix as well): the end of a child whose
/// dispatch froze world W leaves while W goes everywhere, though another
/// world stays on this machine. The hold follows the child's own world.
#[test]
fn a_childs_end_in_a_world_that_goes_everywhere_leaves() -> TestResult {
    let dir = tempfile::tempdir()?;
    let vault = open_vault(dir.path())?;
    let open = world(&vault)?;
    let (root, spawner) = root_run(&vault, Some(open))?;
    let child = spawn_child(&vault, root)?;
    let frame = child_end_frame(&vault, spawner, child)?;

    let other = world(&vault)?;
    vault.keep_world_on_this_machine_for_test(other, true)?;
    assert!(
        carrier_releases(&vault, &off_device(), &frame),
        "W goes everywhere: the line leaves"
    );
    Ok(())
}
