#![cfg(oneiron_test_support)]
//! BOARD-KEYFRAME-CHILD-RELEASE: a connector board's bare child row (a
//! child of the actor that rides no TASK) names only its child's attempt
//! and its label, so the gateway's release judged it by its attempt id
//! alone, and the row of a child working in a world kept on this device
//! left it on the board keyframe. The row is now judged by where its child
//! works, read from the child's own committed attempt, as its `children:`
//! delta line is: the world its dispatch froze or its definition runs in,
//! and its TASK. Those rows are served beside its attempt, and a child a
//! kept world holds, one that names no world while a world is kept, and
//! one that does not read stay off an off-device caller's board.
//!
//! The door `oneiron_server::test_doors::board_keyframe_child_release`
//! runs the judgment a connector board's bare child row passes
//! (`bare_child_served_rows`, which serves each bare child the board
//! admitted), toward a destination the test names: off this device with
//! no machine proof, the destination a OneMachine world withholds from.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron-server --all-features --features oneiron/test-support
//! --no-fail-fast --test board_keyframe_child_release`.

use oneiron::agent_dispatch::{
    AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher, AgentSpawnContext,
    DEFAULT_BASE_LOGICAL_ID, DispatchAgent,
};
use oneiron::claim::CallerLocality;
use oneiron::llm::Scope;
use oneiron::registry::ENTITY_TYPE_WORLD;
use oneiron::settings::ReadDestination;
use oneiron::{AttemptId, EntityId, TimeRange, Vault, VaultConfig};
use oneiron_server::test_doors::board_keyframe_child_release::bare_child_served_rows;

type TestError = Box<dyn std::error::Error>;
type TestResult<T = ()> = Result<T, TestError>;

/// The run every attempt of one test's tree belongs to.
const RUN: &str = "run-keyframe-child-release";

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
/// of delegation left: its attempt.
fn root_run(vault: &Vault, world: Option<EntityId>) -> TestResult<AttemptId> {
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
    Ok(status.attempt.id)
}

/// A live child of `parent`, spawned as the run's dispatcher spawns one:
/// no TASK, and its parent's frozen scope.
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

/// The bare row of a child whose dispatch froze world W is served beside W,
/// and stays off an off-device caller's board once the owner keeps W on
/// this machine, while a caller on this device still sees it. Before the
/// fix the board served the row by its attempt alone, so the release found
/// no row for it and the keyframe showed the child.
#[test]
fn a_bare_child_in_a_world_kept_on_this_device_stays_off_the_keyframe() -> TestResult {
    let dir = tempfile::tempdir()?;
    let vault = open_vault(dir.path())?;
    let kept = world(&vault)?;
    let root = root_run(&vault, Some(kept))?;
    let child = spawn_child(&vault, root)?;
    let child_hex = hex(child);
    let attempt = EntityId::from_hex(&child_hex)?;

    let served = bare_child_served_rows(&vault, &off_device(), &child_hex)
        .ok_or("W goes everywhere yet: the row is on the board")?;
    assert!(served.contains(&attempt), "{served:?}");
    assert!(
        served.contains(&kept),
        "the row is served by the world its child works in: {served:?}"
    );

    vault.keep_world_on_this_machine_for_test(kept, true)?;
    assert_eq!(
        bare_child_served_rows(&vault, &off_device(), &child_hex),
        None,
        "W stays on this machine: the row stays off the board"
    );
    assert!(
        bare_child_served_rows(&vault, &on_device(), &child_hex)
            .is_some_and(|served| served.contains(&kept)),
        "a caller on this device still sees the row, served by W"
    );
    Ok(())
}

/// The bare row of a child that names no world (its root froze none, and
/// the default agent spans every world) goes off this device only while no
/// world stays on it, as a run that names no world is placed. Before the
/// fix the row was shown once a world stayed.
#[test]
fn a_bare_child_naming_no_world_leaves_only_while_no_world_stays_here() -> TestResult {
    let dir = tempfile::tempdir()?;
    let vault = open_vault(dir.path())?;
    let root = root_run(&vault, None)?;
    let child = spawn_child(&vault, root)?;
    let child_hex = hex(child);
    let attempt = EntityId::from_hex(&child_hex)?;

    let served = bare_child_served_rows(&vault, &off_device(), &child_hex)
        .ok_or("no world stays here: the row is on the board")?;
    assert!(served.contains(&attempt), "{served:?}");

    let kept = world(&vault)?;
    vault.keep_world_on_this_machine_for_test(kept, true)?;
    assert_eq!(
        bare_child_served_rows(&vault, &off_device(), &child_hex),
        None,
        "a world stays here: a child that names no world may carry its text"
    );
    assert!(bare_child_served_rows(&vault, &on_device(), &child_hex).is_some());
    Ok(())
}

/// Control: the bare row of a child whose dispatch froze world
/// W stays on the board off this device while W goes everywhere, though
/// another world stays on this machine, and W is served beside its attempt.
/// The hold follows the child's own world.
#[test]
fn a_bare_child_in_a_world_that_goes_everywhere_stays_on_the_keyframe() -> TestResult {
    let dir = tempfile::tempdir()?;
    let vault = open_vault(dir.path())?;
    let open = world(&vault)?;
    let root = root_run(&vault, Some(open))?;
    let child = spawn_child(&vault, root)?;
    let child_hex = hex(child);

    let other = world(&vault)?;
    vault.keep_world_on_this_machine_for_test(other, true)?;
    let served = bare_child_served_rows(&vault, &off_device(), &child_hex)
        .ok_or("W goes everywhere: the row is on the board")?;
    assert!(
        served.contains(&open),
        "the row is served by the world its child works in: {served:?}"
    );
    Ok(())
}
