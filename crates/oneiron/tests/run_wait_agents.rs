//! Primitive D, slice 6.5b (SLICE6-MAP row D; ENGINE CALL S65-NAMES = A):
//! `tasks.wait` keeps its name and gains a wait over the AGENT children a run
//! spawned, named by their attempt ids: `{agents, all?, n_of?, step_key}`.
//!
//! - A wait that is not done answers what has ended and what is pending.
//! - The write that ends a child reduces each wait that names it, keeps a
//!   done reduction, and delivers it as the reply of a run parked on the
//!   wait, with no further call.
//! - A kept reduction answers every later call of its step key, after a
//!   restart too, and through the run's own call as through the host door.
//! - An attempt the caller's run did not spawn is refused, each miss the same
//!   way.
//!
//! On main the request and answer types and the host door do not exist, and
//! `tasks.wait`'s input parses no `agents` member, so this file does not
//! compile there. Public paths only:
//! `cargo test --locked -p oneiron --all-features --test run_wait_agents`.

use oneiron::agent_dispatch::{
    AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher, AgentSpawnContext,
    AgentWaitSetResult, DEFAULT_BASE_LOGICAL_ID, DispatchAgent, agent_dispatch_actor,
};
use oneiron::attempt_queue::{AttemptRecord, ClaimAttempt, ClaimOutcome, CompleteAttempt};
use oneiron::code_run::{
    HostSelfDispatcher, SelfCall, SelfDispatchOutcome, SelfDispatcher, TaskWaitAgentsRequest,
    TaskWaitInput, TaskWaitSetCall, WaitDeliveries,
};
use oneiron::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND;
use oneiron::{AttemptId, AttemptQueue, EntityId, Vault, VaultConfig, WriteActor};

type TestError = Box<dyn std::error::Error>;
type TestResult = Result<(), TestError>;

/// The run every attempt of one test's tree belongs to.
const RUN: &str = "run-6-5b";
/// The lease owner this test claims rows as.
const WORKER: &str = "run-wait-agents";

/// A process-owned vault at `dir`, as an embedded owner opens it.
fn open_vault(dir: &std::path::Path) -> Result<Vault, TestError> {
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

/// A root run of the seeded default agent under `run`, with one level of
/// delegation left: its attempt and the actor it runs as.
fn root_run(vault: &Vault, run: &str, now: u64) -> Result<(AttemptId, WriteActor), TestError> {
    let (agent, _) = vault
        .get_seeded_agent_definition_by_logical_id(DEFAULT_BASE_LOGICAL_ID)?
        .ok_or("the default agent is seeded")?;
    let AgentDispatchOutcome::Dispatched(status) = AgentDispatcher::new(vault)
        .dispatch_with_context(
            DispatchAgent {
                target: AgentDispatchTarget::Custom(agent),
                parent_attempt: None,
                dedupe_key: None,
                run_id: Some(run.to_owned()),
                now,
            },
            AgentSpawnContext::default().with_depth_remaining(1),
        )?
    else {
        return Err("expected one fresh root run".into());
    };
    Ok((status.attempt.id, agent_dispatch_actor(&status.input)?))
}

/// A child of `parent`, spawned as the run's dispatcher spawns one: the
/// default agent again, under the parent's run, keyed by `key`.
fn spawn_child(
    vault: &Vault,
    parent: AttemptId,
    run: &str,
    key: &str,
    now: u64,
) -> Result<AttemptId, TestError> {
    let AgentDispatchOutcome::Dispatched(status) = AgentDispatcher::new(vault)
        .dispatch_default_base(
            Some(parent),
            Some(key.to_owned()),
            Some(run.to_owned()),
            now,
        )?
    else {
        return Err("expected one fresh child".into());
    };
    Ok(status.attempt.id)
}

/// Leases `id` to this test's worker and answers its row. The runner's rows
/// are claimed oldest first, so rows queued before it are claimed past.
fn claim(vault: &Vault, id: AttemptId) -> Result<AttemptRecord, TestError> {
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

/// Runs `id` to its end: leased, then completed.
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

fn wait_on(agents: &[AttemptId], n_of: Option<u32>, step_key: &str) -> TaskWaitAgentsRequest {
    TaskWaitAgentsRequest {
        agents: agents.iter().copied().map(hex).collect(),
        all: None,
        n_of,
        step_key: step_key.to_owned(),
    }
}

/// The reply delivered for `wait`, as a run parked on it reads it; `None`
/// while the wait is not done.
fn delivered(vault: &Vault, wait: &str) -> Result<Option<AgentWaitSetResult>, TestError> {
    match WaitDeliveries::canonical(vault).settled(EntityId::from_hex(wait)?)? {
        Some(delivery) => Ok(Some(serde_json::from_str(&delivery.reply)?)),
        None => Ok(None),
    }
}

/// The same wait as the run's own code makes it: `tasks.wait` through the
/// dispatcher of an attempt, with no host door and no executor step to park.
fn wait_as_run(
    vault: &Vault,
    actor: WriteActor,
    parent: AttemptId,
    agents: &[AttemptId],
    n_of: Option<u32>,
    step_key: &str,
) -> Result<SelfDispatchOutcome, TestError> {
    let call: TaskWaitSetCall = serde_json::from_value(serde_json::json!({
        "tasks": [],
        "agents": agents.iter().copied().map(hex).collect::<Vec<_>>(),
        "n_of": n_of,
        "step_key": step_key,
    }))?;
    Ok(HostSelfDispatcher::for_agent_attempt(vault, actor, parent)?
        .dispatch(SelfCall::TasksWaitSet(call))?)
}

fn answer(outcome: SelfDispatchOutcome) -> Result<AgentWaitSetResult, TestError> {
    match outcome {
        SelfDispatchOutcome::AgentVerb(answer) => Ok(serde_json::from_value(answer.output)?),
        other => Err(format!("expected the wait's reduction, got {other:?}").into()),
    }
}

fn refusal(outcome: SelfDispatchOutcome) -> Result<String, TestError> {
    match outcome {
        SelfDispatchOutcome::Failed(failed) => Ok(failed.error),
        other => Err(format!("expected a refusal, got {other:?}").into()),
    }
}

#[test]
fn the_agents_form_of_tasks_wait_parses() -> TestResult {
    let input: TaskWaitInput = serde_json::from_value(serde_json::json!({
        "agents": ["00112233445566778899aabbccddeeff"],
        "n_of": 1,
        "step_key": "children",
    }))?;
    assert!(matches!(input, TaskWaitInput::Agents(_)));
    // It names no deadline, and no reader child beside the agents.
    for extra in ["until", "tasks", "request"] {
        let mut body = serde_json::json!({
            "agents": ["00112233445566778899aabbccddeeff"],
            "step_key": "children",
        });
        body[extra] = serde_json::json!(1);
        assert!(serde_json::from_value::<TaskWaitInput>(body).is_err());
    }
    Ok(())
}

#[test]
fn a_run_waits_on_its_agent_children_and_a_done_wait_is_kept() -> TestResult {
    let dir = tempfile::tempdir()?;
    let vault = open_vault(dir.path())?;
    let (parent, actor) = root_run(&vault, RUN, 1)?;
    let leased = claim(&vault, parent)?;
    let first = spawn_child(&vault, parent, RUN, "first", 2)?;
    let second = spawn_child(&vault, parent, RUN, "second", 3)?;
    let both = [first, second];
    let host = HostSelfDispatcher::for_leased_agent_attempt(&vault, actor, &leased)?;

    // Nothing has ended: both waits answer what is pending, and no reply
    // stands for a run parked on either.
    let every = host.wait_agents_from_host(wait_on(&both, None, "every-child"))?;
    assert!(!every.done);
    assert_eq!(every.reason, None);
    assert!(every.settled.is_empty());
    assert_eq!(every.pending, vec![hex(first), hex(second)]);
    let quorum = host.wait_agents_from_host(wait_on(&both, Some(1), "first-of-two"))?;
    assert!(!quorum.done);
    assert_ne!(quorum.wait, every.wait);
    assert_eq!(delivered(&vault, &every.wait)?, None);
    assert_eq!(delivered(&vault, &quorum.wait)?, None);

    // The write that ends the first child reduces the quorum wait, keeps the
    // reduction and delivers it, with no call in between.
    complete(&vault, first)?;
    let kept = delivered(&vault, &quorum.wait)?
        .ok_or("the quorum wait's reply is delivered when its first child ends")?;
    assert!(kept.done);
    assert_eq!(kept.reason.as_deref(), Some("quorum"));
    assert_eq!(kept.wait, quorum.wait);
    assert_eq!(kept.settled.len(), 1);
    assert_eq!(kept.settled[0].attempt, hex(first));
    assert_eq!(kept.settled[0].state, "completed");
    assert_eq!(kept.pending, vec![hex(second)]);
    // The wait over every child still waits on the second.
    let waiting = host.wait_agents_from_host(wait_on(&both, None, "every-child"))?;
    assert!(!waiting.done);
    assert_eq!(waiting.settled.len(), 1);
    assert_eq!(waiting.pending, vec![hex(second)]);
    assert_eq!(delivered(&vault, &every.wait)?, None);

    // The second child ends it, and its reply is delivered in that write.
    complete(&vault, second)?;
    let done = delivered(&vault, &every.wait)?
        .ok_or("the wait's reply is delivered when its last child ends")?;
    assert!(done.done);
    assert_eq!(done.reason.as_deref(), Some("all"));
    assert!(done.pending.is_empty());
    assert_eq!(
        done.settled
            .iter()
            .map(|child| (child.attempt.clone(), child.state.clone()))
            .collect::<Vec<_>>(),
        vec![
            (hex(first), "completed".to_owned()),
            (hex(second), "completed".to_owned()),
        ]
    );
    assert_eq!(
        host.wait_agents_from_host(wait_on(&both, None, "every-child"))?,
        done
    );
    // The quorum wait answers what it kept when the first child ended, not
    // the children as they stand now.
    assert_eq!(
        host.wait_agents_from_host(wait_on(&both, Some(1), "first-of-two"))?,
        kept
    );
    // The same step key over other children is another wait.
    let changed = host
        .wait_agents_from_host(wait_on(&[first], None, "every-child"))
        .expect_err("a step key names one wait");
    assert_eq!(changed.code, "task_wait_changed");

    // After a restart the same keys answer the same, through the run's own
    // call as through the host door.
    drop(host);
    drop(vault);
    let vault = open_vault(dir.path())?;
    assert_eq!(
        answer(wait_as_run(
            &vault,
            actor,
            parent,
            &both,
            None,
            "every-child"
        )?)?,
        done
    );
    assert_eq!(
        answer(wait_as_run(
            &vault,
            actor,
            parent,
            &both,
            Some(1),
            "first-of-two"
        )?)?,
        kept
    );
    Ok(())
}

#[test]
fn a_wait_names_only_children_the_callers_run_spawned() -> TestResult {
    let dir = tempfile::tempdir()?;
    let vault = open_vault(dir.path())?;
    let (parent, actor) = root_run(&vault, RUN, 1)?;
    let leased = claim(&vault, parent)?;
    let own = spawn_child(&vault, parent, RUN, "own", 2)?;
    // Another run of the same agent, and the child it spawned.
    let (other, _) = root_run(&vault, "another-run", 3)?;
    let theirs = spawn_child(&vault, other, "another-run", "theirs", 4)?;
    let host = HostSelfDispatcher::for_leased_agent_attempt(&vault, actor, &leased)?;

    // A root run, another run's child, an attempt no row names, and a set
    // with one such member: each miss is the same refusal.
    for (case, agents) in [
        ("a root run", vec![other]),
        ("another run's child", vec![theirs]),
        ("no such attempt", vec![AttemptId::now()]),
        ("one stranger among two", vec![own, theirs]),
    ] {
        let refused = host
            .wait_agents_from_host(wait_on(&agents, None, case))
            .expect_err(case);
        assert_eq!(refused.code, "task_wait_not_own", "{case}");
    }
    // The other run's attempt cannot wait on this run's child either, by the
    // run's own call.
    assert_eq!(
        refusal(wait_as_run(&vault, actor, other, &[own], None, "reach")?)?,
        "task_wait_not_own"
    );

    // A wait with no child, a repeated child, a quorum past its children, or
    // an id that is no attempt id is no wait.
    for (case, request) in [
        ("no child", wait_on(&[], None, "none")),
        ("a repeated child", wait_on(&[own, own], None, "twice")),
        (
            "a quorum past its children",
            wait_on(&[own], Some(2), "past"),
        ),
        (
            "no attempt id",
            TaskWaitAgentsRequest {
                agents: vec!["not-an-attempt".to_owned()],
                all: None,
                n_of: None,
                step_key: "bad".to_owned(),
            },
        ),
    ] {
        let refused = host.wait_agents_from_host(request).expect_err(case);
        assert_eq!(refused.code, "task_wait_invalid", "{case}");
    }

    // A refused call keeps nothing: the run's own child still opens a wait
    // under a key a refusal used.
    let pending = host.wait_agents_from_host(wait_on(&[own], None, "a root run"))?;
    assert!(!pending.done);
    assert_eq!(pending.pending, vec![hex(own)]);
    Ok(())
}
