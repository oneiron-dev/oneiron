//! [AGENT-WAIT-DEADLINE]: `tasks.wait({agents, all?, n_of?, until?,
//! step_key})` names a deadline, as the wait family's `until` form is canon
//! SDK (ARCH-0002). A wait over AGENT children is done at `until` at the
//! latest, as `cutoff`, with what is still pending.
//!
//! - A wait whose `until` has passed is done as `cutoff` with its children
//!   pending, through the host door and through the run's own call, and it
//!   keeps that answer after its children end.
//! - A wait whose `until` is still to come stays open. The due sweep before
//!   it takes nothing. The sweep at it, after a restart, delivers `cutoff` as
//!   the reply of a run parked on the wait, with the child that ended settled
//!   and the other pending, and a later sweep finds no row.
//! - A wait whose policy is met before its `until` leaves no due row, and a
//!   wait with no `until` is never swept.
//!
//! On main the agents form refuses `until`: the host door's input does not
//! parse it, and the run's own call answers `task_wait_invalid`. Nothing
//! sweeps due agent waits there. Public paths only:
//! `cargo test --locked -p oneiron --all-features --test run_wait_agents_until`.

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
const RUN: &str = "run-agent-wait-until";
/// The lease owner this test claims rows as.
const WORKER: &str = "run-wait-agents-until";
/// How far ahead a deadline still to come is set: far past any test's run.
const HOUR_MS: u64 = 60 * 60 * 1000;

/// A process-owned vault at `dir`, as an embedded owner opens it.
fn open_vault(dir: &std::path::Path) -> Result<Vault, TestError> {
    let mut config = VaultConfig::device();
    config.map_size = 32 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = None;
    Ok(Vault::open_owned(dir, config)?)
}

/// Unix milliseconds now: the clock a wait's `until` is on.
fn now_ms() -> Result<u64, TestError> {
    let elapsed = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?;
    Ok(u64::try_from(elapsed.as_millis())?)
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

/// The host door's input for a wait over `agents`, as its caller sends it:
/// with `until` when one is given.
fn wait_on(
    agents: &[AttemptId],
    n_of: Option<u32>,
    until: Option<u64>,
    step_key: &str,
) -> Result<TaskWaitAgentsRequest, TestError> {
    let mut body = serde_json::json!({
        "agents": agents.iter().copied().map(hex).collect::<Vec<_>>(),
        "n_of": n_of,
        "step_key": step_key,
    });
    if let Some(until) = until {
        body["until"] = serde_json::json!(until);
    }
    Ok(serde_json::from_value(body)?)
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
    until: u64,
    step_key: &str,
) -> Result<SelfDispatchOutcome, TestError> {
    let call: TaskWaitSetCall = serde_json::from_value(serde_json::json!({
        "tasks": [],
        "agents": agents.iter().copied().map(hex).collect::<Vec<_>>(),
        "n_of": n_of,
        "until": until,
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

/// Each child the reduction names as ended, with how it ended.
fn ended(result: &AgentWaitSetResult) -> Vec<(String, String)> {
    result
        .settled
        .iter()
        .map(|child| (child.attempt.clone(), child.state.clone()))
        .collect()
}

#[test]
fn a_wait_whose_until_has_passed_answers_cutoff_with_its_children_pending() -> TestResult {
    let dir = tempfile::tempdir()?;
    let vault = open_vault(dir.path())?;
    let (parent, actor) = root_run(&vault, RUN, 1)?;
    let leased = claim(&vault, parent)?;
    let first = spawn_child(&vault, parent, RUN, "first", 2)?;
    let second = spawn_child(&vault, parent, RUN, "second", 3)?;
    let both = [first, second];
    let host = HostSelfDispatcher::for_leased_agent_attempt(&vault, actor, &leased)?;

    // The run's `tasks.wait` input names `until` beside the agents.
    let input: TaskWaitInput = serde_json::from_value(serde_json::json!({
        "agents": [hex(first)],
        "until": 1,
        "step_key": "children",
    }))?;
    assert!(matches!(input, TaskWaitInput::Agents(_)));

    // Through the host door: its `until` has passed, so the wait is done as
    // `cutoff` with both children pending, kept, and delivered.
    let lapsed = host.wait_agents_from_host(wait_on(&both, None, Some(1), "lapsed")?)?;
    assert!(lapsed.done);
    assert_eq!(lapsed.reason.as_deref(), Some("cutoff"));
    assert!(lapsed.settled.is_empty());
    assert_eq!(lapsed.pending, vec![hex(first), hex(second)]);
    assert_eq!(delivered(&vault, &lapsed.wait)?, Some(lapsed.clone()));

    // Through the run's own call, a quorum wait the same.
    let run_lapsed = answer(wait_as_run(
        &vault,
        actor,
        parent,
        &both,
        Some(1),
        1,
        "run-lapsed",
    )?)?;
    assert!(run_lapsed.done);
    assert_eq!(run_lapsed.reason.as_deref(), Some("cutoff"));
    assert!(run_lapsed.settled.is_empty());
    assert_eq!(run_lapsed.pending, vec![hex(first), hex(second)]);
    assert_eq!(
        delivered(&vault, &run_lapsed.wait)?,
        Some(run_lapsed.clone())
    );

    // The children end: each wait answers what it kept at its cutoff.
    complete(&vault, first)?;
    complete(&vault, second)?;
    assert_eq!(
        host.wait_agents_from_host(wait_on(&both, None, Some(1), "lapsed")?)?,
        lapsed
    );
    assert_eq!(delivered(&vault, &lapsed.wait)?, Some(lapsed));
    assert_eq!(
        answer(wait_as_run(
            &vault,
            actor,
            parent,
            &both,
            Some(1),
            1,
            "run-lapsed"
        )?)?,
        run_lapsed
    );
    Ok(())
}

#[test]
fn a_wait_whose_until_comes_is_answered_cutoff_by_the_due_sweep_after_a_restart() -> TestResult {
    let dir = tempfile::tempdir()?;
    let vault = open_vault(dir.path())?;
    let (parent, actor) = root_run(&vault, RUN, 1)?;
    let leased = claim(&vault, parent)?;
    let first = spawn_child(&vault, parent, RUN, "first", 2)?;
    let second = spawn_child(&vault, parent, RUN, "second", 3)?;
    let both = [first, second];
    let host = HostSelfDispatcher::for_leased_agent_attempt(&vault, actor, &leased)?;
    let until = now_ms()? + HOUR_MS;

    // Its `until` is still to come: the wait is open, and nothing is
    // delivered.
    let open = host.wait_agents_from_host(wait_on(&both, None, Some(until), "bounded")?)?;
    assert!(!open.done);
    assert_eq!(open.reason, None);
    assert_eq!(open.pending, vec![hex(first), hex(second)]);
    assert_eq!(delivered(&vault, &open.wait)?, None);
    // The sweep before its `until` takes nothing.
    assert_eq!(vault.settle_due_agent_waits(until - 1)?, 0);
    assert_eq!(delivered(&vault, &open.wait)?, None);

    // One child ends; the wait over both still waits on the other.
    complete(&vault, first)?;
    let waiting = host.wait_agents_from_host(wait_on(&both, None, Some(until), "bounded")?)?;
    assert!(!waiting.done);
    assert_eq!(ended(&waiting), vec![(hex(first), "completed".to_owned())]);
    assert_eq!(waiting.pending, vec![hex(second)]);
    assert_eq!(delivered(&vault, &open.wait)?, None);

    // After a restart, the sweep at its `until` answers it as `cutoff` and
    // delivers that as the reply of a run parked on it.
    drop(host);
    drop(vault);
    let vault = open_vault(dir.path())?;
    assert_eq!(vault.settle_due_agent_waits(until)?, 1);
    let cut =
        delivered(&vault, &open.wait)?.ok_or("the sweep at the wait's until delivers its reply")?;
    assert!(cut.done);
    assert_eq!(cut.reason.as_deref(), Some("cutoff"));
    assert_eq!(cut.wait, open.wait);
    assert_eq!(ended(&cut), vec![(hex(first), "completed".to_owned())]);
    assert_eq!(cut.pending, vec![hex(second)]);

    // The run's own call under the same key answers what was kept, and a
    // later sweep finds no row.
    assert_eq!(
        answer(wait_as_run(
            &vault, actor, parent, &both, None, until, "bounded"
        )?)?,
        cut
    );
    assert_eq!(vault.settle_due_agent_waits(until + 1)?, 0);

    // The other child's end changes nothing kept.
    complete(&vault, second)?;
    assert_eq!(delivered(&vault, &open.wait)?, Some(cut));
    Ok(())
}

#[test]
fn an_early_quorum_leaves_no_due_row_and_a_wait_with_no_until_is_never_swept() -> TestResult {
    let dir = tempfile::tempdir()?;
    let vault = open_vault(dir.path())?;
    let (parent, actor) = root_run(&vault, RUN, 1)?;
    let leased = claim(&vault, parent)?;
    let first = spawn_child(&vault, parent, RUN, "first", 2)?;
    let second = spawn_child(&vault, parent, RUN, "second", 3)?;
    let both = [first, second];
    let host = HostSelfDispatcher::for_leased_agent_attempt(&vault, actor, &leased)?;
    let until = now_ms()? + HOUR_MS;

    let quorum =
        host.wait_agents_from_host(wait_on(&both, Some(1), Some(until), "first-in-time")?)?;
    assert!(!quorum.done);
    let unbounded = host.wait_agents_from_host(wait_on(&both, None, None, "every-child")?)?;
    assert!(!unbounded.done);

    // The first child's end meets the quorum before its `until`.
    complete(&vault, first)?;
    let met = delivered(&vault, &quorum.wait)?
        .ok_or("the quorum wait's reply is delivered when its first child ends")?;
    assert_eq!(met.reason.as_deref(), Some("quorum"));
    assert_eq!(met.pending, vec![hex(second)]);

    // No due row is left, at its `until` or at any later time, and the wait
    // with no `until` still waits.
    assert_eq!(vault.settle_due_agent_waits(until)?, 0);
    assert_eq!(vault.settle_due_agent_waits(u64::MAX)?, 0);
    assert_eq!(delivered(&vault, &quorum.wait)?, Some(met));
    assert_eq!(delivered(&vault, &unbounded.wait)?, None);
    let still = host.wait_agents_from_host(wait_on(&both, None, None, "every-child")?)?;
    assert!(!still.done);
    assert_eq!(still.pending, vec![hex(second)]);
    Ok(())
}
