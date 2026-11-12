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
//! - A retried child is one child: the wait that named its first try is
//!   answered when its newest try ends, and two tries of it are no two
//!   children.
//!
//! On main the request and answer types and the host door do not exist, and
//! `tasks.wait`'s input parses no `agents` member, so this file does not
//! compile there. Public paths only:
//! `cargo test --locked -p oneiron --all-features --test run_wait_agents`.

use oneiron::agent_dispatch::{
    AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher, AgentSpawnContext,
    AgentWaitSetResult, DEFAULT_BASE_LOGICAL_ID, DispatchAgent, agent_dispatch_actor,
};
use oneiron::attempt_queue::{
    AttemptRecord, ClaimAttempt, ClaimOutcome, CompleteAttempt, RetryAttempt, RetryOutcome,
};
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

#[test]
fn a_retried_child_is_one_child_and_its_newest_try_answers_the_wait() -> TestResult {
    let dir = tempfile::tempdir()?;
    let vault = open_vault(dir.path())?;
    let (parent, actor) = root_run(&vault, RUN, 1)?;
    let leased = claim(&vault, parent)?;
    let child = spawn_child(&vault, parent, RUN, "retried", 2)?;
    let host = HostSelfDispatcher::for_leased_agent_attempt(&vault, actor, &leased)?;
    let waiting = host.wait_agents_from_host(wait_on(&[child], None, "the-child"))?;
    assert!(!waiting.done);

    // The child's first try fails and is retried: the spawn's place passes
    // to a new try under a new id.
    let first_try = claim(&vault, child)?;
    let claimed_at = first_try.claimed_at.ok_or("a claim records its time")?;
    let RetryOutcome::Retried(retry) = AttemptQueue::new(&vault).retry(RetryAttempt {
        id: child,
        lease_owner: WORKER.to_owned(),
        attempt_count: first_try.attempt_count,
        backoff_until: claimed_at,
        last_error: Some("the first try failed".to_owned()),
        now: claimed_at,
    })?
    else {
        return Err("a retry schedules a new try".into());
    };
    assert_eq!(retry.retry_of, Some(child));
    // The first try has ended, the child has not: the wait still waits.
    let still = host.wait_agents_from_host(wait_on(&[child], None, "the-child"))?;
    assert!(!still.done);
    assert_eq!(still.pending, vec![hex(child)]);
    assert_eq!(delivered(&vault, &waiting.wait)?, None);
    // Both ids name one child, so a wait over the two is no wait of two.
    let twice = host
        .wait_agents_from_host(wait_on(&[child, retry.id], Some(2), "both-tries"))
        .expect_err("two tries of one child");
    assert_eq!(twice.code, "task_wait_invalid");

    // The newest try ends the child, and the write that ends it answers the
    // wait that named the first try.
    complete(&vault, retry.id)?;
    let done = delivered(&vault, &waiting.wait)?
        .ok_or("the wait is delivered when the child's newest try ends")?;
    assert!(done.done);
    assert_eq!(done.reason.as_deref(), Some("all"));
    assert_eq!(done.settled.len(), 1);
    assert_eq!(done.settled[0].attempt, hex(child));
    assert_eq!(done.settled[0].state, "completed");
    Ok(())
}

#[cfg(oneiron_test_support)]
#[test]
fn a_metered_task_child_settles_its_task_row_scope_and_wait_in_one_write() -> TestResult {
    use oneiron::EdgeActorClass;
    use oneiron::agent_dispatch::budget_doors::OpenSpendLeaseRequest;
    use oneiron::agent_dispatch::{LAUNCH_COST_PRIOR_UNITS, SpendScopeId, SpendState};
    use oneiron::attempt_queue::{AttemptResultRef, AttemptState, SetAttemptResult};
    use oneiron::context_board::TaskBoardStatus;
    use oneiron::dreamer_runner::{
        CompleteDreamerAttempt, CompleteDreamerAttemptOutcome, DreamerRunnerStore,
    };
    use oneiron::task_verb::{
        HostBinding, TaskAssignee, TaskCreateSpec, TaskRouteOutcome, TaskTerminalDisposition,
    };
    use oneiron::test_doors::code_run_answer::install_actor_ceiling;
    use oneiron::test_doors::spend::reserve_child_scope;

    let dir = tempfile::tempdir()?;
    let vault = open_vault(dir.path())?;
    let (parent, actor) = root_run(&vault, RUN, 1)?;
    // The definition is Auto; its actor also needs an Auto policy ceiling
    // for a create to dispatch immediately rather than park a proposal.
    install_actor_ceiling(&vault, &actor.entity_ref(), "auto")?;
    let parent_lease = claim(&vault, parent)?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let launch_cap_units = 1_000;
    let parent_cap_units = 100;
    let spent_units = 3;
    oneiron::verbs::vault_budgets_lease_open(
        &vault.memory(owner, EdgeActorClass::Human),
        OpenSpendLeaseRequest {
            launch: "task-child-settlement".to_owned(),
            cap_units: launch_cap_units,
            unit: "units".to_owned(),
            shown_at_ms: 1,
            funding_grant_ref: None,
        },
    )?;
    let launch = SpendScopeId::launch("task-child-settlement")?;
    let parent_scope = SpendScopeId::for_attempt(&parent);
    reserve_child_scope(&vault, &launch, &parent, parent_cap_units, 1)?;
    let memory = vault
        .memory(actor.entity_ref(), actor.actor_class())
        .with_task_host(HostBinding::from_leased(&parent_lease, None)?);
    // No typed brief: the runner's durable result is sufficient for Done,
    // with no model verdict or confession needed. The bound creator makes
    // the TASK's realizing dispatch a child under the parent's open scope.
    let created = memory.tasks_create(
        &TaskCreateSpec::new(
            rmpv::Value::Nil,
            Some("settle a metered child".to_owned()),
            None,
            Some(2),
        )
        .with_assignee(TaskAssignee::AgentDef {
            agent_def_ref: actor.entity_ref(),
        }),
    )?;
    let task = created.task_ref.ok_or("the child TASK is created")?;
    let Some(TaskRouteOutcome::AgentDispatch {
        attempt_ref: child, ..
    }) = created.route
    else {
        return Err("the bound TASK dispatches an agent child".into());
    };
    let dispatcher = AgentDispatcher::new(&vault);
    let child_scope = SpendScopeId::for_attempt(&child);
    // With no calibration or budget pin, dispatch holds the smaller of
    // LAUNCH_COST_PRIOR_UNITS and the fixture's 100-unit parent carve.
    let reserved_units = LAUNCH_COST_PRIOR_UNITS.min(parent_cap_units);
    let unused_units = reserved_units - spent_units;
    let opened = dispatcher
        .read_spend_scope(&child_scope)?
        .ok_or("dispatch reserves the child's spend scope")?;
    assert_eq!(opened.parent, Some(parent_scope.clone()));
    assert_eq!(opened.state, SpendState::Open);
    assert_eq!(opened.cap_units, reserved_units);
    assert_eq!(opened.spent_units, 0);
    assert_eq!(opened.held_units, 0);
    let before = dispatcher
        .read_spend_scope(&parent_scope)?
        .ok_or("the parent's carved scope exists")?;
    assert_eq!(before.state, SpendState::Open);
    assert_eq!(before.cap_units, parent_cap_units);
    assert_eq!(before.spent_units, 0);
    assert_eq!(before.held_units, reserved_units);

    let host = HostSelfDispatcher::for_leased_agent_attempt(&vault, actor, &parent_lease)?;
    let waiting = host.wait_agents_from_host(wait_on(&[child], None, "metered-task-child"))?;
    assert!(!waiting.done);
    assert!(waiting.settled.is_empty());
    assert_eq!(waiting.pending, vec![hex(child)]);
    assert_eq!(delivered(&vault, &waiting.wait)?, None);

    let leased = claim(&vault, child)?;
    let task_hex = task.to_hex();
    assert_eq!(leased.task_ref.as_deref(), Some(task_hex.as_str()));
    assert_eq!(leased.lease_owner.as_deref(), Some(WORKER));
    let result = vault.create_note("research", "the child's durable result", actor)?;
    let result_hex = result.to_hex();
    AttemptQueue::new(&vault).set_result(SetAttemptResult {
        id: child,
        lease_owner: WORKER.to_owned(),
        attempt_count: leased.attempt_count,
        result_ref: AttemptResultRef::new(result_hex.clone())?,
        now: leased.updated_at,
    })?;
    // This fixture explicitly books 3 units, not the estimated reservation.
    dispatcher.record_guard_spend(&child_scope, spent_units)?;
    let completed = DreamerRunnerStore::new(&vault).complete(CompleteDreamerAttempt {
        id: child,
        lease_owner: WORKER.to_owned(),
        attempt_count: leased.attempt_count,
        now: leased.updated_at,
    })?;
    assert!(matches!(
        completed,
        CompleteDreamerAttemptOutcome::Completed(_)
    ));

    // These public readers have no common snapshot door: read the TASK,
    // attempt, both scopes and delivered reply consecutively, with no write
    // between them. This checks the completed call's durable results, not
    // that a concurrent reader could never see an intermediate transaction.
    let tasks = memory.describe_rows()?;
    let row = AttemptQueue::new(&vault)
        .get(child)?
        .ok_or("the completed child row exists")?;
    let closed = dispatcher
        .read_spend_scope(&child_scope)?
        .ok_or("the settled child scope exists")?;
    let charged = dispatcher
        .read_spend_scope(&parent_scope)?
        .ok_or("the charged parent scope exists")?;
    let reply = delivered(&vault, &waiting.wait)?;

    let task_row = tasks
        .intents
        .iter()
        .find(|intent| intent.id == task_hex)
        .ok_or("the TASK's durable report reads back")?;
    assert_eq!(
        task_row.terminal_disposition,
        Some(TaskTerminalDisposition::Completed),
        "the runner completion must write the TASK's Done fact"
    );
    assert_eq!(task_row.status, TaskBoardStatus::Done);
    assert_eq!(task_row.result_ref.as_deref(), Some(result_hex.as_str()));
    assert_eq!(row.state, AttemptState::Completed);
    assert_eq!(
        row.result_ref.as_ref().map(AttemptResultRef::as_str),
        Some(result_hex.as_str())
    );
    assert_eq!(row.lease_owner, None);
    assert_eq!(
        closed.state,
        SpendState::Closed,
        "the runner completion must close the child's spend scope"
    );
    assert_eq!(closed.closed_at, Some(leased.updated_at));
    assert_eq!(closed.spent_units, spent_units);
    assert_eq!(closed.held_units, 0);
    assert_eq!(charged.state, SpendState::Open);
    assert_eq!(
        charged.spent_units, spent_units,
        "the parent pays the child's 3 booked units"
    );
    assert_eq!(
        charged.held_units, 0,
        "the child's entire reservation is no longer held"
    );
    assert_eq!(charged.local_available(), parent_cap_units - spent_units);
    assert_eq!(
        charged.local_available() - before.local_available(),
        unused_units,
        "the unused part of the child's reservation returns to the parent"
    );
    let reply = reply.ok_or("completion delivers the parent's child wait")?;
    assert!(reply.done);
    assert_eq!(reply.wait, waiting.wait);
    assert_eq!(reply.reason.as_deref(), Some("all"));
    assert!(reply.pending.is_empty());
    assert_eq!(reply.settled.len(), 1);
    assert_eq!(reply.settled[0].attempt, hex(child));
    assert_eq!(reply.settled[0].state, "completed");
    assert_eq!(
        reply.settled[0].result_ref.as_deref(),
        Some(result_hex.as_str())
    );
    Ok(())
}
