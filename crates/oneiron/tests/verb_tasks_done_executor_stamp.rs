//! A met DONE through the public `tasks.update` stamps the executor model of the
//! authenticated host run it came through (LEARN-CRITIC Q2), so the completed try can
//! be sealed. An agent takes a TASK addressed to it on its external lane, from a run
//! the host leased and stamped through the production stamp
//! (`AttemptQueue::set_executor_model`), and reports DONE through
//! `oneiron::task_verb::sdk::invoke`, JSON in and JSON out. The held try then carries
//! the run's model, and the owner's seal confession (the `vault.seal.confess` call)
//! admits it. A model string in the report is never read. A DONE with no host, a
//! binding whose lease no longer holds, a binding of another agent's run, an unstamped
//! run and a try that already holds a model each lend nothing new, and each DONE still
//! lands.
//! Run with `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test verb_tasks_done_executor_stamp`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::agent_dispatch::{
    AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher, DispatchAgent,
};
use oneiron::attempt_queue::{
    AttemptId, AttemptQueue, AttemptRecord, AttemptState, ClaimAttempt, ClaimOutcome,
};
use oneiron::authority::{ActSurface, AgentTier, MachineRole};
use oneiron::claim::base_world_id;
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeId};
use oneiron::learning::TypeRef;
use oneiron::memory::{Memory, MemoryError};
use oneiron::registry::ENTITY_TYPE_TURN;
use oneiron::self_heal::audit::doors::confess_as_owner;
use oneiron::self_heal::audit::{AttemptConfession, ObjectiveConfession};
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::invoke;
use oneiron::task_verb::{AttemptHandle, HostBinding, TaskHandle};
use oneiron::temporal::TimeRange;
use oneiron::test_doors::derive_verbs::define_agent;
use oneiron::verbs::{AgentGrantMintRequest, mint_agent_grant_as};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_store::ports::manual_clock::ManualClock;
use serde_json::{Value, json};

/// The model and revision the host ran the agent's run on.
const RUN_MODEL: &str = "fixture/run-model@rev-a";
/// A model a caller names in its own report text.
const FORGED_MODEL: &str = "fixture/forged-model@rev-b";
/// A model another host stamped on the held try before the DONE.
const FIRST_MODEL: &str = "fixture/first-model@rev-c";
const RUN_LEASE_OWNER: &str = "executor-stamp-host";

/// The vault clock's fixed time for every test here: no wall time, no sleeps.
const T0: u64 = 1_780_000_000;

struct Fixture {
    vault: Vault,
    _dir: tempfile::TempDir,
    owner: EntityId,
}

/// A rooted vault with its install enrolled and its embedded owner.
fn rooted_vault() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let clock = ManualClock::new(T0);
    let mut config = VaultConfig::device();
    config.store_clock = clock.bundle();
    let vault = Vault::open(dir.path(), config).expect("open vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.prepare_install_signing().expect("install signing");
    let issuer = vault.bootstrap_host_slip_issuer().expect("host issuer");
    vault.ensure_host_root_slip(&issuer).expect("host root");
    vault
        .provision_engine_machine_identities(&issuer)
        .expect("engine machine identities");
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("serving install profile");
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    Fixture {
        vault,
        _dir: dir,
        owner,
    }
}

fn owner_proof(fixture: &Fixture) -> AuthenticatedOwner {
    fixture
        .vault
        .authenticate_owner(
            fixture.owner,
            &fixture.owner.to_hex(),
            true,
            GateDecisionId::now(),
        )
        .expect("owner proof")
}

fn owner_memory(fixture: &Fixture) -> Memory<'_> {
    fixture.vault.memory(fixture.owner, EdgeActorClass::Human)
}

/// `name`'s agent definition with an owner Grant of base reach: the generated
/// reference check reads each record a call names (`tasks.accept`'s and
/// `tasks.update`'s `task_ref`) with the caller's own key, so an agent with no
/// Grant reads no TASK and its call is refused before the verb runs.
fn granted_agent(fixture: &Fixture, name: &str) -> EntityId {
    let agent = define_agent(&fixture.vault, name).expect("agent");
    let mut authority_scope = Scope::top();
    authority_scope.worlds = [ScopeId(base_world_id())].into_iter().collect();
    authority_scope.verbs = AgentTier::FullAccess
        .grant_verbs()
        .iter()
        .map(|verb| (*verb).to_owned())
        .collect();
    let minted = mint_agent_grant_as(
        &fixture.vault,
        &owner_proof(fixture),
        ActSurface::ThisInstall,
        AgentGrantMintRequest {
            agent,
            authority_scope,
            expires_at: None,
            repo_bounds: None,
            verb_classes: BTreeSet::new(),
            wallet_ref: None,
            working_view_bounds: None,
        },
    )
    .expect("the owner grants the agent base reach");
    assert!(minted.grant.confers, "the grant confers");
    agent
}

/// One run of `agent`, dispatched and leased by the host, as the host holds the run
/// an agent's calls go through.
fn leased_run(fixture: &Fixture, agent: EntityId) -> AttemptRecord {
    let now = fixture.vault.now_recorded_at();
    let AgentDispatchOutcome::Dispatched(status) = AgentDispatcher::new(&fixture.vault)
        .dispatch(DispatchAgent {
            target: AgentDispatchTarget::Custom(agent),
            parent_attempt: None,
            dedupe_key: None,
            run_id: None,
            now,
        })
        .expect("dispatch the agent's run")
    else {
        panic!("the agent's run was not dispatched");
    };
    let ClaimOutcome::Claimed(leased) = AttemptQueue::new(&fixture.vault)
        .claim(ClaimAttempt {
            lease_owner: RUN_LEASE_OWNER.into(),
            now,
        })
        .expect("claim the run")
    else {
        panic!("the agent's run was not leased");
    };
    assert_eq!(leased.id, status.attempt.id, "the dispatched run is leased");
    leased
}

/// The host's own stamp of the model it runs `run` on, through the production stamp.
fn stamp_run(fixture: &Fixture, run: &AttemptRecord, model: &str) -> AttemptRecord {
    AttemptQueue::new(&fixture.vault)
        .set_executor_model(run.id, RUN_LEASE_OWNER, run.attempt_count, model)
        .expect("the host stamps its run's model")
}

/// `agent`'s Memory bound to `run`'s lease, as the host binds an agent's call.
fn hosted<'a>(fixture: &'a Fixture, agent: EntityId, run: &AttemptRecord) -> Memory<'a> {
    let binding = HostBinding::from_leased(run, None).expect("host binding");
    fixture
        .vault
        .memory(agent, EdgeActorClass::Agent)
        .with_task_host(binding)
}

/// The owner's TASK addressed to `agent` as a spawned child: the external lane.
fn task_for(fixture: &Fixture, agent: EntityId) -> EntityId {
    let receipt = invoke(
        &owner_memory(fixture),
        "tasks.create",
        json!({
            "spec": { "summary": "summarize the week's notes" },
            "assignee": { "child": { "actor_ref": agent.to_hex() } },
        }),
    )
    .expect("the owner creates the task");
    serde_json::from_value(receipt["task_ref"].clone())
        .unwrap_or_else(|error| panic!("no created task ({error}): {receipt}"))
}

/// The agent's accept of `task`; the try handle it returns.
fn accept(memory: &Memory<'_>, task: EntityId) -> AttemptHandle {
    let receipt = invoke(
        memory,
        "tasks.accept",
        json!({ "task_ref": task.to_hex(), "intent_key": "take-the-task" }),
    )
    .expect("the assignee accepts");
    match serde_json::from_value::<TaskHandle>(receipt["handle"].clone()) {
        Ok(TaskHandle::Attempt(handle)) => handle,
        other => panic!("the accept named no try ({other:?}): {receipt}"),
    }
}

/// A durable row the DONE names as its result.
fn result_row(fixture: &Fixture) -> EntityId {
    let id = EntityId::now();
    let at = fixture.vault.now_recorded_at();
    let body = rmp_serde::to_vec_named(&std::collections::BTreeMap::from([("role", "user")]))
        .expect("a TURN body");
    fixture
        .vault
        .put_entity(
            &id,
            ENTITY_TYPE_TURN,
            TimeRange { start: at, end: at },
            at,
            &body,
        )
        .expect("the result row");
    id
}

/// The `tasks.update` DONE wire for `task` on `handle`; `done` carries any extra text.
fn done_request(task: EntityId, handle: &AttemptHandle, result: EntityId, extra: Value) -> Value {
    let mut done = json!({ "result_ref": result.to_hex() });
    if let (Some(done), Some(extra)) = (done.as_object_mut(), extra.as_object()) {
        done.extend(extra.clone());
    }
    json!({
        "task_ref": task.to_hex(),
        "report_key": "done-once",
        "attempt": serde_json::to_value(handle).expect("handle wire"),
        "report": { "done": done },
    })
}

fn report_done(
    memory: &Memory<'_>,
    task: EntityId,
    handle: &AttemptHandle,
    result: EntityId,
    extra: Value,
) -> Value {
    invoke(
        memory,
        "tasks.update",
        done_request(task, handle, result, extra),
    )
    .expect("the DONE lands")
}

/// The held try as stored: completed with the DONE's result.
fn completed_try(fixture: &Fixture, handle: &AttemptHandle, result: EntityId) -> AttemptRecord {
    let record = AttemptQueue::new(&fixture.vault)
        .get(handle.attempt_ref)
        .expect("read the try")
        .expect("the try exists");
    assert_eq!(
        record.state,
        AttemptState::Completed,
        "the DONE completes the try"
    );
    assert_eq!(
        record
            .result_ref
            .as_ref()
            .map(|result| result.as_str().to_owned()),
        Some(result.to_hex()),
        "the try holds the DONE's result"
    );
    record
}

/// The owner's seal confession of `attempt`, measured against `subject`.
fn confess(
    fixture: &Fixture,
    attempt: AttemptId,
    subject: EntityId,
) -> oneiron::Result<oneiron::self_heal::audit::doors::SealReceiptView> {
    confess_as_owner(
        &fixture.vault,
        &owner_proof(fixture),
        &AttemptConfession {
            attempt,
            subject,
            type_ref: TypeRef::root(1),
            objectives: vec![ObjectiveConfession {
                objective: "summarize the week's notes".to_owned(),
                met: Some(true),
                flaw: None,
                uncertainty: None,
            }],
        },
    )
}

fn assert_unsealable(fixture: &Fixture, attempt: AttemptId, subject: EntityId) {
    let error = confess(fixture, attempt, subject)
        .expect_err("a try with no executor revision is not sealed");
    assert!(
        error.to_string().contains("executor revision"),
        "refused for its missing executor revision: {error}"
    );
}

#[test]
fn a_hosted_done_stamps_the_runs_executor_and_the_try_is_sealed() {
    let fixture = rooted_vault();
    let agent = granted_agent(&fixture, "executor-stamp-agent");
    let run = stamp_run(&fixture, &leased_run(&fixture, agent), RUN_MODEL);
    let task = task_for(&fixture, agent);
    let memory = hosted(&fixture, agent, &run);
    let handle = accept(&memory, task);
    let result = result_row(&fixture);

    report_done(&memory, task, &handle, result, json!({}));

    let record = completed_try(&fixture, &handle, result);
    assert_eq!(
        record.executor_model.as_deref(),
        Some(RUN_MODEL),
        "the held try carries the host run's model"
    );
    let sealed = confess(&fixture, handle.attempt_ref, agent).expect("the owner seals the try");
    let sealed = serde_json::to_value(&sealed).expect("seal wire");
    assert_eq!(
        sealed["receipt"]["executor"].as_str(),
        Some(RUN_MODEL),
        "the seal names the host run's model: {sealed}"
    );
    assert_eq!(
        sealed["receipt"]["passing"].as_bool(),
        Some(true),
        "a completed try is passing: {sealed}"
    );
}

#[test]
fn a_model_named_in_the_report_is_never_stamped() {
    let fixture = rooted_vault();
    let agent = granted_agent(&fixture, "executor-stamp-agent");
    let run = stamp_run(&fixture, &leased_run(&fixture, agent), RUN_MODEL);
    let task = task_for(&fixture, agent);
    let memory = hosted(&fixture, agent, &run);
    let handle = accept(&memory, task);
    let result = result_row(&fixture);

    let mut top_level = done_request(task, &handle, result, json!({}));
    top_level["executor_model"] = json!(FORGED_MODEL);
    let error: MemoryError = invoke(&memory, "tasks.update", top_level)
        .expect_err("the request names no executor field");
    assert!(
        error.to_string().contains("executor_model"),
        "the unknown field is refused: {error}"
    );

    report_done(
        &memory,
        task,
        &handle,
        result,
        json!({ "executor_model": FORGED_MODEL, "executor": FORGED_MODEL }),
    );

    let record = completed_try(&fixture, &handle, result);
    assert_eq!(
        record.executor_model.as_deref(),
        Some(RUN_MODEL),
        "the stamp is the host run's model, never the report's text"
    );
}

#[test]
fn a_wire_done_stamps_nothing_and_the_try_stays_unsealed() {
    let fixture = rooted_vault();
    let agent = granted_agent(&fixture, "executor-stamp-agent");
    let _run = stamp_run(&fixture, &leased_run(&fixture, agent), RUN_MODEL);
    let task = task_for(&fixture, agent);
    let wire = fixture.vault.memory(agent, EdgeActorClass::Agent);
    let handle = accept(&wire, task);
    let result = result_row(&fixture);

    report_done(
        &wire,
        task,
        &handle,
        result,
        json!({ "executor_model": FORGED_MODEL }),
    );

    let record = completed_try(&fixture, &handle, result);
    assert_eq!(record.executor_model, None, "no host run, no stamp");
    assert_unsealable(&fixture, handle.attempt_ref, agent);
}

#[test]
fn a_binding_whose_lease_no_longer_holds_lends_nothing() {
    let fixture = rooted_vault();
    let agent = granted_agent(&fixture, "executor-stamp-agent");
    let run = stamp_run(&fixture, &leased_run(&fixture, agent), RUN_MODEL);
    let mut rebound = run.clone();
    rebound.lease_owner = Some("another-host".to_owned());
    let task = task_for(&fixture, agent);
    let memory = hosted(&fixture, agent, &rebound);
    let handle = accept(&memory, task);
    let result = result_row(&fixture);

    report_done(&memory, task, &handle, result, json!({}));

    let record = completed_try(&fixture, &handle, result);
    assert_eq!(
        record.executor_model, None,
        "a lease the run does not hold lends no model"
    );
    assert_unsealable(&fixture, handle.attempt_ref, agent);
}

#[test]
fn another_agents_run_lends_nothing() {
    let fixture = rooted_vault();
    let runner = granted_agent(&fixture, "executor-stamp-runner");
    let reporter = granted_agent(&fixture, "executor-stamp-reporter");
    let run = stamp_run(&fixture, &leased_run(&fixture, runner), RUN_MODEL);
    let task = task_for(&fixture, reporter);
    let memory = hosted(&fixture, reporter, &run);
    let handle = accept(&memory, task);
    let result = result_row(&fixture);

    report_done(&memory, task, &handle, result, json!({}));

    let record = completed_try(&fixture, &handle, result);
    assert_eq!(
        record.executor_model, None,
        "a run that writes as another agent lends no model"
    );
    assert_unsealable(&fixture, handle.attempt_ref, reporter);
}

#[test]
fn an_unstamped_run_lends_nothing() {
    let fixture = rooted_vault();
    let agent = granted_agent(&fixture, "executor-stamp-agent");
    let run = leased_run(&fixture, agent);
    let task = task_for(&fixture, agent);
    let memory = hosted(&fixture, agent, &run);
    let handle = accept(&memory, task);
    let result = result_row(&fixture);

    report_done(&memory, task, &handle, result, json!({}));

    let record = completed_try(&fixture, &handle, result);
    assert_eq!(
        record.executor_model, None,
        "a run the host never stamped stays unknown"
    );
    assert_unsealable(&fixture, handle.attempt_ref, agent);
}

#[test]
fn a_try_that_holds_a_model_keeps_it() {
    let fixture = rooted_vault();
    let agent = granted_agent(&fixture, "executor-stamp-agent");
    let run = stamp_run(&fixture, &leased_run(&fixture, agent), RUN_MODEL);
    let task = task_for(&fixture, agent);
    let memory = hosted(&fixture, agent, &run);
    let handle = accept(&memory, task);
    let held = AttemptQueue::new(&fixture.vault)
        .get(handle.attempt_ref)
        .expect("read the try")
        .expect("the try exists");
    AttemptQueue::new(&fixture.vault)
        .set_executor_model(
            held.id,
            held.lease_owner
                .as_deref()
                .expect("the accept leased the try"),
            held.attempt_count,
            FIRST_MODEL,
        )
        .expect("a host stamps the held try first");
    let result = result_row(&fixture);

    report_done(&memory, task, &handle, result, json!({}));

    let record = completed_try(&fixture, &handle, result);
    assert_eq!(
        record.executor_model.as_deref(),
        Some(FIRST_MODEL),
        "the first stamp stands; the DONE neither rebinds it nor fails"
    );
}
