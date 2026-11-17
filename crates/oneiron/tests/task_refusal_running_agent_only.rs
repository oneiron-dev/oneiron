//! Only the agent running a task can refuse it (ARCH-0079 promise-gate-08;
//! FIX [TASK-CANCEL-REFUSAL-NO-DOOR-TEST]). Two doors refuse, and each is
//! proved for the running agent and for another agent:
//!
//! - the refusal of a soft cancel, `AttemptQueue::reject_cancel`: the owner's
//!   ordinary `cancel` asks the running try to land; only the try's lease
//!   holder, at its live try count, answers with a refusal, and the try stays
//!   at work. Another agent's refusal, and the holder's at a stale try count,
//!   are refused and write nothing, so the ask stays owed.
//! - the refusal of the task itself, `Memory::land_task_refusal` (`tasks.refuse`):
//!   only the agent the task is addressed to refuses it. Another agent's
//!   refusal is refused. The running agent's Voice refusal records one
//!   objection, and the task goes on (promise-gate-06).
//!
//! In both tests the running agent's DONE lands after the refusal, so the
//! task stayed live.
//! Run with `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test task_refusal_running_agent_only`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::agent_def::{RefusalDomain, RefusalLevel, RefusalOutcome};
use oneiron::attempt_queue::{
    AttemptCancelReceiptKind, AttemptQueue, AttemptRecord, AttemptState, RejectAttemptCancel,
};
use oneiron::authority::{ActSurface, AgentTier, MachineRole};
use oneiron::claim::base_world_id;
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeId};
use oneiron::memory::Memory;
use oneiron::registry::ENTITY_TYPE_TURN;
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::invoke;
use oneiron::task_verb::{AttemptHandle, ConsultPayloadRef, SelfRefusalInput, TaskHandle};
use oneiron::temporal::TimeRange;
use oneiron::test_doors::derive_verbs::define_agent;
use oneiron::verbs::{AgentGrantMintRequest, mint_agent_grant_as};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_store::ports::manual_clock::ManualClock;
use serde_json::json;

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

fn agent_memory(fixture: &Fixture, agent: EntityId) -> Memory<'_> {
    fixture.vault.memory(agent, EdgeActorClass::Agent)
}

/// `name`'s agent definition with an owner Grant of base reach: the generated
/// reference check reads each record a call names with the caller's own key,
/// so an agent with no Grant reads no TASK and its call is refused before the
/// verb runs.
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

/// The owner's TASK addressed to `agent` as a spawned child: the external lane.
fn task_for(fixture: &Fixture, agent: EntityId) -> EntityId {
    let receipt = invoke(
        &owner_memory(fixture),
        "tasks.create",
        json!({
            "spec": { "summary": "file the week's receipts" },
            "assignee": { "child": { "actor_ref": agent.to_hex() } },
        }),
    )
    .expect("the owner creates the task");
    serde_json::from_value(receipt["task_ref"].clone())
        .unwrap_or_else(|error| panic!("no created task ({error}): {receipt}"))
}

/// The agent's accept of `task`: the try it now runs.
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

/// The try `handle` names, as stored.
fn stored_try(fixture: &Fixture, handle: &AttemptHandle) -> AttemptRecord {
    AttemptQueue::new(&fixture.vault)
        .get(handle.attempt_ref)
        .expect("read the try")
        .expect("the try exists")
}

/// A durable TURN row: a refusal's reason, or a DONE's result.
fn turn_row(fixture: &Fixture) -> EntityId {
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
        .expect("the TURN row");
    id
}

/// The running agent's met DONE of `task` on the try `handle` names; the try
/// then reads Completed.
fn done_lands(fixture: &Fixture, memory: &Memory<'_>, task: EntityId, handle: &AttemptHandle) {
    let result = turn_row(fixture);
    invoke(
        memory,
        "tasks.update",
        json!({
            "task_ref": task.to_hex(),
            "report_key": "done-once",
            "attempt": serde_json::to_value(handle).expect("handle wire"),
            "report": { "done": { "result_ref": result.to_hex() } },
        }),
    )
    .expect("the running agent's DONE lands");
    assert_eq!(
        stored_try(fixture, handle).state,
        AttemptState::Completed,
        "the DONE completes the try the agent kept running"
    );
}

/// A refusal of the outstanding soft cancel on `handle`'s try, under
/// `lease_owner` at `attempt_count`.
fn cancel_refusal(
    fixture: &Fixture,
    handle: &AttemptHandle,
    lease_owner: &str,
    attempt_count: u32,
) -> RejectAttemptCancel {
    RejectAttemptCancel {
        id: handle.attempt_ref,
        lease_owner: lease_owner.to_owned(),
        attempt_count,
        reason: "half the receipts are filed; stopping now loses the batch".to_owned(),
        status: Some("filing".to_owned()),
        request_sequence: None,
        now: fixture.vault.now_recorded_at(),
    }
}

#[test]
fn only_the_running_holder_refuses_a_soft_cancel() {
    let fixture = rooted_vault();
    let holder = granted_agent(&fixture, "cancel-refusal-holder");
    let outsider = granted_agent(&fixture, "cancel-refusal-outsider");
    let task = task_for(&fixture, holder);
    let holder_memory = agent_memory(&fixture, holder);
    let handle = accept(&holder_memory, task);
    let leased = stored_try(&fixture, &handle);
    assert_eq!(leased.state, AttemptState::Leased, "the accept runs the try");
    let holder_lease = leased
        .lease_owner
        .clone()
        .expect("the running try names its lease holder");

    // The owner's ordinary cancel asks the running try to land.
    let receipt = invoke(
        &owner_memory(&fixture),
        "cancel",
        json!({ "task_ref": task.to_hex() }),
    )
    .expect("the owner cancels");
    assert_eq!(
        (&receipt["cancel_requested"], &receipt["effected"]),
        (&json!(true), &json!(false)),
        "a running try is asked, not stopped: {receipt}"
    );
    let asked = stored_try(&fixture, &handle);
    assert_eq!(asked.state, AttemptState::Leased, "the ask stops nothing");
    assert_eq!(asked.cancel_state.pressure.pending, 1, "one ask is owed");
    let request = asked
        .cancel_state
        .receipts
        .iter()
        .find(|receipt| receipt.kind == AttemptCancelReceiptKind::SoftRequested)
        .expect("the ask is recorded on the try")
        .sequence;

    let queue = AttemptQueue::new(&fixture.vault);

    // Another agent cannot refuse the holder's cancel, and its call writes
    // nothing: the ask stays owed.
    let outsider_lease = format!("{}@unbound", outsider.to_hex());
    let refused = queue
        .reject_cancel(cancel_refusal(
            &fixture,
            &handle,
            &outsider_lease,
            handle.attempt_count,
        ))
        .expect_err("another agent cannot refuse the running try's cancel");
    assert!(
        refused
            .to_string()
            .contains("action=cancel_reject, state=leased_by_other"),
        "refused for its lease: {refused}"
    );
    assert_eq!(
        stored_try(&fixture, &handle),
        asked,
        "a refused refusal writes nothing"
    );

    // The holder's own lease at a try count it no longer runs is refused too.
    let stale = queue
        .reject_cancel(cancel_refusal(
            &fixture,
            &handle,
            &holder_lease,
            handle.attempt_count + 1,
        ))
        .expect_err("a refusal at a stale try count is refused");
    assert!(
        stale
            .to_string()
            .contains("action=cancel_reject, state=stale_attempt"),
        "refused for its try count: {stale}"
    );
    assert_eq!(
        stored_try(&fixture, &handle),
        asked,
        "a stale refusal writes nothing"
    );

    // The running holder's refusal lands, and the try stays at work.
    let answered = queue
        .reject_cancel(cancel_refusal(
            &fixture,
            &handle,
            &holder_lease,
            handle.attempt_count,
        ))
        .expect("the running holder refuses the cancel");
    assert_eq!(
        answered.answered_request_sequence, request,
        "the refusal answers the owner's ask"
    );
    assert_eq!(answered.record.state, AttemptState::Leased, "the try runs on");
    assert_eq!(
        answered.record.lease_owner.as_deref(),
        Some(holder_lease.as_str()),
        "the holder keeps its lease"
    );
    assert_eq!(
        (answered.pressure.pending, answered.pressure.rejections),
        (0, 1),
        "the ask is answered by one refusal"
    );
    let last = answered
        .record
        .cancel_state
        .receipts
        .last()
        .expect("the refusal is recorded");
    assert_eq!(
        (&last.kind, last.actor.as_str(), last.request_sequence),
        (
            &AttemptCancelReceiptKind::SoftRejected,
            holder_lease.as_str(),
            Some(request)
        ),
        "the refusal receipt names the holder and the ask it answers"
    );
    assert_eq!(
        stored_try(&fixture, &handle),
        answered.record,
        "the refusal is stored as answered"
    );

    done_lands(&fixture, &holder_memory, task, &handle);
}

#[test]
fn only_the_addressed_agent_refuses_the_task() {
    let fixture = rooted_vault();
    let holder = granted_agent(&fixture, "task-refusal-holder");
    let outsider = granted_agent(&fixture, "task-refusal-outsider");
    let task = task_for(&fixture, holder);
    let holder_memory = agent_memory(&fixture, holder);
    let handle = accept(&holder_memory, task);
    let input = SelfRefusalInput {
        domain: RefusalDomain::Logistics,
        reason_ref: ConsultPayloadRef::Turn(turn_row(&fixture)),
        at: fixture.vault.now_recorded_at(),
    };

    // Another agent cannot refuse a task addressed to the holder.
    let refused = agent_memory(&fixture, outsider)
        .land_task_refusal(task, &input)
        .expect_err("another agent cannot refuse the holder's task");
    assert!(
        format!("{refused:?}")
            .contains("only the addressed assignee may write this task's execution facts"),
        "refused as an unaddressed write: {refused:?}"
    );

    // The running agent's refusal lands through her dial: a personal vault's
    // logistics default is Voice, one objection, and the task goes on.
    let receipt = holder_memory
        .land_task_refusal(task, &input)
        .expect("the running agent refuses her task");
    assert!(
        !receipt.idempotent_replay,
        "the outsider's call left no refusal for this one to replay"
    );
    assert_eq!(
        (receipt.level, receipt.outcome),
        (RefusalLevel::Voice, RefusalOutcome::Object),
        "a Voice refusal is one objection"
    );
    assert_eq!(
        receipt.record.as_ref().map(|record| record.by),
        Some(holder),
        "the task's one refusal is the running agent's"
    );
    assert!(receipt.terminal.is_none(), "an objection settles nothing");
    assert_eq!(
        stored_try(&fixture, &handle).state,
        AttemptState::Leased,
        "the objection leaves the try running"
    );

    done_lands(&fixture, &holder_memory, task, &handle);
}
