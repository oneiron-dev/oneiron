//! Restriction wave 9, C53 and C54: two owner-only reads an owner may hand
//! to an agent by a Setting key. With `failure_ladder.drill.delegate` on for
//! an agent, that agent drills into a custom-agent failure
//! (`vault.healer.failure_drill_as`); with `self_heal.audit.delegate_read` on,
//! it reads seal receipts, pending checks and audit draws
//! (`vault.seal.receipt_as`, `.pending_as`, `.audit_as`). Each takes the
//! agent's own live Grant listing the verb, and each answer holds only what
//! the agent's read lane admits: a trace whose producers recorded no complete
//! read set stays the owner's (FIX 10093). With the key off (the default) the
//! agent is refused, and the owner's own doors answer as before.
//! Run with `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test agent_delegated_owner_reads`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::agent_dispatch::{
    AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher, DispatchAgent, HealerSlot,
};
use oneiron::attempt_queue::{
    AttemptId, AttemptInterventionKind, AttemptQueue, AttemptRecord, AttemptState, ClaimAttempt,
    ClaimOutcome, InterveneAttempt, ReadSetProducer,
};
use oneiron::authority::{ActSurface, AgentTier, MachineRole};
use oneiron::claim::base_world_id;
use oneiron::consent::AuthenticatedOwner;
use oneiron::failure_ladder::{
    FailureEscalationMode, FailureLadderOutcome, FailureScope, FailureScopePolicy,
    FailureSignalClass, HandleAttemptFailure, TypedFailureEvidence, TypedFailureVerdict,
};
use oneiron::federation::{Scope, ScopeId};
use oneiron::learning::TypeRef;
use oneiron::memory::{Memory, MemoryError};
use oneiron::registry::ENTITY_TYPE_TURN;
use oneiron::self_heal::audit::doors::{
    SealAttemptRequest, SealPendingRequest, confess_as_owner, pending_sourced_as_owner,
    receipt_as_owner,
};
use oneiron::self_heal::audit::{AttemptConfession, ObjectiveConfession};
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::invoke;
use oneiron::task_verb::{AttemptHandle, HostBinding, TaskHandle};
use oneiron::temporal::TimeRange;
use oneiron::test_doors::derive_verbs::define_agent;
use oneiron::verbs::{AgentGrantMintRequest, mint_agent_grant_as};
use oneiron::{DreamerRunnerStore, EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_store::ports::manual_clock::ManualClock;
use serde_json::{Value, json};

const DRILL_KEY: &str = "failure_ladder.drill.delegate";
const SEAL_KEY: &str = "self_heal.audit.delegate_read";
const DRILL_AS: &str = "vault.healer.failure_drill_as";
const RECEIPT_AS: &str = "vault.seal.receipt_as";
const PENDING_AS: &str = "vault.seal.pending_as";
const AUDIT_AS: &str = "vault.seal.audit_as";
const SET: &str = "vault.settings.set";
/// The agents' own read, named so a failing assert shows which rows its lane reads.
const REVISIONS_READ: &str = "vault.revisions.read";

const RUN_MODEL: &str = "fixture/run-model@rev-a";
const RUN_LEASE_OWNER: &str = "delegated-reads-host";
const FAILED_WORKER: &str = "delegated-reads-failed-worker";

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

/// `name`'s agent definition with an owner Grant of base reach, listing the
/// full-access tier's verbs and `extra`.
fn granted_agent(fixture: &Fixture, name: &str, extra: &[&str]) -> EntityId {
    let agent = define_agent(&fixture.vault, name).expect("agent");
    let mut authority_scope = Scope::top();
    authority_scope.worlds = [ScopeId(base_world_id())].into_iter().collect();
    authority_scope.verbs = AgentTier::FullAccess
        .grant_verbs()
        .iter()
        .chain(extra.iter())
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

/// The owner turns `key` on: for `agent` alone, or with `None` for every agent.
fn owner_turns_on(fixture: &Fixture, key: &str, agent: Option<EntityId>) {
    let scope = agent.map_or_else(
        || json!({ "kind": "vault" }),
        |agent| json!({ "kind": "agent", "id": agent.to_hex() }),
    );
    let applied = invoke(
        &owner_memory(fixture),
        SET,
        json!({ "key": key, "scope": scope, "value": true }),
    )
    .unwrap_or_else(|error| panic!("the owner sets {key}: {error:?}"));
    assert_eq!(applied["status"], json!("applied"), "{applied}");
}

/// What `agent`'s own read lane serves of `rows`, for an assert's message.
fn lane_view(fixture: &Fixture, agent: EntityId, rows: &[EntityId]) -> String {
    let refs: Vec<String> = rows.iter().map(EntityId::to_hex).collect();
    match invoke(
        &agent_memory(fixture, agent),
        REVISIONS_READ,
        json!({ "refs": refs }),
    ) {
        Ok(read) => format!("rows {refs:?} read as {read}"),
        Err(error) => format!("rows {refs:?} unread: {error:?}"),
    }
}

/// One run of `agent`, dispatched and leased by the host.
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

/// The attempt's producers report a complete read set of `rows` (FIX 7073).
fn record_complete_read_set(fixture: &Fixture, attempt: AttemptId, rows: Vec<EntityId>) {
    assert!(
        fixture
            .vault
            .declare_attempt_read_producers(attempt, &[ReadSetProducer::TOOL_ANSWERS])
            .expect("declare the producer"),
        "the live attempt takes the declaration"
    );
    assert!(
        fixture
            .vault
            .record_attempt_sources(attempt, ReadSetProducer::TOOL_ANSWERS, Some(rows))
            .expect("record the sources"),
        "the live attempt takes the report"
    );
}

/// A custom agent's run the failure ladder ended and the owner's review
/// recorded as a task failure; with `complete`, its read set was recorded
/// complete (and empty) while it ran.
fn failed_custom_run(fixture: &Fixture, complete: bool) -> AttemptId {
    let vault = &fixture.vault;
    let agent = define_agent(vault, FAILED_WORKER).expect("the failing agent");
    let leased = leased_run(fixture, agent);
    if complete {
        record_complete_read_set(fixture, leased.id, Vec::new());
    }
    let now = vault.now_recorded_at();
    AttemptQueue::new(vault)
        .intervene(InterveneAttempt {
            id: leased.id,
            kind: AttemptInterventionKind::Interrupt,
            actor: "operator".to_owned(),
            note: Some("stalled on the deploy step".to_owned()),
            now,
        })
        .expect("an operator note on the live try");
    let outcome = DreamerRunnerStore::new(vault)
        .fail_agent_dispatch_with_evidence(
            HandleAttemptFailure {
                attempt_id: leased.id,
                lease_owner: RUN_LEASE_OWNER.to_owned(),
                attempt_count: leased.attempt_count,
                evidence: TypedFailureEvidence {
                    evidence_ref: None,
                    verdict: TypedFailureVerdict::Indeterminate,
                    tier: None,
                    stable_reason: "step_failed".to_owned(),
                },
                blocked_reports: Vec::new(),
                pre_fail_checkpoint_ref: agent,
                qa_thread_ref: agent,
                retry_at: now + 10,
                now,
            },
            FailureScopePolicy {
                scope: FailureScope {
                    agent_ref: agent.to_hex(),
                    skill_ref: None,
                },
                max_consecutive_transients: std::num::NonZeroU16::MIN,
                escalation_mode: FailureEscalationMode::Human,
                healer_slot: HealerSlot::Reserved,
            },
        )
        .expect("the ladder ends the run");
    assert!(
        matches!(outcome, FailureLadderOutcome::Human(_)),
        "the failure surfaces to a person"
    );
    vault
        .record_custom_agent_failure(leased.id, FailureSignalClass::TaskFailure)
        .expect("the owner's review records the failure");
    leased.id
}

/// An attempt id in the lowercase hex the drill request takes.
fn attempt_hex(attempt: AttemptId) -> String {
    attempt
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn drill_request(attempt: AttemptId) -> Value {
    json!({ "class": "task_failure", "attempt": attempt_hex(attempt) })
}

/// The owner's drill of `attempt`, through the owner's door: the attempt, its
/// state on the wire and its receipt ids.
fn owner_drill(fixture: &Fixture, attempt: AttemptId) -> (String, Value, Vec<String>) {
    let drill = fixture
        .vault
        .drill_custom_agent_failure(
            &owner_proof(fixture),
            FailureSignalClass::TaskFailure,
            attempt,
        )
        .expect("the owner drills");
    (
        attempt_hex(drill.trace.id),
        serde_json::to_value(drill.trace.state).expect("state wire"),
        drill.receipt_refs,
    )
}

fn assert_drill_answers(fixture: &Fixture, agent: EntityId, attempt: AttemptId) {
    let drill = invoke(
        &agent_memory(fixture, agent),
        DRILL_AS,
        drill_request(attempt),
    )
    .unwrap_or_else(|error| panic!("the delegated agent drills: {error:?}"));
    let (owner_attempt, owner_state, owner_receipts) = owner_drill(fixture, attempt);
    assert_eq!(drill["attempt"], json!(owner_attempt), "{drill}");
    assert_eq!(
        owner_state,
        serde_json::to_value(AttemptState::Failed).expect("state wire"),
        "the ladder failed the try"
    );
    assert_eq!(drill["state"], owner_state, "{drill}");
    assert_eq!(drill["receipt_refs"], json!(owner_receipts), "{drill}");
    assert_eq!(
        drill["events"][0]["note"],
        json!("stalled on the deploy step"),
        "the drill carries the try's interventions: {drill}"
    );
    assert_eq!(drill["events"][0]["kind"], json!("interrupt"), "{drill}");
}

#[test]
fn an_agent_the_owner_delegates_the_drill_to_drills_a_custom_agent_failure() {
    let fixture = rooted_vault();
    let attempt = failed_custom_run(&fixture, true);
    let reviewer = granted_agent(&fixture, "delegated-drill-reviewer", &[DRILL_AS]);
    owner_turns_on(&fixture, DRILL_KEY, Some(reviewer));

    assert_drill_answers(&fixture, reviewer, attempt);
}

#[test]
fn a_vault_row_delegates_the_drill_to_every_agent() {
    let fixture = rooted_vault();
    let attempt = failed_custom_run(&fixture, true);
    let reviewer = granted_agent(&fixture, "delegated-drill-reviewer", &[DRILL_AS]);
    owner_turns_on(&fixture, DRILL_KEY, None);

    assert_drill_answers(&fixture, reviewer, attempt);
}

#[test]
fn with_the_key_off_an_agent_is_refused_the_drill_and_the_owner_drills_as_before() {
    let fixture = rooted_vault();
    let attempt = failed_custom_run(&fixture, true);
    let reviewer = granted_agent(&fixture, "delegated-drill-reviewer", &[DRILL_AS]);

    let refused: MemoryError = invoke(
        &agent_memory(&fixture, reviewer),
        DRILL_AS,
        drill_request(attempt),
    )
    .expect_err("an agent the owner did not delegate to drills nothing");
    assert!(
        !refused.to_string().is_empty(),
        "the refusal says why: {refused:?}"
    );
    let (owner_attempt, _, _) = owner_drill(&fixture, attempt);
    assert_eq!(owner_attempt, attempt_hex(attempt), "the owner drills");
}

#[test]
fn a_failure_whose_read_set_is_unknown_stays_the_owners() {
    let fixture = rooted_vault();
    let attempt = failed_custom_run(&fixture, false);
    let reviewer = granted_agent(&fixture, "delegated-drill-reviewer", &[DRILL_AS]);
    owner_turns_on(&fixture, DRILL_KEY, Some(reviewer));

    invoke(
        &agent_memory(&fixture, reviewer),
        DRILL_AS,
        drill_request(attempt),
    )
    .expect_err("a trace no complete read set proves is not the agent's to read");
    let (owner_attempt, _, _) = owner_drill(&fixture, attempt);
    assert_eq!(owner_attempt, attempt_hex(attempt), "the owner drills");
}

/// A sealed try of `worker`'s: a TASK the owner addressed to it, accepted on
/// a leased and stamped run, reported DONE with a durable result, confessed
/// with one uncertain objective (so a directed recheck waits). With
/// `complete`, the try's read set was recorded complete (the result row)
/// while it ran. Answers the try and the rows its seal was derived from.
fn sealed_try(fixture: &Fixture, worker: EntityId, complete: bool) -> (AttemptId, Vec<EntityId>) {
    let leased = leased_run(fixture, worker);
    let run = AttemptQueue::new(&fixture.vault)
        .set_executor_model(leased.id, RUN_LEASE_OWNER, leased.attempt_count, RUN_MODEL)
        .expect("the host stamps its run's model");
    let created = invoke(
        &owner_memory(fixture),
        "tasks.create",
        json!({
            "spec": { "summary": "summarize the week's notes" },
            "assignee": { "child": { "actor_ref": worker.to_hex() } },
        }),
    )
    .expect("the owner creates the task");
    let task: EntityId = serde_json::from_value(created["task_ref"].clone())
        .unwrap_or_else(|error| panic!("no created task ({error}): {created}"));
    let hosted = fixture
        .vault
        .memory(worker, EdgeActorClass::Agent)
        .with_task_host(HostBinding::from_leased(&run, None).expect("host binding"));
    let accepted = invoke(
        &hosted,
        "tasks.accept",
        json!({ "task_ref": task.to_hex(), "intent_key": "take-the-task" }),
    )
    .expect("the assignee accepts");
    let handle: AttemptHandle =
        match serde_json::from_value::<TaskHandle>(accepted["handle"].clone()) {
            Ok(TaskHandle::Attempt(handle)) => handle,
            other => panic!("the accept named no try ({other:?}): {accepted}"),
        };
    let result = EntityId::now();
    let at = fixture.vault.now_recorded_at();
    let body = rmp_serde::to_vec_named(&std::collections::BTreeMap::from([("role", "user")]))
        .expect("a TURN body");
    fixture
        .vault
        .put_entity(
            &result,
            ENTITY_TYPE_TURN,
            TimeRange { start: at, end: at },
            at,
            &body,
        )
        .expect("the result row");
    if complete {
        record_complete_read_set(fixture, handle.attempt_ref, vec![result]);
    }
    invoke(
        &hosted,
        "tasks.update",
        json!({
            "task_ref": task.to_hex(),
            "report_key": "done-once",
            "attempt": serde_json::to_value(&handle).expect("handle wire"),
            "report": { "done": { "result_ref": result.to_hex() } },
        }),
    )
    .expect("the DONE lands");
    confess_as_owner(
        &fixture.vault,
        &owner_proof(fixture),
        &AttemptConfession {
            attempt: handle.attempt_ref,
            subject: worker,
            type_ref: TypeRef::root(1),
            objectives: vec![ObjectiveConfession {
                objective: "summarize the week's notes".to_owned(),
                met: Some(true),
                flaw: None,
                uncertainty: Some("the week's sources may be partial".to_owned()),
            }],
        },
    )
    .expect("the owner seals the try");
    (handle.attempt_ref, vec![worker, task, result])
}

fn owner_receipt(fixture: &Fixture, attempt: AttemptId) -> Value {
    let receipt = receipt_as_owner(
        &fixture.vault,
        &owner_proof(fixture),
        &SealAttemptRequest { attempt },
    )
    .expect("the owner reads the receipt")
    .expect("the try is sealed");
    serde_json::to_value(&receipt).expect("receipt wire")
}

fn owner_pending(fixture: &Fixture, attempt: AttemptId) -> Value {
    let pending = pending_sourced_as_owner(
        &fixture.vault,
        &owner_proof(fixture),
        &SealPendingRequest {
            attempt: Some(attempt),
        },
    )
    .expect("the owner reads the pending checks");
    assert!(
        !pending.is_empty(),
        "the uncertain objective waits a recheck"
    );
    serde_json::to_value(
        pending
            .into_iter()
            .map(|(request, _)| request)
            .collect::<Vec<_>>(),
    )
    .expect("pending wire")
}

const SEAL_VERBS: &[&str] = &[RECEIPT_AS, PENDING_AS, AUDIT_AS, REVISIONS_READ];

#[test]
fn an_agent_the_owner_delegates_seal_reads_to_reads_the_receipt_pending_checks_and_audit() {
    let fixture = rooted_vault();
    let worker = granted_agent(&fixture, "delegated-seal-reader", SEAL_VERBS);
    let (attempt, rows) = sealed_try(&fixture, worker, true);
    owner_turns_on(&fixture, SEAL_KEY, Some(worker));
    let me = agent_memory(&fixture, worker);
    let request = json!({ "attempt": attempt });

    let receipt = invoke(&me, RECEIPT_AS, request.clone())
        .unwrap_or_else(|error| panic!("the delegated agent reads the receipt: {error:?}"));
    assert_eq!(
        receipt,
        owner_receipt(&fixture, attempt),
        "the agent reads the owner's receipt whole; {}",
        lane_view(&fixture, worker, &rows)
    );

    let pending = invoke(&me, PENDING_AS, request.clone())
        .unwrap_or_else(|error| panic!("the delegated agent reads pending checks: {error:?}"));
    assert_eq!(pending, owner_pending(&fixture, attempt), "{pending}");

    let audited = invoke(&me, AUDIT_AS, request)
        .unwrap_or_else(|error| panic!("the delegated agent audits: {error:?}"));
    assert_eq!(
        audited,
        owner_receipt(&fixture, attempt),
        "the audit answers the seal as stored after it"
    );
}

#[test]
fn with_the_key_off_an_agent_is_refused_seal_reads_and_the_owner_reads_as_before() {
    let fixture = rooted_vault();
    let worker = granted_agent(&fixture, "delegated-seal-reader", SEAL_VERBS);
    let (attempt, _) = sealed_try(&fixture, worker, true);
    let before = owner_receipt(&fixture, attempt);
    let me = agent_memory(&fixture, worker);
    let request = json!({ "attempt": attempt });

    for verb in [RECEIPT_AS, PENDING_AS, AUDIT_AS] {
        invoke(&me, verb, request.clone())
            .expect_err("an agent the owner did not delegate to reads no seal");
    }
    assert_eq!(
        owner_receipt(&fixture, attempt),
        before,
        "the refused agent changed nothing"
    );
    owner_pending(&fixture, attempt);
}

#[test]
fn a_seal_whose_read_set_is_unknown_stays_the_owners() {
    let fixture = rooted_vault();
    let worker = granted_agent(&fixture, "delegated-seal-reader", SEAL_VERBS);
    let (attempt, _) = sealed_try(&fixture, worker, false);
    owner_turns_on(&fixture, SEAL_KEY, Some(worker));
    let before = owner_receipt(&fixture, attempt);
    let me = agent_memory(&fixture, worker);
    let request = json!({ "attempt": attempt });

    let receipt = invoke(&me, RECEIPT_AS, request.clone());
    assert!(
        matches!(&receipt, Ok(Value::Null) | Err(_)),
        "an unproven seal reads as none: {receipt:?}"
    );
    let pending = invoke(&me, PENDING_AS, request.clone());
    assert!(
        matches!(&pending, Ok(Value::Array(checks)) if checks.is_empty()) || pending.is_err(),
        "an unproven seal's checks are left out: {pending:?}"
    );
    invoke(&me, AUDIT_AS, request).expect_err("an unproven seal is not drawn for the agent");
    assert_eq!(
        owner_receipt(&fixture, attempt),
        before,
        "the agent's refused audit drew nothing"
    );
    owner_pending(&fixture, attempt);
}
