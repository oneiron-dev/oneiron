//! `vault.evals.authoring.execute`'s engine half (LEARN-EXEC-PROOF = A, LEARN-EXEC-SHAPE =
//! A): the caller's admission in the writer that queues the Coach's eval-authoring job and
//! admits that very job, the plan applied on it as the Coach, the kept record that names the
//! caller, and `vault.evals.authoring.result` reading that record. The host's model step is
//! replaced by a hand-written plan for the vault's own inventory; no model is called. The
//! owner and an agent whose live owner Grant lists the verb are admitted; an agent with no
//! Grant, or a revoked one, is refused FORBIDDEN and queues nothing. A second request while
//! the pass is leased waits on it, and an attempt the door did not admit (a queued nightly
//! pass) takes no record. An attempt leased again after its lease lapsed keeps its first
//! request's caller, and once its pass ended runs no second pass; an apply after an end
//! answers the first end. A host whose lease lapsed, and whose attempt a later request
//! leased again, neither claims nor ends the record.
//! Run with `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test verb_vault_evals_authoring_execute`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::attempt_queue::{AttemptQueue, CleanupAttemptLeases};
use oneiron::authority::{ActSurface, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::dreamer_runner::{
    AdmitDreamerAttempt, DreamerAdmissionOutcome, DreamerAdmittedAttempt, DreamerRunnerStore,
};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError};
use oneiron::skill_optimize::eval_doors::{
    EvalAuthorNowRequest, EvalAuthoringRef, author_now, authoring_result,
};
use oneiron::skill_optimize::{
    EvalAuthoringAdmission, EvalAuthoringCaller, EvalAuthoringExecuteRequest,
    EvalAuthoringExecution, EvalAuthoringOutcome, EvalAuthoringPlan, EvalAuthoringReport,
    admit_eval_authoring_execution, eval_authoring_execute_admits, eval_authoring_inventory,
    eval_authoring_skill_id,
};
use oneiron::store::GateDecisionId;
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentGrantMintRequest, AgentGrantRevokeRequest,
    create_agent_definition_as, mint_agent_grant_as, revoke_agent_grant_as,
};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_store::ports::manual_clock::ManualClock;
use serde_json::json;

const VERB: &str = "vault.evals.authoring.execute";

/// The vault clock's fixed time for every test here: no wall time, no sleeps.
const T0: u64 = 1_780_000_000;

/// A time past the first lease's timeout: the lease lapsed, and the queue takes it back.
const LATER: u64 = T0 + 100;

/// The lease timeout the queue's cleanup applies at [`LATER`].
const LEASE_TIMEOUT_SECS: u64 = 10;

/// The Coach host queue's lease owner and budget line, as its worker admits.
const COACH_HOST: &str = "coach.host";

/// The skill revision the hand-written pass names as the one it ran.
const FIXTURE_REVISION: &str = "fixture-revision";

struct Fixture {
    vault: Vault,
    _dir: tempfile::TempDir,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
}

/// A rooted vault with its install enrolled, its embedded owner and proof. The owner's
/// Grant acts on `ThisInstall` need the full five-step install first.
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
    let owner_proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("owner proof");
    Fixture {
        vault,
        _dir: dir,
        owner,
        owner_proof,
    }
}

/// An enabled, active agent definition the owner creates: the requesting caller.
fn requesting_agent(fixture: &Fixture) -> EntityId {
    let id = fixture.vault.new_entity_id().expect("agent id");
    create_agent_definition_as(
        &fixture.vault,
        &fixture.owner_proof,
        AgentDefinitionCreateRequest {
            agent_def_ref: id,
            definition: serde_json::from_value(json!({
                "agent_id": "eval-authoring-requester",
                "desc": "eval authoring execute fixture",
                "version": "1.0.0",
                "ceiling": "auto",
                "enabled": true,
            }))
            .expect("agent spec"),
        },
    )
    .expect("owner creates the requesting agent");
    id
}

/// The owner's live Grant naming `read` and this verb for `agent`; the grant's row.
fn grant_execute(fixture: &Fixture, agent: EntityId) -> EntityId {
    let mut scope = Scope::top();
    scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned(), VERB.to_owned()]));
    let minted = mint_agent_grant_as(
        &fixture.vault,
        &fixture.owner_proof,
        ActSurface::ThisInstall,
        AgentGrantMintRequest {
            agent,
            authority_scope: scope,
            expires_at: None,
            repo_bounds: None,
            verb_classes: BTreeSet::new(),
            wallet_ref: None,
            working_view_bounds: None,
            check_in_ref: None,
        },
    )
    .expect("owner mints the execute Grant");
    assert!(minted.grant.confers, "the execute Grant confers");
    minted.grant.grant_ref
}

fn revoke_grant(fixture: &Fixture, grant_ref: EntityId) {
    let owner_proof = fixture
        .vault
        .authenticate_owner(
            fixture.owner,
            &fixture.owner.to_hex(),
            true,
            GateDecisionId::now(),
        )
        .expect("owner proof");
    let revoked = revoke_agent_grant_as(
        &fixture.vault,
        &owner_proof,
        ActSurface::ThisInstall,
        AgentGrantRevokeRequest {
            grant_ref,
            seen: None,
        },
    )
    .expect("owner revokes the grant");
    assert!(revoked.changed, "the revoke lands");
}

fn owner_memory(fixture: &Fixture) -> Memory<'_> {
    fixture.vault.memory(fixture.owner, EdgeActorClass::Human)
}

/// The Coach host worker's admission input: its lease owner and budget line.
fn coach_host_admission() -> AdmitDreamerAttempt {
    coach_host_admission_at(T0)
}

fn coach_host_admission_at(now: u64) -> AdmitDreamerAttempt {
    AdmitDreamerAttempt {
        lease_owner: COACH_HOST.to_owned(),
        now,
        budget_id: COACH_HOST.to_owned(),
        budget_total_units: 1 << 20,
        reserve_units: 1,
        started_milestone: None,
    }
}

fn request(memory: &Memory<'_>) -> Result<EvalAuthoringAdmission, MemoryError> {
    request_at(memory, T0)
}

fn request_at(memory: &Memory<'_>, now: u64) -> Result<EvalAuthoringAdmission, MemoryError> {
    admit_eval_authoring_execution(
        memory,
        EvalAuthoringExecuteRequest {},
        coach_host_admission_at(now),
    )
}

/// The request's own leased Coach attempt and the record its admission wrote.
fn admitted(memory: &Memory<'_>) -> (Box<DreamerAdmittedAttempt>, EvalAuthoringExecution) {
    match request(memory).expect("an admitted caller's request") {
        EvalAuthoringAdmission::Admitted { attempt, execution } => (attempt, *execution),
        EvalAuthoringAdmission::Ended { execution, .. } => {
            panic!("the request found an ended pass instead of running its own: {execution:?}")
        }
        EvalAuthoringAdmission::Waiting { attempt } => {
            panic!("the request waited on {attempt:?} instead of running its own pass")
        }
    }
}

/// The queue's cleanup at [`LATER`]: the lapsed lease of the one leased pass goes back to
/// the queue, as a host that stopped before it settled leaves it.
fn lapse_the_lease(fixture: &Fixture) {
    let report = AttemptQueue::new(&fixture.vault)
        .cleanup_leases(CleanupAttemptLeases {
            now: LATER,
            lease_timeout_secs: LEASE_TIMEOUT_SECS,
        })
        .expect("the queue takes lapsed leases back");
    assert_eq!(report.stale_requeued, 1, "the pass's lease lapsed");
}

fn attempt_id(attempt: &DreamerAdmittedAttempt) -> EntityId {
    EntityId::from_bytes(*attempt.status.attempt.id.as_bytes()).expect("attempt id")
}

/// A plan for the vault's current inventory that decides nothing: what a hand-written
/// model answer gives the engine when no model is called.
fn empty_plan(
    fixture: &Fixture,
) -> (
    EvalAuthoringPlan,
    oneiron::skill_optimize::EvalAuthoringInventory,
) {
    let inventory = eval_authoring_inventory(&fixture.vault, T0).expect("inventory");
    let plan = EvalAuthoringPlan {
        inventory_digest: inventory.inventory_digest.clone(),
        families: Vec::new(),
        cases: Vec::new(),
        cuts: Vec::new(),
        cohorts: Vec::new(),
    };
    (plan, inventory)
}

fn skill() -> (EntityId, String) {
    (
        eval_authoring_skill_id().expect("eval-authoring skill id"),
        FIXTURE_REVISION.to_owned(),
    )
}

fn result(
    fixture: &Fixture,
    attempt: EntityId,
) -> oneiron::skill_optimize::eval_doors::EvalAuthoringResult {
    authoring_result(
        &fixture.vault,
        &fixture.owner_proof,
        EvalAuthoringRef { attempt },
    )
    .expect("the owner reads the pass")
    .expect("the queue holds the pass")
}

fn assert_refused(error: &MemoryError, code: &str, phrase: &str) {
    assert_eq!(
        error.code, code,
        "the verb's own refusal; got {}: {}",
        error.code, error.message,
    );
    assert!(
        error.message.contains(phrase),
        "the refusal names why ({phrase}): {}",
        error.message
    );
}

#[test]
fn owner_runs_the_requested_pass_and_keeps_its_report() {
    let fixture = rooted_vault();
    let owner = owner_memory(&fixture);
    eval_authoring_execute_admits(&owner).expect("the owner passes the host's early check");

    let (attempt, requested) = admitted(&owner);
    assert_eq!(requested.attempt, attempt_id(&attempt));
    assert_eq!(
        requested.caller,
        EvalAuthoringCaller::Owner {
            person: fixture.owner
        }
    );
    assert_eq!(requested.outcome, EvalAuthoringOutcome::Running);
    assert_eq!(requested.requested_at, T0);
    assert_eq!(
        attempt.status.attempt.lease_owner.as_deref(),
        Some(COACH_HOST)
    );

    let (plan, inventory) = empty_plan(&fixture);
    let applied = fixture
        .vault
        .apply_requested_eval_authoring(&attempt, plan, &inventory, skill(), T0)
        .expect("the Coach applies the plan on the request's own attempt");
    assert_eq!(applied.outcome, EvalAuthoringOutcome::Applied);
    assert_eq!(applied.report, Some(EvalAuthoringReport::default()));
    assert_eq!(
        applied.inventory_digest.as_deref(),
        Some(inventory.inventory_digest.as_str())
    );
    let ran = applied
        .skill
        .clone()
        .expect("the record names the skill it ran");
    assert_eq!(ran.revision, FIXTURE_REVISION);
    assert_eq!(applied.ended_at, Some(T0));
    assert_eq!(
        applied.caller, requested.caller,
        "the record keeps its caller"
    );

    let read = result(&fixture, applied.attempt);
    assert_eq!(
        read.execution.as_ref(),
        Some(&applied),
        "the result reads the kept record"
    );

    let again = fixture
        .vault
        .end_requested_eval_authoring(&attempt, EvalAuthoringOutcome::NoPlan, None, None, T0)
        .expect("a second end answers the first");
    assert_eq!(again, applied, "the first end stands");
    assert!(
        fixture
            .vault
            .end_requested_eval_authoring(&attempt, EvalAuthoringOutcome::Applied, None, None, T0)
            .is_err(),
        "only the apply door records an applied pass"
    );
}

#[test]
fn granted_agent_runs_a_pass_its_record_names() {
    let fixture = rooted_vault();
    let agent_id = requesting_agent(&fixture);
    let grant = grant_execute(&fixture, agent_id);
    let agent = fixture.vault.memory(agent_id, EdgeActorClass::Agent);
    eval_authoring_execute_admits(&agent).expect("the granted agent passes the early check");

    let (attempt, requested) = admitted(&agent);
    assert_eq!(
        requested.caller,
        EvalAuthoringCaller::Agent {
            agent: agent_id,
            grant
        },
        "the record names the agent and the Grant that admitted it"
    );
    let ended = fixture
        .vault
        .end_requested_eval_authoring(&attempt, EvalAuthoringOutcome::NoWork, None, None, T0)
        .expect("a pass with nothing to decide ends");
    assert_eq!(ended.outcome, EvalAuthoringOutcome::NoWork);
    assert_eq!(ended.report, None);
    assert_eq!(result(&fixture, ended.attempt).execution, Some(ended));
}

#[test]
fn agent_without_a_live_grant_is_refused_and_queues_nothing() {
    let fixture = rooted_vault();
    let agent_id = requesting_agent(&fixture);
    let agent = fixture.vault.memory(agent_id, EdgeActorClass::Agent);

    let early = eval_authoring_execute_admits(&agent).expect_err("no Grant lists the verb");
    assert_refused(&early, MEMORY_CODE_FORBIDDEN, VERB);
    let error = request(&agent).expect_err("no Grant lists the verb");
    assert_refused(&error, MEMORY_CODE_FORBIDDEN, VERB);
    let queued = DreamerRunnerStore::new(&fixture.vault)
        .admit_next_coach_host_job(coach_host_admission())
        .expect("the Coach queue admits");
    assert!(
        matches!(queued, DreamerAdmissionOutcome::Empty),
        "a refused request queued no Coach job: {queued:?}"
    );

    let grant = grant_execute(&fixture, agent_id);
    admitted(&agent);
    revoke_grant(&fixture, grant);
    let error = request(&agent).expect_err("a revoked Grant admits no request");
    assert_refused(&error, MEMORY_CODE_FORBIDDEN, VERB);
}

#[test]
fn second_request_waits_on_the_leased_pass() {
    let fixture = rooted_vault();
    let owner = owner_memory(&fixture);
    let (attempt, _) = admitted(&owner);
    match request(&owner).expect("the owner's second request") {
        EvalAuthoringAdmission::Waiting { attempt: waits_on } => {
            assert_eq!(
                waits_on,
                attempt_id(&attempt),
                "it waits on the pass that runs"
            );
        }
        EvalAuthoringAdmission::Admitted { .. } | EvalAuthoringAdmission::Ended { .. } => {
            panic!("a second pass was admitted while the first holds the lease")
        }
    }
}

#[test]
fn reclaimed_pass_that_ended_keeps_its_first_end_and_runs_no_second_pass() {
    let fixture = rooted_vault();
    let agent_id = requesting_agent(&fixture);
    grant_execute(&fixture, agent_id);
    let agent = fixture.vault.memory(agent_id, EdgeActorClass::Agent);
    let (attempt, _) = admitted(&agent);
    let ended = fixture
        .vault
        .end_requested_eval_authoring(&attempt, EvalAuthoringOutcome::NoWork, None, None, T0)
        .expect("the agent's pass ends");
    // Its host stops before it settles the lease; the lease lapses.
    lapse_the_lease(&fixture);

    match request_at(&owner_memory(&fixture), LATER).expect("the owner's later request") {
        EvalAuthoringAdmission::Ended {
            attempt: again,
            execution,
        } => {
            assert_eq!(attempt_id(&again), attempt_id(&attempt), "the same attempt");
            assert_eq!(
                *execution, ended,
                "the first request's caller and end stand"
            );
        }
        EvalAuthoringAdmission::Admitted { execution, .. } => {
            panic!("an ended pass was admitted to run again: {execution:?}")
        }
        EvalAuthoringAdmission::Waiting { attempt } => {
            panic!("the request waited on {attempt:?} instead of taking the lapsed lease")
        }
    }
    assert_eq!(result(&fixture, ended.attempt).execution, Some(ended));
}

#[test]
fn reclaimed_running_pass_keeps_its_first_caller() {
    let fixture = rooted_vault();
    let (attempt, first) = admitted(&owner_memory(&fixture));
    // The owner's host stops before the pass ends; the lease lapses.
    lapse_the_lease(&fixture);

    let agent_id = requesting_agent(&fixture);
    grant_execute(&fixture, agent_id);
    let agent = fixture.vault.memory(agent_id, EdgeActorClass::Agent);
    let (again, kept) = match request_at(&agent, LATER).expect("the agent's later request") {
        EvalAuthoringAdmission::Admitted { attempt, execution } => (attempt, *execution),
        other => panic!("the lapsed pass is admitted to run on its record: {other:?}"),
    };
    assert_eq!(attempt_id(&again), attempt_id(&attempt), "the same attempt");
    assert_eq!(kept, first, "the record stays the owner's request");

    let (plan, inventory) = empty_plan(&fixture);
    let applied = fixture
        .vault
        .apply_requested_eval_authoring(&again, plan, &inventory, skill(), LATER)
        .expect("the pass runs on the lease the agent's request took");
    assert_eq!(applied.outcome, EvalAuthoringOutcome::Applied);
    assert_eq!(
        applied.caller,
        EvalAuthoringCaller::Owner {
            person: fixture.owner
        }
    );
    assert_eq!(applied.requested_at, T0);
    assert_eq!(applied.ended_at, Some(LATER));
}

#[test]
fn apply_after_an_end_keeps_the_first_end() {
    let fixture = rooted_vault();
    let owner = owner_memory(&fixture);
    let (attempt, _) = admitted(&owner);
    let ended = fixture
        .vault
        .end_requested_eval_authoring(
            &attempt,
            EvalAuthoringOutcome::NoPlan,
            Some(skill()),
            None,
            T0,
        )
        .expect("the pass ends with no plan");
    assert_eq!(ended.outcome, EvalAuthoringOutcome::NoPlan);

    let (plan, inventory) = empty_plan(&fixture);
    let again = fixture
        .vault
        .apply_requested_eval_authoring(&attempt, plan, &inventory, skill(), T0)
        .expect("an apply after the end answers it");
    assert_eq!(again, ended, "the first end stands; no report is added");

    let (mut other, inventory) = empty_plan(&fixture);
    other.inventory_digest = "another inventory".to_owned();
    let answered = fixture
        .vault
        .apply_requested_eval_authoring(&attempt, other, &inventory, skill(), T0)
        .expect("an ended pass answers before it reads a plan");
    assert_eq!(
        answered, ended,
        "the plan for another inventory is never read"
    );
    assert_eq!(result(&fixture, ended.attempt).execution, Some(ended));
}

#[test]
fn host_whose_lease_lapsed_neither_claims_nor_ends_the_record() {
    let fixture = rooted_vault();
    let owner = owner_memory(&fixture);
    let (stalled, first) = admitted(&owner);
    // The owner's host stalls in its model step; its lease lapses, and a later request
    // leases the attempt again.
    lapse_the_lease(&fixture);
    let (current, kept) = match request_at(&owner, LATER).expect("the owner's later request") {
        EvalAuthoringAdmission::Admitted { attempt, execution } => (attempt, *execution),
        other => panic!("the lapsed pass is admitted to run on its record: {other:?}"),
    };
    assert_eq!(
        attempt_id(&current),
        attempt_id(&stalled),
        "the same attempt"
    );
    assert_eq!(kept, first, "the record stays the first request's");

    let (plan, inventory) = empty_plan(&fixture);
    assert!(
        fixture
            .vault
            .apply_requested_eval_authoring(&stalled, plan, &inventory, skill(), LATER)
            .is_err(),
        "the stalled host's plan takes no claim on a lease it lost"
    );
    assert!(
        fixture
            .vault
            .end_requested_eval_authoring(&stalled, EvalAuthoringOutcome::Failed, None, None, LATER)
            .is_err(),
        "the stalled host ends nothing on a lease it lost"
    );
    assert_eq!(
        result(&fixture, first.attempt).execution.as_ref(),
        Some(&first),
        "the record still runs, for the host that holds the lease"
    );

    let (plan, inventory) = empty_plan(&fixture);
    let applied = fixture
        .vault
        .apply_requested_eval_authoring(&current, plan, &inventory, skill(), LATER)
        .expect("the host that holds the lease applies the plan");
    assert_eq!(applied.outcome, EvalAuthoringOutcome::Applied);
    assert_eq!(applied.ended_at, Some(LATER));
}

#[test]
fn nightly_attempt_takes_no_record() {
    let fixture = rooted_vault();
    let queued = author_now(
        &fixture.vault,
        &fixture.owner_proof,
        EvalAuthorNowRequest {},
    )
    .expect("the owner queues the nightly pass");
    let DreamerAdmissionOutcome::Admitted(nightly) = DreamerRunnerStore::new(&fixture.vault)
        .admit_next_coach_host_job(coach_host_admission())
        .expect("the Coach queue admits")
    else {
        panic!("the queued pass is admitted");
    };
    assert_eq!(attempt_id(&nightly), queued.attempt);

    let (plan, inventory) = empty_plan(&fixture);
    assert!(
        fixture
            .vault
            .apply_requested_eval_authoring(&nightly, plan, &inventory, skill(), T0)
            .is_err(),
        "a pass no request admitted takes no applied record"
    );
    assert!(
        fixture
            .vault
            .end_requested_eval_authoring(&nightly, EvalAuthoringOutcome::NoWork, None, None, T0)
            .is_err(),
        "a pass no request admitted takes no ended record"
    );
    assert_eq!(result(&fixture, queued.attempt).execution, None);
}
