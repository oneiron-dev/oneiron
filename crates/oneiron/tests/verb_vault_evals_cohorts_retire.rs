//! `vault.evals.cohorts.retire` (LEARNING-04, ND-130; LEARN-RETIRE-SOURCE = B) through the
//! verb dispatch (`oneiron::task_verb::sdk::invoke`), as a client calls it: JSON in, JSON
//! out. The vault owner and an agent whose live owner Grant lists the verb retire a served
//! sealed cohort that is not its seat's reference, and the receipt names that caller and the
//! exposure the retiring writer read. An agent with no live Grant is refused FORBIDDEN, on a
//! cohort that already retired too: admission comes before the replay. The reference cohort
//! and a cohort that served nothing are refused; a repeat keeps the first date and receipt.
//! The eval-authoring skill's own retirement still names its attempt, and a retirement
//! stored before receipts named their author reads as the skill's.
//! Run with `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test verb_vault_evals_cohorts_retire`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{ActSurface, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::dreamer_runner::{AdmitDreamerAttempt, DreamerAdmissionOutcome, DreamerRunnerStore};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError};
use oneiron::skill_optimize::eval_doors::{EvalAuthorNowRequest, author_now};
use oneiron::skill_optimize::{
    CohortRetirement, CutDecision, DerivationKind, EvalAuthoringPlan, EvalCaseDraft, EvalCohort,
    EvalCohortDecision, EvalCohortRetirementAuthor, EvalCohortSetup, EvalExposureCounts,
    EvalExposureKind, EvalSeat, FamilyPurpose, eval_authoring_inventory, eval_authoring_skill_id,
    setup_eval_cohorts,
};
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::invoke;
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentGrantMintRequest, AgentGrantRevokeRequest,
    create_agent_definition_as, mint_agent_grant_as, revoke_agent_grant_as,
};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_store::ports::manual_clock::ManualClock;
use serde::Serialize;
use serde_json::json;

const VERB: &str = "vault.evals.cohorts.retire";

/// The vault clock's fixed time: no wall time, no sleeps.
const T0: u64 = 1_780_000_000;

/// A later time, for a repeat.
const LATER: u64 = T0 + 100;

const DAY: u64 = 86_400;

/// The rubric revision every cut here is scored under.
const RUBRIC: &str = "fixture-rubric";

/// The consumer a fixture serving names.
const CONSUMER: &str = "fixture-consumer:retirement";

/// The skill revision the hand-written pass names as the one it ran.
const REVISION: &str = "fixture-revision";

/// The Coach host queue's lease owner and budget line, as its worker admits.
const COACH_HOST: &str = "coach.host";

struct Fixture {
    vault: Vault,
    _dir: tempfile::TempDir,
    clock: Arc<ManualClock>,
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
        clock,
        owner,
        owner_proof,
    }
}

fn seat() -> EvalSeat {
    EvalSeat::Companion
}

/// An enabled, active agent definition the owner creates: the retiring caller.
fn requesting_agent(fixture: &Fixture) -> EntityId {
    let id = fixture.vault.new_entity_id().expect("agent id");
    create_agent_definition_as(
        &fixture.vault,
        &fixture.owner_proof,
        AgentDefinitionCreateRequest {
            agent_def_ref: id,
            definition: serde_json::from_value(json!({
                "agent_id": "eval-cohort-retirer",
                "desc": "eval cohort retire fixture",
                "version": "1.0.0",
                "ceiling": "auto",
                "enabled": true,
            }))
            .expect("agent spec"),
        },
    )
    .expect("owner creates the retiring agent");
    id
}

/// The owner's live Grant naming `read` and this verb for `agent`; the grant's row.
fn grant_retire(fixture: &Fixture, agent: EntityId) -> EntityId {
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
        },
    )
    .expect("owner mints the retire Grant");
    assert!(minted.grant.confers, "the retire Grant confers");
    minted.grant.grant_ref
}

fn revoke_grant(fixture: &Fixture, grant_ref: EntityId) {
    let revoked = revoke_agent_grant_as(
        &fixture.vault,
        &fixture.owner_proof,
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

fn agent_memory(fixture: &Fixture, agent: EntityId) -> Memory<'_> {
    fixture.vault.memory(agent, EdgeActorClass::Agent)
}

/// One sealed family of a single receipt case at `source_at`, cut by the owner's setup into
/// a cohort of its own over `[from, until)`.
fn cut(
    fixture: &Fixture,
    root: &str,
    source_at: u64,
    window: (u64, u64),
    reference: bool,
) -> EntityId {
    let vault = &fixture.vault;
    vault
        .assign_eval_family(
            &seat(),
            &BTreeSet::from([root.to_owned()]),
            FamilyPurpose::SealedConfirmation,
            T0,
        )
        .expect("assign the sealed family");
    vault
        .record_eval_case(
            &EvalCaseDraft {
                seat: seat(),
                kind: DerivationKind::Receipt,
                receipts: vec![root.to_owned()],
                parents: Vec::new(),
                stratum: None,
                draw_probability: None,
                source_at,
            },
            T0,
        )
        .expect("record the sealed case");
    let inventory = eval_authoring_inventory(vault, T0).expect("inventory");
    let report = setup_eval_cohorts(
        vault,
        &fixture.owner_proof,
        EvalCohortSetup {
            inventory_at: T0,
            inventory_digest: inventory.inventory_digest,
            families: Vec::new(),
            cases: Vec::new(),
            cuts: vec![CutDecision {
                seat: seat(),
                from: window.0,
                until: window.1,
                rubric_revision: RUBRIC.to_owned(),
                reference,
            }],
        },
        T0,
    )
    .expect("the owner cuts the cohort");
    assert_eq!(report.cohorts_cut.len(), 1, "one cohort cut: {report:?}");
    report.cohorts_cut[0]
}

/// One candidate served from `cohort`, counted by the release door.
fn serve(fixture: &Fixture, cohort: EntityId) {
    fixture
        .vault
        .open_eval_cohort(&cohort, EvalExposureKind::Candidate, CONSUMER, None, T0)
        .expect("the cohort serves one candidate");
}

/// A served cohort that is not the seat's reference.
fn served_cohort(fixture: &Fixture, root: &str) -> EntityId {
    let cohort = cut(fixture, root, T0 - DAY, (T0 - 2 * DAY, T0), false);
    serve(fixture, cohort);
    cohort
}

fn retire(memory: &Memory<'_>, cohort: EntityId, reason: &str) -> Result<EvalCohort, MemoryError> {
    let answer = invoke(
        memory,
        VERB,
        json!({ "cohort": cohort.to_hex(), "reason": reason }),
    )?;
    Ok(serde_json::from_value(answer).expect("the verb answers the cohort"))
}

/// `cohort`'s kept row.
fn stored(fixture: &Fixture, cohort: EntityId) -> EvalCohort {
    fixture
        .vault
        .eval_cohorts(&seat())
        .expect("the seat's cohorts")
        .into_iter()
        .find(|row| row.id == cohort)
        .expect("the cohort is kept")
}

const ONE_CANDIDATE: EvalExposureCounts = EvalExposureCounts {
    candidates: 1,
    queries: 0,
    promotions: 0,
};

fn assert_refused(error: &MemoryError) {
    assert_eq!(
        error.code, MEMORY_CODE_FORBIDDEN,
        "the verb's own refusal; got {}: {}",
        error.code, error.message,
    );
    assert!(
        error.message.contains(VERB),
        "the refusal names the verb: {}",
        error.message
    );
}

#[test]
fn owner_retires_a_served_cohort_and_the_receipt_names_the_owner() {
    let fixture = rooted_vault();
    let cohort = served_cohort(&fixture, "fixture-source:owner-retires");

    let retired = retire(&owner_memory(&fixture), cohort, "  the owner's call  ")
        .expect("the owner retires the served cohort");
    assert_eq!(retired.id, cohort);
    assert_eq!(retired.retired_at, Some(T0));
    let receipt = retired
        .retirement
        .clone()
        .expect("the cohort keeps its retirement");
    assert_eq!(
        receipt.author,
        EvalCohortRetirementAuthor::Owner {
            person: fixture.owner
        }
    );
    assert_eq!(
        receipt.reason, "the owner's call",
        "the kept reason is trimmed"
    );
    assert_eq!(
        receipt.exposure, ONE_CANDIDATE,
        "the exposure the retiring writer read"
    );
    assert_eq!(stored(&fixture, cohort), retired, "the kept row reads back");
}

#[test]
fn granted_agent_retires_and_the_receipt_names_its_grant() {
    let fixture = rooted_vault();
    let cohort = served_cohort(&fixture, "fixture-source:agent-retires");
    let agent = requesting_agent(&fixture);
    let grant = grant_retire(&fixture, agent);

    let retired = retire(&agent_memory(&fixture, agent), cohort, "the agent's call")
        .expect("the granted agent retires the served cohort");
    let receipt = retired.retirement.expect("the cohort keeps its retirement");
    assert_eq!(
        receipt.author,
        EvalCohortRetirementAuthor::Agent { agent, grant },
        "the receipt names the agent and the Grant that admitted it"
    );
    assert_eq!(receipt.exposure, ONE_CANDIDATE);
    assert_eq!(retired.retired_at, Some(T0));
}

#[test]
fn agent_without_a_live_grant_is_refused_before_the_replay() {
    let fixture = rooted_vault();
    let cohort = served_cohort(&fixture, "fixture-source:agent-refused");
    let agent = requesting_agent(&fixture);
    let memory = agent_memory(&fixture, agent);

    assert_refused(&retire(&memory, cohort, "no grant").expect_err("no Grant lists the verb"));
    assert_eq!(
        stored(&fixture, cohort).retired_at,
        None,
        "a refused call retires nothing"
    );

    let grant = grant_retire(&fixture, agent);
    revoke_grant(&fixture, grant);
    assert_refused(
        &retire(&memory, cohort, "revoked").expect_err("a revoked Grant admits nothing"),
    );
    assert_eq!(stored(&fixture, cohort).retired_at, None);

    let first = retire(&owner_memory(&fixture), cohort, "the owner's call")
        .expect("the owner retires the cohort");
    assert_refused(
        &retire(&memory, cohort, "a replay").expect_err("admission comes before the replay"),
    );
    assert_eq!(stored(&fixture, cohort), first);
}

#[test]
fn reference_and_unserved_cohorts_are_refused() {
    let fixture = rooted_vault();
    let reference = cut(
        &fixture,
        "fixture-source:reference",
        T0 - 3 * DAY,
        (T0 - 4 * DAY, T0 - 2 * DAY),
        true,
    );
    serve(&fixture, reference);
    let unserved = cut(
        &fixture,
        "fixture-source:unserved",
        T0 - DAY,
        (T0 - 2 * DAY, T0),
        false,
    );
    let owner = owner_memory(&fixture);

    let error = retire(&owner, reference, "the reference").expect_err("the reference stays");
    assert!(
        error
            .message
            .contains("reference eval cohort is never retired"),
        "the reference refusal: {}: {}",
        error.code,
        error.message
    );
    let error = retire(&owner, unserved, "unserved").expect_err("an unserved cohort stays");
    assert!(
        error.message.contains("served nothing"),
        "the unserved refusal: {}: {}",
        error.code,
        error.message
    );
    assert_eq!(stored(&fixture, reference).retirement, None);
    assert_eq!(stored(&fixture, unserved).retirement, None);
    assert!(
        retire(
            &owner,
            served_cohort(&fixture, "fixture-source:bounded"),
            " "
        )
        .is_err(),
        "an empty reason is refused"
    );
}

#[test]
fn repeat_keeps_the_first_date_and_receipt() {
    let fixture = rooted_vault();
    let cohort = served_cohort(&fixture, "fixture-source:repeat");
    let agent = requesting_agent(&fixture);
    grant_retire(&fixture, agent);

    let first = retire(&owner_memory(&fixture), cohort, "the first call")
        .expect("the owner retires the cohort");
    fixture.clock.set(LATER);
    let again = retire(&agent_memory(&fixture, agent), cohort, "a later call")
        .expect("a repeat answers the first retirement");
    assert_eq!(again, first, "the first date and receipt stand");
    assert_eq!(again.retired_at, Some(T0));
    assert_eq!(stored(&fixture, cohort), first);
}

#[test]
fn the_skills_own_retirement_still_names_its_attempt() {
    let fixture = rooted_vault();
    let cohort = served_cohort(&fixture, "fixture-source:skill-retires");
    let queued = author_now(
        &fixture.vault,
        &fixture.owner_proof,
        EvalAuthorNowRequest {},
    )
    .expect("the owner queues the nightly pass");
    let DreamerAdmissionOutcome::Admitted(nightly) = DreamerRunnerStore::new(&fixture.vault)
        .admit_next_coach_host_job(AdmitDreamerAttempt {
            lease_owner: COACH_HOST.to_owned(),
            now: T0,
            budget_id: COACH_HOST.to_owned(),
            budget_total_units: 1 << 20,
            reserve_units: 1,
            started_milestone: None,
        })
        .expect("the Coach queue admits")
    else {
        panic!("the queued pass is admitted");
    };
    let attempt = EntityId::from_bytes(*nightly.status.attempt.id.as_bytes()).expect("attempt id");
    assert_eq!(attempt, queued.attempt);

    let inventory = eval_authoring_inventory(&fixture.vault, T0).expect("inventory");
    let plan = EvalAuthoringPlan {
        inventory_digest: inventory.inventory_digest.clone(),
        families: Vec::new(),
        cases: Vec::new(),
        cuts: Vec::new(),
        cohorts: vec![EvalCohortDecision {
            cohort,
            retire: true,
            reason: "the skill's call".to_owned(),
        }],
    };
    let skill = eval_authoring_skill_id().expect("eval-authoring skill id");
    let report = fixture
        .vault
        .run_coach_eval_authoring(&nightly, plan, &inventory, (skill, REVISION.to_owned()), T0)
        .expect("the Coach applies the plan");
    assert_eq!(report.cohorts_retired, vec![cohort], "{report:?}");
    let receipt = stored(&fixture, cohort)
        .retirement
        .expect("the skill's retirement is kept");
    assert_eq!(
        receipt.author,
        EvalCohortRetirementAuthor::Skill {
            attempt,
            skill,
            revision: REVISION.to_owned(),
        }
    );
    assert_eq!(receipt.exposure, ONE_CANDIDATE);

    let again = retire(&owner_memory(&fixture), cohort, "the owner's call")
        .expect("the owner's later call answers the first retirement");
    assert_eq!(
        again.retirement,
        Some(receipt),
        "the skill's receipt stands"
    );
}

/// A retirement as rows kept it before receipts named their author.
#[derive(Serialize)]
struct FlatRetirement<'a> {
    reason: &'a str,
    skill: EntityId,
    revision: &'a str,
    attempt: EntityId,
    exposure: EvalExposureCounts,
}

#[test]
fn a_retirement_stored_before_authors_reads_as_the_skills() {
    let fixture = rooted_vault();
    let skill = fixture.vault.new_entity_id().expect("skill id");
    let attempt = fixture.vault.new_entity_id().expect("attempt id");
    let stored = rmp_serde::to_vec_named(&FlatRetirement {
        reason: "an earlier call",
        skill,
        revision: REVISION,
        attempt,
        exposure: ONE_CANDIDATE,
    })
    .expect("encode the flat row");

    let read: CohortRetirement = rmp_serde::from_slice(&stored).expect("a flat row decodes");
    assert_eq!(
        read,
        CohortRetirement {
            reason: "an earlier call".to_owned(),
            author: EvalCohortRetirementAuthor::Skill {
                attempt,
                skill,
                revision: REVISION.to_owned(),
            },
            exposure: ONE_CANDIDATE,
        }
    );
    let rewritten = rmp_serde::to_vec_named(&read).expect("encode the read row");
    let again: CohortRetirement = rmp_serde::from_slice(&rewritten).expect("the new shape decodes");
    assert_eq!(again, read);
    let wire = serde_json::to_value(&read).expect("the receipt as JSON");
    assert_eq!(wire["author"]["kind"], "skill");
    assert!(
        wire.get("skill").is_none(),
        "only the new shape is written: {wire}"
    );

    let mixed = json!({
        "reason": "a mixed row",
        "author": { "kind": "owner", "person": fixture.owner.to_hex() },
        "skill": skill.to_hex(),
        "exposure": ONE_CANDIDATE,
    });
    assert!(
        serde_json::from_value::<CohortRetirement>(mixed).is_err(),
        "a row with an author and a flat skill is refused"
    );
    let partial = json!({
        "reason": "a partial row",
        "skill": skill.to_hex(),
        "exposure": ONE_CANDIDATE,
    });
    assert!(
        serde_json::from_value::<CohortRetirement>(partial).is_err(),
        "a flat row without its revision and attempt is refused"
    );
}
