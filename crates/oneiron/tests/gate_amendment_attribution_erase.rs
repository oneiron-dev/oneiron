//! An erase of an owner-amended claim takes the amendment attribution kept
//! under its Gate decision's receipt with the decision's content (FIX
//! [GATE-RECEIPT-ATTRIBUTION-ROWS-OUTLIVE-SKELETON]).
//!
//! A MACHINE writes a Proposed CLAIM, the gate holds it for the owner, and
//! the owner's own same-id revision lands as an `approved_amended` decision
//! with its Δ (FIX [OWNER-REVISION-AMEND-DELTA-UNCAPTURED]). The host then
//! records the amendment's routing facts and the judge settles it: the
//! receipt `gate:<hex>` keys an evidence row, a judgment, a preference note
//! and a cause row. The owner's hard delete leaves the decision as its
//! retention skeleton, which keeps the receipt id and outcome. On main the
//! skeleton lost its Δ but kept all four rows, naming the MACHINE the
//! skeleton no longer names. With the fix none is left, and an erase of
//! another claim leaves this receipt's rows as they were.
//!
//! An erase that commits after the evidence door or the judge has read the
//! receipt's Δ, and before its writer opens, leaves nothing either: the
//! writer finds the Δ gone and lands nothing under the skeleton (REVIEW-10051
//! P1-1). The race is set up through a test door that runs the erase there.
//!
//! What a dropped judgment held up goes on the next gate-decision
//! housekeeping sweep, with no later settle (FIX
//! [AMENDMENT-TARGET-RETRACT-WAITS-FOR-NEXT-SETTLE]): a judged execution
//! lapse charges the MACHINE's own edit-cost cell and earns it a lesson, and
//! after the erase of the claim, or a re-judgment that withdraws the lapse,
//! the owner's housekeeping pass leaves the cell counting no run and the
//! lesson retracted. On main both stood until some later amendment settled.
//! A sweep over a lapse nothing dropped leaves both as they were.
//!
//! The sweep's reliability half lands every amended attempt's verdict in one
//! write, so one attempt it cannot reproject must not hold the others
//! (REVIEW-10104 P1). A `skill_defect` judgment on the MACHINE's typed attempt
//! charges the skill, and is then withdrawn; a second judgment charges an
//! attempt whose pack receipt has no task typeRef and no learning anchor, or
//! no executor stamp. The sweep after both lands the withdrawal and the second
//! charge. On the PR's first head the second attempt failed the pass, so the
//! first attempt still read as a loss after every sweep.
//!
//! The cause rows have no public read that shows a row whose judgment is
//! gone, so they are counted through a test door:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test gate_amendment_attribution_erase`.
// `bind_host_owner` exists only under `test-support`; the door only under the cfg.
#![cfg(all(feature = "test-support", oneiron_test_support))]

use std::sync::Arc;

use ed25519_dalek::{Signer as _, SigningKey};
use oneiron::actor_claims::PREDICATE_ACTOR_LESSON;
use oneiron::agent_dispatch::{AgentDispatchOutcome, AgentDispatcher};
use oneiron::attempt_queue::{
    AttemptQueue, ClaimAttempt, ClaimOutcome, CompleteAttempt, CompleteOutcome, EnqueueAttempt,
    EnqueueOutcome, ManifestEntry, ManifestKind,
};
use oneiron::authority::HostSlipIssuer;
use oneiron::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND;
use oneiron::edit_distance::attribution::{
    AmendmentCause, AmendmentClass, AmendmentEvidence, AmendmentJudgment, amendment_evidence,
    amendment_judgments, edit_cost_for, judge_amendment, pending_preference_proposals,
    project_amendment_lessons, project_amendment_reliability, project_edit_cost_claims,
    record_amendment_evidence,
};
use oneiron::housekeeping::HousekeepingBudget;
use oneiron::receipt::attempt_pack_receipt_id;
use oneiron::registry::{ENTITY_TYPE_MACHINE, ENTITY_TYPE_PERSON};
use oneiron::skill::{SkillLifecycle, SkillRecord, canonical_skill_tree_hash};
use oneiron::skill_reliability::effective_skill_outcome;
use oneiron::test_doors::gate_amendment_attribution as door;
use oneiron::test_support::bind_host_owner;
use oneiron::write_envelope::MachineWriteSignature;
use oneiron::{
    ClaimApprovalStatus, ClaimCandidate, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    DeleteReason, EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor,
    WriteEnvelope, WriteProvenance,
};

const SECRET: &[u8] = b"gate-amendment-attribution-erase-test-owner";
const MACHINE_NOTE: &str = "a machine note";
const REVISED_NOTE: &str = "the owner's revised note";
const SCOPE: &str = "outbound";
/// The skill [`active_skill`] holds, as an attempt's pack manifest names it.
const SKILL_ID: &str = "gate-amendment.lapse";
const SKILL_VERSION: &str = "1.0.0";
/// The executor revision an attempt fixture stamps.
const MODEL: &str = "fixture/model@1";
/// The lease owner of an attempt fixture.
const LEASE: &str = "fixture";
/// The kind of the plain queue row an untyped attempt fixture runs as.
const UNTYPED_KIND: &str = "test.gate_amendment.untyped";

fn at(time: u64) -> TimeRange {
    TimeRange {
        start: time,
        end: time,
    }
}

fn person(vault: &Vault, now: u64) -> EntityId {
    let id = EntityId::now();
    let body = rmp_serde::to_vec_named(&serde_json::json!({ "name": "person" })).expect("body");
    vault
        .put_entity(&id, ENTITY_TYPE_PERSON, at(now), now, &body)
        .expect("FIXTURE: a PERSON");
    id
}

/// A rooted vault with this install's keystore, an enrolled MACHINE and a
/// bound owner.
struct Seeded {
    _dir: tempfile::TempDir,
    vault: Vault,
    machine: EntityId,
    signing: SigningKey,
    owner: EntityId,
    now: u64,
}

fn seed() -> Seeded {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("fresh vault");
    // The owner's hard delete signs its receipt with this install's key, so
    // the keystore goes in as a host installs it after each open. Without it
    // the erase is refused at setup (proof9967, the owner-revision erase test).
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    vault
        .prepare_install_signing()
        .expect("FIXTURE: this install's signing keys");
    let now = vault.now_recorded_at();
    let issuer = HostSlipIssuer::from_secret(SECRET).expect("host issuer");
    vault.ensure_host_root_slip(&issuer).expect("host root");
    let machine = EntityId::now();
    vault
        .put_entity(&machine, ENTITY_TYPE_MACHINE, at(now), now, b"machine")
        .expect("FIXTURE: a MACHINE");
    let signing = SigningKey::from_bytes(&[229; 32]);
    vault
        .enroll_machine_identity(
            &issuer,
            machine,
            signing.verifying_key().to_bytes(),
            [19; 32],
            |transcript| Ok(signing.sign(transcript).to_bytes()),
        )
        .expect("FIXTURE: machine enrollment");
    let owner = vault.ensure_embedded_owner_actor().expect("vault owner");
    bind_host_owner(&vault, &issuer, owner).expect("FIXTURE: owner binding");
    Seeded {
        _dir: dir,
        vault,
        machine,
        signing,
        owner,
        now,
    }
}

/// A CLAIM the MACHINE writes Proposed about a new PERSON, held for the
/// owner, then revised by the owner: an `approved_amended` decision with its
/// Δ. Returns the claim and the decision's receipt id.
fn owner_amended_claim(seeded: &Seeded) -> (EntityId, String) {
    let vault = &seeded.vault;
    let now = seeded.now;
    let subject = person(vault, now);
    let target = EntityId::now();
    let candidate = ClaimCandidate::new(
        "profile.note",
        ClaimSubject::Entity(subject),
        rmpv::Value::from(MACHINE_NOTE),
        1.0,
    );
    let envelope = WriteEnvelope::new(
        WriteActor::new(seeded.machine, EdgeActorClass::System),
        ClaimSource::Observed,
        WriteProvenance::new(rmpv::Value::from("machine output")).expect("provenance"),
        ClaimApprovalStatus::Proposed,
    );
    let transcript = vault
        .machine_claim_transcript(&target, &candidate, &envelope)
        .expect("FIXTURE: machine transcript");
    let signed = envelope.with_machine_signature(MachineWriteSignature {
        public_key: seeded.signing.verifying_key().to_bytes(),
        signature: seeded.signing.sign(&transcript).to_bytes(),
    });
    vault
        .batch()
        .claim_candidate(&target, candidate, &signed, at(now), now)
        .commit()
        .expect("FIXTURE: the machine birth");

    let successor = ClaimCandidate::new(
        "profile.note",
        ClaimSubject::Entity(subject),
        rmpv::Value::from(REVISED_NOTE),
        1.0,
    );
    let revision = WriteEnvelope::new(
        WriteActor::new(seeded.owner, EdgeActorClass::Human),
        ClaimSource::UserStated,
        WriteProvenance::new(rmpv::Value::from("person")).expect("provenance"),
        ClaimApprovalStatus::Auto,
    );
    vault
        .batch()
        .claim_candidate(&target, successor, &revision, at(now), now)
        .commit()
        .expect("FIXTURE: the owner's own revision of the held machine claim lands");
    let amended = vault
        .gate_decisions(1_000)
        .expect("ledger read")
        .into_iter()
        .find(|record| {
            record.claim_id == Some(*target.as_bytes()) && record.outcome == "approved_amended"
        })
        .expect("FIXTURE: the owner's revision records its amended approval");
    (target, format!("gate:{}", amended.decision_id.to_hex()))
}

/// The host's routing facts for the amendment under `receipt`, and the
/// judge's settlement: the decider wanted it otherwise, so the judgment is
/// one `preference_shift` share with its preference note and cause row.
fn judge(seeded: &Seeded, receipt: &str) {
    let evidence = AmendmentEvidence::new(receipt, seeded.machine, SCOPE)
        .at(seeded.now)
        .with_cause(AmendmentCause::DeciderPreference);
    record_amendment_evidence(&seeded.vault, &evidence).expect("FIXTURE: the amendment evidence");
    judge_amendment(&seeded.vault, receipt)
        .expect("FIXTURE: the judging pass")
        .expect("FIXTURE: the judge settles the amendment");
}

/// The amendment rows the vault keeps under `receipt`, by name.
fn rows_kept(vault: &Vault, receipt: &str) -> Vec<&'static str> {
    let mut kept = Vec::new();
    if amendment_evidence(vault, receipt)
        .expect("evidence read")
        .is_some()
    {
        kept.push("evidence");
    }
    if amendment_judgments(vault)
        .expect("judgment read")
        .iter()
        .any(|judgment| judgment.receipt_id == receipt)
    {
        kept.push("judgment");
    }
    if pending_preference_proposals(vault)
        .expect("preference read")
        .iter()
        .any(|note| note.receipt_id == receipt)
    {
        kept.push("preference");
    }
    let (causes, attempts) = door::amendment_cause_rows(vault, receipt).expect("cause rows read");
    if causes > 0 {
        kept.push("cause");
    }
    if attempts > 0 {
        kept.push("attempt index");
    }
    kept
}

#[test]
fn an_erase_of_an_owner_amended_claim_leaves_no_attribution_under_its_receipt() {
    let seeded = seed();
    let (target, receipt) = owner_amended_claim(&seeded);
    judge(&seeded, &receipt);
    assert_eq!(
        rows_kept(&seeded.vault, &receipt),
        vec!["evidence", "judgment", "preference", "cause"],
        "FIXTURE: the settled amendment keeps its rows under the receipt before the erase"
    );

    seeded
        .vault
        .delete_entity_with_reason(&target, DeleteReason::UserHardDelete)
        .expect("the owner's erase of the claim");

    let skeleton = seeded
        .vault
        .gate_decisions(1_000)
        .expect("ledger read after the erase")
        .into_iter()
        .find(|record| format!("gate:{}", record.decision_id.to_hex()) == receipt)
        .expect("the erase keeps the amended approval as its retention skeleton");
    assert!(
        skeleton.redacted_at.is_some() && skeleton.actor_ref.is_none(),
        "the erase redacts the amended approval: {skeleton:?}"
    );
    let kept = rows_kept(&seeded.vault, &receipt);
    assert!(
        kept.is_empty(),
        "the erase leaves no amendment attribution under the skeleton's receipt: {kept:?}"
    );
}

#[test]
fn an_erase_of_another_claim_keeps_the_amended_receipts_attribution() {
    let seeded = seed();
    let (_, receipt) = owner_amended_claim(&seeded);
    judge(&seeded, &receipt);
    let (other, other_receipt) = owner_amended_claim(&seeded);
    judge(&seeded, &other_receipt);

    seeded
        .vault
        .delete_entity_with_reason(&other, DeleteReason::UserHardDelete)
        .expect("the owner's erase of the other claim");

    assert_eq!(
        rows_kept(&seeded.vault, &receipt),
        vec!["evidence", "judgment", "preference", "cause"],
        "an erase of another claim leaves this receipt's rows as they were"
    );
}

/// The owner's erase of `target`, run by the next amendment attribution
/// writer after its reads and before it opens.
fn erase_before_next_writer(target: EntityId) {
    door::before_next_amendment_writer(Box::new(move |vault: &Vault| {
        vault
            .delete_entity_with_reason(&target, DeleteReason::UserHardDelete)
            .expect("the owner's erase, racing the writer");
    }));
}

/// The decider-preference routing facts for the amendment under `receipt`.
fn preference_evidence(seeded: &Seeded, receipt: &str) -> AmendmentEvidence {
    AmendmentEvidence::new(receipt, seeded.machine, SCOPE)
        .at(seeded.now)
        .with_cause(AmendmentCause::DeciderPreference)
}

#[test]
fn an_erase_that_overtakes_the_judges_reads_leaves_no_attribution_under_its_receipt() {
    let seeded = seed();
    let (target, receipt) = owner_amended_claim(&seeded);
    record_amendment_evidence(&seeded.vault, &preference_evidence(&seeded, &receipt))
        .expect("FIXTURE: the amendment evidence");
    erase_before_next_writer(target);

    judge_amendment(&seeded.vault, &receipt).expect("the judging pass");

    let kept = rows_kept(&seeded.vault, &receipt);
    assert!(
        kept.is_empty(),
        "a judge whose reads the erase overtook lands nothing under the skeleton's receipt: \
         {kept:?}"
    );
}

#[test]
fn an_erase_that_overtakes_the_evidence_doors_reads_leaves_no_evidence() {
    let seeded = seed();
    let (target, receipt) = owner_amended_claim(&seeded);
    erase_before_next_writer(target);

    let recorded =
        record_amendment_evidence(&seeded.vault, &preference_evidence(&seeded, &receipt));

    let kept = rows_kept(&seeded.vault, &receipt);
    assert!(
        kept.is_empty(),
        "an evidence write whose reads the erase overtook lands nothing under the skeleton's \
         receipt: {kept:?}"
    );
    assert!(
        recorded.is_err(),
        "the evidence door refuses a receipt whose Δ the erase took: {recorded:?}"
    );
}

/// A SKILL the vault holds Active: the one the lapse evidence says the
/// MACHINE had for the step and did not follow.
fn active_skill(vault: &Vault) -> EntityId {
    let id = EntityId::now();
    let tree = canonical_skill_tree_hash([("SKILL.md", b"# lapse fixture\n".as_slice())])
        .expect("FIXTURE: the skill tree hash");
    let candidate = SkillRecord::new(
        SKILL_ID,
        "a skill the machine did not follow",
        SKILL_VERSION,
        ClaimApprovalStatus::Approved,
        SkillLifecycle::Candidate,
        ClaimSource::UserStated,
        0.9,
        false,
        true,
        Vec::new(),
        rmpv::Value::Map(vec![(
            rmpv::Value::from("source"),
            rmpv::Value::from("gate-amendment-lapse-fixture"),
        )]),
    )
    .with_content_hash(tree);
    vault
        .put_skill_record(&id, &candidate, at(10), 11)
        .expect("FIXTURE: the skill");
    let mut active = candidate;
    active.lifecycle_status = SkillLifecycle::Active;
    vault
        .update_skill_record(&id, &active, at(12), 13)
        .expect("FIXTURE: the skill goes Active");
    id
}

/// The routing facts for the amendment under `receipt`, naming `skill`:
/// the proposal was wrong, and with `followed` unset the judge has a fact
/// unsettled and abstains. `Some(false)`: the MACHINE had the skill for the
/// step and did not follow it, an execution lapse.
fn lapse_evidence(
    seeded: &Seeded,
    receipt: &str,
    skill: EntityId,
    followed: Option<bool>,
) -> AmendmentEvidence {
    let evidence = AmendmentEvidence::new(receipt, seeded.machine, SCOPE)
        .at(seeded.now)
        .with_skill(skill)
        .with_cause(AmendmentCause::ProposalWrong);
    match followed {
        Some(followed) => evidence.with_routing_facts(followed, true),
        None => evidence,
    }
}

/// An owner-amended claim whose amendment the judge settles as one
/// execution lapse of the MACHINE, projected: its charge on the MACHINE's
/// own edit-cost cell and its lesson. Returns the claim, its receipt, the
/// skill and the judgment.
fn projected_lapse(seeded: &Seeded) -> (EntityId, String, EntityId, AmendmentJudgment) {
    let vault = &seeded.vault;
    let skill = active_skill(vault);
    let (target, receipt) = owner_amended_claim(seeded);
    record_amendment_evidence(vault, &lapse_evidence(seeded, &receipt, skill, Some(false)))
        .expect("FIXTURE: the lapse evidence");
    let judgment = judge_amendment(vault, &receipt)
        .expect("FIXTURE: the judging pass")
        .expect("FIXTURE: a skill the machine did not follow is a lapse");
    assert_eq!(
        judgment.sole_class(),
        Some(AmendmentClass::ExecutionLapse),
        "FIXTURE: the judgment is one execution lapse"
    );
    project_edit_cost_claims(vault, std::slice::from_ref(&judgment))
        .expect("FIXTURE: the edit-cost pass");
    project_amendment_lessons(vault, std::slice::from_ref(&judgment))
        .expect("FIXTURE: the lesson pass");
    assert!(
        machine_cell_runs(seeded, &judgment) > 0.0,
        "FIXTURE: the lapse charges the MACHINE's own edit-cost cell"
    );
    assert_eq!(
        active_lessons(seeded),
        vec![format!("execution_lapse:{receipt}")],
        "FIXTURE: the lapse earns the MACHINE one lesson citing the receipt"
    );
    (target, receipt, skill, judgment)
}

/// The own runs the MACHINE's edit-cost cell counts where `judgment`
/// charged it: none while the cell holds no row.
fn machine_cell_runs(seeded: &Seeded, judgment: &AmendmentJudgment) -> f64 {
    edit_cost_for(
        &seeded.vault,
        &seeded.machine,
        &seeded.machine.to_hex(),
        &judgment.scope,
        judgment.type_ref.as_ref(),
        judgment.project,
    )
    .expect("edit-cost read")
    .map_or(0.0, |estimate| estimate.runs)
}

/// The text of each Active lesson the MACHINE holds.
fn active_lessons(seeded: &Seeded) -> Vec<String> {
    let vault = &seeded.vault;
    let mut lessons = Vec::new();
    for id in vault
        .claims_for_subject(&seeded.machine)
        .expect("claim read")
    {
        let Some(body) = vault.get_claim(&id).expect("claim read") else {
            continue;
        };
        if body.predicate == PREDICATE_ACTOR_LESSON
            && body.lifecycle == ClaimLifecycleStatus::Active
            && let Some(text) = body.value.as_str()
        {
            lessons.push(text.to_owned());
        }
    }
    lessons
}

/// The owner's housekeeping pass: every engine sweep now, the gate-decision
/// sweep among them.
fn housekeeping(seeded: &Seeded) {
    seeded
        .vault
        .housekeeping_all(HousekeepingBudget::unbounded())
        .expect("the owner's housekeeping pass");
}

#[test]
fn an_erased_amendments_charge_and_lesson_go_on_the_next_gate_decision_sweep() {
    let seeded = seed();
    let (target, _, _, judgment) = projected_lapse(&seeded);
    seeded
        .vault
        .delete_entity_with_reason(&target, DeleteReason::UserHardDelete)
        .expect("the owner's erase of the claim");

    housekeeping(&seeded);

    assert_eq!(
        machine_cell_runs(&seeded, &judgment),
        0.0,
        "the sweep after the erase leaves the MACHINE's cell counting no run of the erased receipt"
    );
    assert!(
        active_lessons(&seeded).is_empty(),
        "the sweep after the erase retracts the erased receipt's lesson: {:?}",
        active_lessons(&seeded)
    );
}

#[test]
fn a_withdrawn_lapses_charge_and_lesson_go_on_the_next_gate_decision_sweep() {
    let seeded = seed();
    let (_, receipt, skill, judgment) = projected_lapse(&seeded);
    record_amendment_evidence(
        &seeded.vault,
        &lapse_evidence(&seeded, &receipt, skill, None),
    )
    .expect("FIXTURE: the routing facts recorded again, unsettled");
    assert!(
        judge_amendment(&seeded.vault, &receipt)
            .expect("the re-judging pass")
            .is_none(),
        "FIXTURE: a judge with a fact unsettled abstains, which withdraws the lapse"
    );

    housekeeping(&seeded);

    assert_eq!(
        machine_cell_runs(&seeded, &judgment),
        0.0,
        "the sweep after the withdrawal leaves the MACHINE's cell counting no run of the receipt"
    );
    assert!(
        active_lessons(&seeded).is_empty(),
        "the sweep after the withdrawal retracts the lapse's lesson: {:?}",
        active_lessons(&seeded)
    );
}

#[test]
fn a_gate_decision_sweep_keeps_a_standing_lapses_charge_and_lesson() {
    let seeded = seed();
    let (_, receipt, _, judgment) = projected_lapse(&seeded);

    housekeeping(&seeded);

    assert!(
        machine_cell_runs(&seeded, &judgment) > 0.0,
        "a sweep over a judgment nothing dropped leaves its charge in the MACHINE's cell"
    );
    assert_eq!(
        active_lessons(&seeded),
        vec![format!("execution_lapse:{receipt}")],
        "a sweep over a judgment nothing dropped leaves its lesson standing"
    );
}

/// A completed attempt the MACHINE ran with [`active_skill`]'s pack loaded,
/// returning its pack receipt; neither kind stamps a learning anchor.
/// `typed`: an agent dispatch, whose receipt carries the task typeRef;
/// otherwise a plain queue row, whose receipt carries none. `stamped`: its
/// executor revision is stamped.
fn completed_attempt(seeded: &Seeded, typed: bool, stamped: bool) -> String {
    let vault = &seeded.vault;
    let queue = AttemptQueue::new(vault);
    let now = vault.now_recorded_at();
    let (row, kind) = if typed {
        let AgentDispatchOutcome::Dispatched(dispatched) = AgentDispatcher::new(vault)
            .dispatch_default_base(None, None, None, now)
            .expect("FIXTURE: the agent dispatch")
        else {
            panic!("FIXTURE: a fresh agent dispatch");
        };
        (dispatched.attempt, DREAMER_RUNNER_ATTEMPT_KIND)
    } else {
        let EnqueueOutcome::Enqueued(row) = queue
            .enqueue(EnqueueAttempt {
                kind: UNTYPED_KIND.to_owned(),
                payload: b"untyped".to_vec(),
                dedupe_key: None,
                run_id: None,
                now,
            })
            .expect("FIXTURE: the queue row")
        else {
            panic!("FIXTURE: a fresh queue row");
        };
        (row, UNTYPED_KIND)
    };
    vault
        .bind_actor_attempt(row.id, &seeded.machine)
        .expect("FIXTURE: the MACHINE runs the attempt");
    queue
        .append_manifest_entry(
            row.id,
            ManifestEntry::new(ManifestKind::Skill, SKILL_ID, SKILL_VERSION, now),
        )
        .expect("FIXTURE: the pack loads the skill");
    let ClaimOutcome::Claimed(leased) = queue
        .claim_kind(
            kind,
            ClaimAttempt {
                lease_owner: LEASE.to_owned(),
                now: vault.now_recorded_at(),
            },
        )
        .expect("FIXTURE: the claim")
    else {
        panic!("FIXTURE: the attempt leases");
    };
    assert_eq!(leased.id, row.id, "FIXTURE: the claim leases this attempt");
    if stamped {
        queue
            .set_executor_model(row.id, LEASE, leased.attempt_count, MODEL)
            .expect("FIXTURE: the executor stamp");
    }
    let completed = queue
        .complete(CompleteAttempt {
            id: row.id,
            lease_owner: LEASE.to_owned(),
            attempt_count: leased.attempt_count,
            now: vault.now_recorded_at(),
        })
        .expect("FIXTURE: the completion");
    assert!(
        matches!(completed, CompleteOutcome::Completed(_)),
        "FIXTURE: the attempt completes"
    );
    attempt_pack_receipt_id(&row.id)
}

/// The routing facts for the amendment under `receipt`, joined with
/// `attempt`: the MACHINE followed the skill and the skill covered the step,
/// so the judge charges the skill one `skill_defect` share. With `settled`
/// false the facts are unset and the judge abstains.
fn defect_evidence(
    seeded: &Seeded,
    receipt: &str,
    skill: EntityId,
    attempt: &str,
    settled: bool,
) -> AmendmentEvidence {
    lapse_evidence(seeded, receipt, skill, settled.then_some(true)).with_attempt(attempt)
}

/// An owner-amended claim whose amendment the judge settles as one
/// `skill_defect` of `skill` on `attempt`; returns its receipt.
fn judged_defect(seeded: &Seeded, skill: EntityId, attempt: &str) -> String {
    let (_, receipt) = owner_amended_claim(seeded);
    record_amendment_evidence(
        &seeded.vault,
        &defect_evidence(seeded, &receipt, skill, attempt, true),
    )
    .expect("FIXTURE: the defect evidence");
    let judgment = judge_amendment(&seeded.vault, &receipt)
        .expect("FIXTURE: the judging pass")
        .expect("FIXTURE: a followed, covered step is the skill's defect");
    assert_eq!(
        judgment.sole_class(),
        Some(AmendmentClass::SkillDefect),
        "FIXTURE: the judgment is one skill defect"
    );
    receipt
}

/// The attempt's outcome as the skill's attributed ledger reads it.
fn attempt_outcome(seeded: &Seeded, skill: &EntityId, attempt: &str) -> Option<bool> {
    effective_skill_outcome(&seeded.vault, skill, attempt).expect("attributed outcome read")
}

/// A defect on the MACHINE's typed attempt projected and then withdrawn,
/// and a second defect judged on an attempt `stamped` as given, which only
/// the next sweep lands; then the sweep. Returns the skill and both attempts.
fn withdrawal_beside_second_defect(seeded: &Seeded, stamped: bool) -> (EntityId, String, String) {
    let vault = &seeded.vault;
    let skill = active_skill(vault);
    let typed = completed_attempt(seeded, true, true);
    let first = judged_defect(seeded, skill, &typed);
    assert_eq!(
        project_amendment_reliability(vault).expect("FIXTURE: the reliability pass"),
        vec![skill],
        "FIXTURE: the defect moves the skill's record"
    );
    assert_eq!(
        attempt_outcome(seeded, &skill, &typed),
        Some(false),
        "FIXTURE: the typed attempt reads as the defect's loss"
    );

    let untyped = completed_attempt(seeded, false, stamped);
    judged_defect(seeded, skill, &untyped);
    record_amendment_evidence(
        vault,
        &defect_evidence(seeded, &first, skill, &typed, false),
    )
    .expect("FIXTURE: the first amendment's routing facts recorded again, unset");
    assert!(
        judge_amendment(vault, &first)
            .expect("the re-judging pass")
            .is_none(),
        "FIXTURE: a judge with the facts unset abstains, which withdraws the first defect"
    );

    housekeeping(seeded);
    (skill, typed, untyped)
}

#[test]
fn a_sweep_lands_a_withdrawal_beside_an_untyped_attempts_defect() {
    let seeded = seed();
    let (skill, typed, untyped) = withdrawal_beside_second_defect(&seeded, true);
    assert_eq!(
        attempt_outcome(&seeded, &skill, &typed),
        None,
        "the sweep withdraws the first defect: an attempt with no typeRef beside it holds nothing"
    );
    assert_eq!(
        attempt_outcome(&seeded, &skill, &untyped),
        Some(false),
        "the same sweep lands the untyped attempt's defect"
    );
}

#[test]
fn a_sweep_lands_a_withdrawal_beside_an_unstamped_attempts_defect() {
    let seeded = seed();
    let (skill, typed, unstamped) = withdrawal_beside_second_defect(&seeded, false);
    assert_eq!(
        attempt_outcome(&seeded, &skill, &typed),
        None,
        "the sweep withdraws the first defect: an attempt with no executor stamp beside it \
         holds nothing"
    );
    assert_eq!(
        attempt_outcome(&seeded, &skill, &unstamped),
        Some(false),
        "the same sweep lands the unstamped attempt's defect"
    );
}
