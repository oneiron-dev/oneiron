use std::cell::RefCell;

use super::job::PROVENANCE_OPTIMIZE_PRINCIPAL_KEY;
use super::*;

use crate::attempt_queue::{
    AttemptQueue, ClaimAttempt, ClaimOutcome, CompleteAttempt, CompleteOutcome, EnqueueAttempt,
    EnqueueOutcome, ManifestEntry, ManifestKind,
};
use crate::config::VaultConfig;
use crate::dreamer_runner::{
    DreamerRunnerStore, EnqueueDreamerAttemptOutcome, EnqueueDreamerSkillOptimizeAttempt,
};
use crate::edge::EdgeKind;
use crate::error::ErrorKind;
use crate::receipt::attempt_pack_receipt_id;
use crate::registry::ENTITY_TYPE_PERSON;
use crate::skill_attribution::{
    AttemptOutcome, OutcomeEvidence, read_attribution_cursor, record_attribution_evidence,
    run_attribution_projector,
};
use crate::skill_hub::{HubFile, HubPackage, SkillCapabilitySurface};
use crate::skill_reliability::{project_skill_reliability, record_skill_contributing_win};

// ─── fixtures ───────────────────────────────────────────────────────────

const FIXTURE_VERSION: &str = "1.0.0";

fn temp_vault() -> (tempfile::TempDir, Vault) {
    let tmp = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(tmp.path(), VaultConfig::default()).expect("open vault");
    (tmp, vault)
}

fn t(ts: u64) -> TimeRange {
    TimeRange { start: ts, end: ts }
}

fn provenance(birth: Option<&str>) -> Value {
    match birth {
        Some(path) => Value::Map(vec![(Value::from(PROVENANCE_BIRTH_KEY), Value::from(path))]),
        None => Value::Map(vec![(
            Value::from("source"),
            Value::from("skill-opt-fixture"),
        )]),
    }
}

/// A human-authored skill (prior Beta(2, 1), mean ≈ 0.667) with the fixture's
/// choice of tier mark and birth path.
fn record(skill_id: &str, tier: Option<SkillGovernanceTier>, birth: Option<&str>) -> SkillRecord {
    let record = SkillRecord::new(
        skill_id,
        "Do the thing, then the other thing.",
        FIXTURE_VERSION,
        ClaimApprovalStatus::Approved,
        SkillLifecycle::Candidate,
        ClaimSource::UserStated,
        0.5,
        false,
        true,
        vec![SkillDependency::new("oneiron.skill.base")],
        provenance(birth),
    );
    match tier {
        Some(tier) => record.with_governance_tier(tier),
        None => record,
    }
}

/// Puts a skill and walks it `candidate → active`.
fn put_active(vault: &Vault, id: &EntityId, record: &SkillRecord) -> SkillRecord {
    vault.put_skill_record(id, record, t(10), 11).expect("put");
    let mut active = record.clone();
    active.lifecycle_status = SkillLifecycle::Active;
    vault
        .update_skill_record(id, &active, t(12), 13)
        .expect("activate");
    active
}

/// The ordinary case: an active, standard-marked, optimizable skill.
fn put_standard_active(vault: &Vault, skill_id: &str) -> (EntityId, SkillRecord) {
    let id = EntityId::now();
    let record = put_active(
        vault,
        &id,
        &record(skill_id, Some(SkillGovernanceTier::Standard), None),
    );
    (id, record)
}

fn put_actor(vault: &Vault, id: &EntityId) {
    vault
        .put_entity(id, ENTITY_TYPE_PERSON, t(1), 1, b"skill-opt actor")
        .expect("put actor");
}

fn stamped_receipt_version_as(
    vault: &Vault,
    skill_id: &str,
    version: &str,
    now: u64,
    actor: Option<EntityId>,
) -> String {
    let queue = AttemptQueue::new(vault);
    let EnqueueOutcome::Enqueued(attempt) = queue
        .enqueue(EnqueueAttempt {
            kind: "skill-opt.attempt".to_owned(),
            payload: Vec::new(),
            dedupe_key: None,
            run_id: None,
            now,
        })
        .expect("enqueue")
    else {
        panic!("a fresh dedupe-free enqueue is never Existing");
    };
    if let Some(actor) = actor {
        vault
            .bind_actor_attempt(attempt.id, &actor)
            .expect("bind executor");
    }
    queue
        .append_manifest_entry(
            attempt.id,
            ManifestEntry::new(ManifestKind::Skill, skill_id, version, now),
        )
        .expect("manifest append");
    let ClaimOutcome::Claimed(leased) = queue
        .claim(ClaimAttempt {
            lease_owner: "skill-opt-worker".to_owned(),
            now: now + 1,
        })
        .expect("claim")
    else {
        panic!("the enqueued attempt is claimable");
    };
    queue
        .set_executor_model(
            attempt.id,
            "skill-opt-worker",
            leased.attempt_count,
            "fixture/model@1",
        )
        .expect("stamp model");
    let CompleteOutcome::Completed(_) = queue
        .complete(CompleteAttempt {
            id: attempt.id,
            lease_owner: "skill-opt-worker".to_owned(),
            attempt_count: leased.attempt_count,
            now: now + 2,
        })
        .expect("complete")
    else {
        panic!("a leased attempt completes exactly once");
    };
    let receipt_id = attempt_pack_receipt_id(&attempt.id);
    crate::receipt::make_attempt_receipt_legacy_for_tests(vault, &receipt_id)
        .expect("emulate historical unknown-executor evidence");
    receipt_id
}

/// Attributes SK-04 skill DEFECTS until the DEV partition holds `count` more of
/// them AND the skill reserves at least one held-out receipt, projecting the
/// posterior as it goes.
///
/// `count` is stated in DEV outcomes, not in attributed ones, because that is
/// the quantity the job under test actually reads: ONE-1449 makes the N dial,
/// the ranking and the brief dev-partition-only, so a fixture that attributed
/// exactly five and then asserted the job saw five would be asserting a
/// one-in-five coin flip five times over. Every attributed receipt is still
/// returned, both sides of the split together, so a caller can still reason
/// about the partition as a whole.
///
/// The RESERVE is guaranteed here as well because selection now reads it too:
/// a skill with an empty reserve is not a candidate at all (the gate would have
/// nothing to score it against), so a fixture that left it to the hash would
/// make every drafting test a one-in-four coin flip. The top-up records ONLY
/// reserved draws, so the dev count stays exactly the number the caller asked
/// for.
fn attribute_defects(vault: &Vault, skill: &EntityId, skill_id: &str, count: u32) -> Vec<String> {
    let actor = EntityId::now();
    put_actor(vault, &actor);
    let target = dev_receipts(vault, skill).expect("dev split").len()
        + usize::try_from(count).expect("count fits");
    let mut receipts = Vec::new();
    let mut minted = 0u32;
    let attribute = |receipt: &str, at: u64| {
        record_attribution_evidence(
            vault,
            &OutcomeEvidence::new(receipt, actor, AttemptOutcome::Failed, at + 5)
                .with_skill(*skill)
                .with_routing_facts(true, true),
        )
        .expect("record evidence");
        let cursor = read_attribution_cursor(vault).expect("cursor");
        let judgments = run_attribution_projector(vault, cursor).expect("attribution pass");
        project_skill_reliability(vault, &judgments).expect("reliability pass");
    };
    while dev_receipts(vault, skill).expect("dev split").len() < target {
        assert!(
            minted < count * 12 + 12,
            "a four-in-five dev draw reaches {count} long before {minted} attempts"
        );
        let at = 100 + u64::from(minted) * 10;
        let receipt = stamped_receipt_version_as(vault, skill_id, FIXTURE_VERSION, at, Some(actor));
        minted += 1;
        attribute(&receipt, at);
        receipts.push(receipt);
    }
    while held_out_receipts(vault, skill)
        .expect("held-out split")
        .is_empty()
    {
        assert!(
            minted < count * 12 + 60,
            "one receipt in five is reserved, so {minted} draws is not a near miss"
        );
        let at = 100 + u64::from(minted) * 10;
        let receipt = stamped_receipt_version_as(vault, skill_id, FIXTURE_VERSION, at, Some(actor));
        minted += 1;
        if !receipt_is_held_out(skill, &receipt) {
            continue;
        }
        attribute(&receipt, at);
        receipts.push(receipt);
    }
    receipts
}

const DRAFTED_DESC: &str = "Do the thing. Check the result BEFORE the other thing.";

/// The engine double. Records every brief it was handed, so a test can assert
/// what the job actually read.
struct StubAuthor {
    answer: SkillEditDraft,
    seen: RefCell<Vec<SkillOptimizeBrief>>,
}

impl StubAuthor {
    fn editing() -> Self {
        Self {
            answer: SkillEditDraft::Edit {
                desc: DRAFTED_DESC.to_owned(),
                rationale: "five attributed defects name the missing check".to_owned(),
            },
            seen: RefCell::new(Vec::new()),
        }
    }

    fn brief(&self) -> SkillOptimizeBrief {
        self.seen.borrow().first().cloned().expect("one brief")
    }
}

impl SkillOptimizeAuthor for StubAuthor {
    fn draft(&self, brief: &SkillOptimizeBrief) -> Result<SkillEditDraft> {
        self.seen.borrow_mut().push(brief.clone());
        Ok(self.answer.clone())
    }
}

/// An author that must never be reached: selection already answered.
struct UnreachableAuthor;

impl SkillOptimizeAuthor for UnreachableAuthor {
    fn draft(&self, _brief: &SkillOptimizeBrief) -> Result<SkillEditDraft> {
        panic!("a healthy library must not reach the authoring tier");
    }
}

/// One drafting attempt, through a REAL queue row.
///
/// The drafting door resolves the cycle a proposal is born into from the
/// attempt's stored row and fails closed when there is none, so a fixture that
/// invented an [`AttemptId`] would be drafting into a cycle nothing proves.
fn run(vault: &Vault, author: &dyn SkillOptimizeAuthor) -> Result<SkillOptimizeOutcome> {
    let attempt = enqueue_attempt(vault, None, 5);
    run_skill_optimize(vault, attempt, author, t(300), 301)
}

/// The record as it stands right now.
///
/// The baseline for "the job touched nothing" has to be read AFTER the
/// reliability pass: projecting the posterior refreshes the record's demoted
/// `confidence` CACHE (ONE-1738), which is truth moving, not this job.
fn stored(vault: &Vault, id: &EntityId) -> SkillRecord {
    vault.get_skill_record(id).expect("read").expect("stored")
}

// ─── ONE-1449 fixtures ──────────────────────────────────────────────────

/// The target's instructions, as [`record`] writes them.
const TARGET_DESC: &str = "Do the thing, then the other thing.";

/// Attributes defects until BOTH sides of the held-out split are populated, the
/// dev side deeply enough to clear the N dial.
///
/// The split is a hash of receipt identity and the fixture's receipt ids are
/// UUIDv7-derived, so how many outcomes it takes to cover both sides is not
/// knowable up front. Looping until the precondition HOLDS is what makes these
/// tests deterministic — a fixed count would be a 1-in-3 coin flip on five
/// receipts, which is a flaky suite, not a strict gate.
///
/// [`attribute_defects`] guarantees both sides on its own now (the selector
/// reads the reserve too), so what this adds is the LOUD spelling: a gate-facing
/// test says in its fixture that it depends on both halves being populated, and
/// keeps saying so if the selector's own precondition ever moves again.
fn attribute_defects_across_split(vault: &Vault, skill: &EntityId, skill_id: &str) -> Vec<String> {
    let mut receipts = Vec::new();
    for _ in 0..24 {
        receipts.extend(attribute_defects(vault, skill, skill_id, 5));
        let reserved = held_out_receipts(vault, skill).expect("held-out split");
        let dev = dev_receipts(vault, skill).expect("dev split");
        if !reserved.is_empty() && !dev.is_empty() {
            return receipts;
        }
    }
    panic!("a one-in-five split covers both sides long before 120 outcomes");
}

/// An active losing skill plus the one gated proposal ONE-1448 drafts for it.
fn losing_skill_with_proposal(vault: &Vault, skill_id: &str) -> (EntityId, EntityId) {
    let (skill, _) = put_standard_active(vault, skill_id);
    attribute_defects_across_split(vault, &skill, skill_id);
    let proposal = run(vault, &StubAuthor::editing())
        .expect("attempt")
        .proposal
        .expect("a losing skill draws a proposal");
    (skill, proposal)
}

/// The replay judge double.
///
/// Keyed on the INSTRUCTIONS it is handed, which is the only thing that differs
/// between a verdict's two cases — so a scorer that answered on anything else
/// would be answering the wrong question.
struct StubScorer {
    before: f32,
    after: f32,
    revision: &'static str,
    seen: RefCell<Vec<(String, Vec<String>)>>,
}

impl StubScorer {
    fn new(before: f32, after: f32) -> Self {
        Self {
            before,
            after,
            revision: "fixture-judge@1",
            seen: RefCell::new(Vec::new()),
        }
    }

    /// The proposed text replays better than the text it replaces.
    fn improving() -> Self {
        Self::new(0.40, 0.75)
    }

    fn with_revision(mut self, revision: &'static str) -> Self {
        self.revision = revision;
        self
    }

    /// Every held-out list this scorer was handed.
    fn evidence(&self) -> Vec<Vec<String>> {
        self.seen
            .borrow()
            .iter()
            .map(|(_, receipts)| receipts.clone())
            .collect()
    }
}

impl HeldOutReplayScorer for StubScorer {
    fn judge_revision(&self) -> &str {
        self.revision
    }
    fn score(&self, case: &HeldOutReplayCase<'_>) -> Result<f32> {
        self.seen.borrow_mut().push((
            case.instructions.to_owned(),
            case.held_out_receipts.to_vec(),
        ));
        Ok(if case.instructions == TARGET_DESC {
            self.before
        } else {
            self.after
        })
    }
    fn structural_audit(&self, _task: &str, _instructions: &str) -> Result<f32> {
        Ok(0.5)
    }
    fn blind_preference(&self, _task: &str, _receipts: &[String]) -> Result<Vec<BlindPreference>> {
        Ok(vec![BlindPreference {
            pair_ref: "fixture-pair".to_owned(),
            preferred: PreferredResponse::First,
        }])
    }
    fn contrastive_audit(
        &self,
        _case: &HeldOutReplayCase<'_>,
        _blind: &[BlindPreference],
    ) -> Result<f32> {
        Ok(0.5)
    }
    fn predict_task_success(&self, case: &HeldOutReplayCase<'_>) -> Result<Vec<f32>> {
        Ok(vec![0.5; case.held_out_receipts.len()])
    }
}

/// A scorer that must never be reached.
struct UnreachableScorer;

impl HeldOutReplayScorer for UnreachableScorer {
    fn judge_revision(&self) -> &str {
        "fixture-judge@1"
    }
    fn score(&self, _case: &HeldOutReplayCase<'_>) -> Result<f32> {
        panic!("a refused proposal must not reach the replay tier");
    }
    fn structural_audit(&self, _task: &str, _instructions: &str) -> Result<f32> {
        Ok(0.5)
    }
    fn blind_preference(&self, _task: &str, _receipts: &[String]) -> Result<Vec<BlindPreference>> {
        Ok(vec![BlindPreference {
            pair_ref: "fixture-pair".to_owned(),
            preferred: PreferredResponse::First,
        }])
    }
    fn contrastive_audit(
        &self,
        _case: &HeldOutReplayCase<'_>,
        _blind: &[BlindPreference],
    ) -> Result<f32> {
        Ok(0.5)
    }
    fn predict_task_success(&self, case: &HeldOutReplayCase<'_>) -> Result<Vec<f32>> {
        Ok(vec![0.5; case.held_out_receipts.len()])
    }
}

/// Enqueues one real attempt row — the durable scheduler identity every cycle
/// label is now derived from. `run` names the wake when the attempt belongs to
/// one; a runless attempt is its own cycle.
///
/// The row is claimed and completed straight away rather than left READY,
/// because [`stamped_receipt_version_as`] claims whatever the queue offers next: a wake row
/// idling in the ready set would be leased out from under it. What proves the
/// cycle is the stored ROW, and that outlives any lease.
fn enqueue_attempt(vault: &Vault, run: Option<&str>, now: u64) -> AttemptId {
    let queue = AttemptQueue::new(vault);
    let EnqueueDreamerAttemptOutcome::Enqueued(status) = DreamerRunnerStore::new(vault)
        .enqueue_skill_optimize(EnqueueDreamerSkillOptimizeAttempt {
            input: Value::Nil,
            parent_attempt: None,
            dedupe_key: None,
            run_id: run.map(str::to_owned),
            now,
        })
        .expect("enqueue")
    else {
        panic!("a fresh dedupe-free enqueue is never Existing");
    };
    let attempt = status.attempt;
    let ClaimOutcome::Claimed(leased) = queue
        .claim(ClaimAttempt {
            lease_owner: "skill-opt-wake".to_owned(),
            now: now + 1,
        })
        .expect("claim")
    else {
        panic!("the enqueued attempt is claimable");
    };
    assert_eq!(
        leased.id, attempt.id,
        "the fixtures leave the ready set empty between attempts"
    );
    let CompleteOutcome::Completed(_) = queue
        .complete(CompleteAttempt {
            id: attempt.id,
            lease_owner: "skill-opt-wake".to_owned(),
            attempt_count: leased.attempt_count,
            now: now + 2,
        })
        .expect("complete")
    else {
        panic!("a leased attempt completes exactly once");
    };
    attempt.id
}

/// The proven wake a gate call rules under.
///
/// A cycle is no longer a string a caller can invent: the gate takes an
/// [`AttemptId`] and resolves the label from that attempt's stored row. Two
/// attempts enqueued under the same `run` therefore name the SAME cycle, which
/// is exactly the quantity the per-wake cap counts.
fn wake(vault: &Vault, run: &str, now: u64) -> AttemptId {
    enqueue_attempt(vault, Some(run), now)
}

/// The projected Gate receipt for one verdict row.
fn verdict_receipt(vault: &Vault, verdict: &HeldOutVerdict) -> crate::receipt::ReceiptRecord {
    let wanted = format!("skill_edit:{}", verdict.id.to_hex());
    vault
        .receipts(crate::receipt::ReceiptQuery::default())
        .expect("receipts")
        .into_iter()
        .find(|record| record.receipt_id == wanted)
        .expect("every verdict projects a Gate receipt")
}

// ─── reading the signal, drafting the proposal ──────────────────────────

#[test]
fn a_losing_skill_drafts_one_gated_proposal_citing_its_defect_evidence() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let (skill, _) = put_standard_active(&vault, "oneiron.skill.losing");
    let receipts = attribute_defects(&vault, &skill, "oneiron.skill.losing", 5);
    let before = stored(&vault, &skill);

    let author = StubAuthor::editing();
    let outcome = run(&vault, &author)?;

    // The brief is the evidence, not a summary of it.
    let brief = author.brief();
    assert_eq!(brief.skill, skill);
    assert_eq!(brief.desc, before.desc);
    assert_eq!(brief.attributed_outcomes, 5);
    assert!(
        brief.posterior.mean() < brief.prior.mean(),
        "the job selects on evidence of LOSS"
    );
    // ONE-1449: the author reads the DEV split, never the whole ledger. Both
    // evidence lists are the same reserved-free view of the same receipts.
    let dev = dev_receipts(&vault, &skill)?;
    let reserved = held_out_receipts(&vault, &skill)?;
    assert_eq!(brief.defect_receipts, dev);
    assert_eq!(brief.cited_receipts, dev);
    assert_eq!(
        dev.len() + reserved.len(),
        receipts.len(),
        "the two views partition the attributed set"
    );
    assert!(
        reserved
            .iter()
            .all(|receipt| !brief.defect_receipts.contains(receipt)),
        "no reserved receipt reaches the tier that writes the replacement"
    );

    assert_eq!(outcome.skill, Some(skill));
    let proposal_id = outcome.proposal.expect("a losing skill draws a proposal");

    // GATED: proposed, candidate, and a revision of the same skill.
    let proposal = vault
        .get_skill_record(&proposal_id)?
        .expect("the proposal is a stored SKILL");
    assert_eq!(proposal.approval_status, ClaimApprovalStatus::Proposed);
    assert_eq!(proposal.lifecycle_status, SkillLifecycle::Candidate);
    assert_eq!(proposal.skill_id, before.skill_id);
    assert_eq!(proposal.desc, DRAFTED_DESC);
    let Value::Map(ref provenance) = proposal.provenance else {
        panic!("proposal provenance is a map");
    };
    let authority = vault.dreamer_authority()?;
    assert!(provenance.iter().any(|(key, value)| {
        key.as_str() == Some("actor_entity_ref")
            && value.as_slice() == Some(authority.entity_ref().as_bytes().as_slice())
    }));
    assert!(provenance.iter().any(|(key, value)| {
        key.as_str() == Some("actor_class")
            && value.as_u64() == Some(u64::from(crate::EdgeActorClass::System as u8))
    }));
    assert_ne!(proposal.version, before.version);
    assert_eq!(
        proposal.dependencies, before.dependencies,
        "a revision inherits the contract its predecessor shipped with"
    );
    assert_eq!(
        proposal.governance_tier,
        Some(SkillGovernanceTier::Standard),
        "the successor carries the tier forward explicitly"
    );

    // NOT A MUTATION: the Active record is byte-identical to what it was.
    let after = vault.get_skill_record(&skill)?.expect("target survives");
    assert_eq!(after, before);

    // ONE proposal per attempt, and the open question stops the next attempt
    // from asking it again.
    let second = run(&vault, &StubAuthor::editing())?;
    assert_eq!(second.skill, None);
    assert_eq!(second.proposal, None);
    Ok(())
}

#[test]
fn approval_admits_the_successor_through_the_supersede_chain() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let (skill, proposal_id) = losing_skill_with_proposal(&vault, "oneiron.skill.losing");
    let before = stored(&vault, &skill);

    // The admission act, now routed through ONE-1449's gate: score first, then
    // admit. Nothing the drafting job wrote could do either — it can only stamp
    // `proposed`, and a bare flip is refused at the chokepoint.
    let scorer = StubScorer::improving();
    score_gate_skill_edit_in_cycle(
        &vault,
        &proposal_id,
        &scorer,
        wake(&vault, "wake-1", 10),
        900,
    )?;
    admit_optimized_skill_revision(&vault, &proposal_id, t(400), 401)?;
    let admitted = stored(&vault, &proposal_id);
    assert_eq!(admitted.approval_status, ClaimApprovalStatus::Approved);
    assert_eq!(admitted.lifecycle_status, SkillLifecycle::Active);

    // A bare flip into `superseded` is NOT the archive path.
    let mut bare_flip = before.clone();
    bare_flip.lifecycle_status = SkillLifecycle::Superseded;
    let err = vault
        .update_skill_record(&skill, &bare_flip, t(402), 403)
        .expect_err("the update door never archives");
    assert_eq!(err.kind(), ErrorKind::InvalidSkillBody);

    // The supersede door does: prior frozen, succession edge new → old.
    vault.supersede_skill_record(&skill, &proposal_id, t(404), 405)?;
    let frozen = vault.get_skill_record(&skill)?.expect("prior revision");
    assert_eq!(frozen.lifecycle_status, SkillLifecycle::Superseded);
    assert_eq!(
        frozen.desc, before.desc,
        "freezing a revision preserves it; it does not rewrite it"
    );
    let edges = vault.edges_out(&proposal_id)?;
    assert_eq!(edges.len(), 1, "exactly one succession edge");
    assert_eq!(edges[0].kind, EdgeKind::Supersedes);
    assert_eq!(edges[0].target, skill);
    Ok(())
}

// ─── the exclusion pre-check ────────────────────────────────────────────

#[test]
fn identity_and_alignment_tiers_never_enter_the_candidate_list() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let mut protected = Vec::new();
    for (skill_id, tier) in [
        ("oneiron.skill.identity", SkillGovernanceTier::Identity),
        ("oneiron.skill.alignment", SkillGovernanceTier::Alignment),
    ] {
        let id = EntityId::now();
        put_active(&vault, &id, &record(skill_id, Some(tier), None));
        attribute_defects(&vault, &id, skill_id, 5);
        protected.push(id);
    }

    for id in &protected {
        let verdict = skill_governance_tier(&vault, id)?;
        assert!(!verdict.optimizable());
        assert!(verdict.tier().expect("a marked tier").is_protected());
    }
    assert!(
        optimize_candidates(&vault)?.is_empty(),
        "protected skills are ABSENT from the list, not rejected after it"
    );
    let outcome = run(&vault, &UnreachableAuthor)?;
    assert_eq!(outcome.proposal, None);
    Ok(())
}

// ─── ONE-1449: the held-out split ───────────────────────────────────────

/// Owner-scoped rejection feedback is not a back door into another
/// principal's preference evidence, including an unbound optimizer job.
#[test]
fn rejected_edit_buffer_keeps_preference_principals_separate() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let (skill, _) = put_standard_active(&vault, "oneiron.skill.private-buffer");
    attribute_defects_across_split(&vault, &skill, "oneiron.skill.private-buffer");
    let owner_id = EntityId::now();
    let other_id = EntityId::now();
    put_actor(&vault, &owner_id);
    put_actor(&vault, &other_id);
    let owner = crate::write_envelope::WriteActor::new(owner_id, crate::EdgeActorClass::Human);
    let other = crate::write_envelope::WriteActor::new(other_id, crate::EdgeActorClass::Human);
    let first = run_skill_optimize_as(
        &vault,
        enqueue_attempt(&vault, None, 5),
        &StubAuthor::editing(),
        t(300),
        301,
        owner,
    )?
    .proposal
    .expect("owner-scoped edit");
    score_gate_skill_edit_in_cycle(
        &vault,
        &first,
        &StubScorer::new(0.60, 0.55),
        wake(&vault, "wake-private", 10),
        900,
    )?;
    // The ordinary candidate update door permits this provenance value to
    // change before scoring. The verdict digest therefore binds the MALFORMED
    // body: a digest comparison by itself does not make the stamp unbound.
    for (index, malformed_value) in [Value::Nil, Value::from(42), Value::from("not-an-id")]
        .into_iter()
        .enumerate()
    {
        let proposal = run_skill_optimize_as(
            &vault,
            enqueue_attempt(&vault, None, 20 + index as u64),
            &StubAuthor::editing(),
            t(400 + index as u64),
            401 + index as u64,
            owner,
        )?
        .proposal
        .expect("owner-scoped edit");
        let mut malformed = stored(&vault, &proposal);
        malformed.version = format!("opt-malformed-{index}");
        let Value::Map(ref mut provenance) = malformed.provenance else {
            panic!("optimizer provenance is a map");
        };
        let (_, stamp) = provenance
            .iter_mut()
            .find(|(key, _)| key.as_str() == Some(PROVENANCE_OPTIMIZE_PRINCIPAL_KEY))
            .expect("owner stamp");
        *stamp = malformed_value;
        vault.update_skill_record(
            &proposal,
            &malformed,
            t(500 + index as u64),
            501 + index as u64,
        )?;
        score_gate_skill_edit_in_cycle(
            &vault,
            &proposal,
            &StubScorer::new(0.60, 0.55),
            wake(&vault, "wake-malformed", 10),
            910 + index as u64,
        )?;
    }
    let candidate = optimize_candidates(&vault)?
        .into_iter()
        .find(|candidate| candidate.skill == skill)
        .expect("still eligible");
    assert!(
        optimize_brief(&vault, &candidate)?
            .rejected_edits
            .is_empty()
    );
    assert!(
        optimize_brief_for_principal_at(&vault, &candidate, other, 301)?
            .rejected_edits
            .is_empty()
    );
    assert_eq!(
        optimize_brief_for_principal_at(&vault, &candidate, owner, 301)?.rejected_edits[0].proposal,
        first
    );
    Ok(())
}

// ─── ONE-1449: the protected-tier accept-time recheck ───────────────────

#[test]
fn a_protected_tier_refuses_at_accept_even_when_the_score_improves() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    for (skill_id, tier) in [
        ("oneiron.skill.identity", SkillGovernanceTier::Identity),
        ("oneiron.skill.alignment", SkillGovernanceTier::Alignment),
    ] {
        let (skill, proposal) = losing_skill_with_proposal(&vault, skill_id);

        // The owner marks the target protected AFTER the draft was taken — a
        // state flip through the ordinary door, which this ticket must not
        // touch. The gate has to see the newer ruling, not the older one.
        let mut marked = stored(&vault, &skill);
        marked.governance_tier = Some(tier);
        vault.update_skill_record(&skill, &marked, t(500), 501)?;

        let scorer = StubScorer::improving();
        assert_eq!(
            score_gate_skill_edit_in_cycle(
                &vault,
                &proposal,
                &scorer,
                wake(&vault, "wake-1", 10),
                900
            )
            .expect_err("a protected tier is refused at accept time")
            .kind(),
            ErrorKind::InvalidSkillBody
        );
        let verdict = skill_edit_verdict(&vault, &proposal)?.expect("a durable refusal");
        assert_eq!(
            verdict.disposition,
            SkillEditDisposition::RefusedProtectedTier
        );
        assert!(
            verdict.after > verdict.before,
            "refused EVEN THOUGH it improved — the receipt has to be able to say so"
        );
        assert_eq!(
            verdict_receipt(&vault, &verdict).outcome,
            "refused_protected_tier"
        );

        // No mutation on any record, and admission refuses it too.
        assert_eq!(
            stored(&vault, &proposal).lifecycle_status,
            SkillLifecycle::Candidate
        );
        assert_eq!(
            admit_optimized_skill_revision(&vault, &proposal, t(502), 503)
                .expect_err("a refused proposal is never admitted")
                .kind(),
            ErrorKind::InvalidSkillBody
        );

        // The dial is on the ROBOT: the owner still edits their own protected
        // skill through the ordinary door, content and all.
        let mut owner_edit = stored(&vault, &skill);
        owner_edit.desc = "The owner rewrote this by hand.".to_owned();
        owner_edit.version = "2.0.0".to_owned();
        vault.update_skill_record(&skill, &owner_edit, t(504), 505)?;
        let after = stored(&vault, &skill);
        assert_eq!(after.desc, "The owner rewrote this by hand.");
        assert_eq!(after.governance_tier, Some(tier));
        assert_eq!(after.lifecycle_status, SkillLifecycle::Active);
    }
    Ok(())
}

// ─── ONE-1449: cited-source liveness at candidate → active ──────────────

/// Hand-crafts an optimizer-born proposal citing `sources`.
///
/// ONE-1448's drafter stamps no `source_messages` of its own — its bytes are an
/// author's, not a passage's, and inheriting the target's citation would be a
/// fabricated one. The liveness rule still has to hold for any optimizer-born
/// record that DOES carry the linkage, which is exactly what the blueprint's
/// "hand-crafted proposal against this job's accept path" means, so the fixture
/// mints one directly.
fn optimizer_proposal_citing(vault: &Vault, target: &EntityId, sources: Value) -> EntityId {
    let id = EntityId::now();
    let record = optimizer_proposal_record_citing(vault, target, sources, HAND_CRAFTED_CYCLE);
    vault
        .put_skill_record(&id, &record, t(300), 301)
        .expect("put");
    id
}

/// The birth cycle a hand-crafted proposal carries.
///
/// Every optimizer-born proposal must be stamped with the cycle it was drafted
/// in — the gate refuses one that is not — so a fixture that mints a proposal
/// by hand stamps it too. The label a hand-crafted record carries is not the
/// one the gate rules under: presenting another proven wake is the ordinary
/// later-cycle pickup.
const HAND_CRAFTED_CYCLE: Option<&str> = Some("run:hand-crafted");

/// A proposal born with NO cycle stamp at all — the shape both gate doors must
/// now refuse rather than rule on.
fn unstamped_optimizer_proposal(vault: &Vault, target: &EntityId) -> EntityId {
    let id = EntityId::now();
    let record = optimizer_proposal_record_citing(vault, target, Value::Array(Vec::new()), None);
    vault
        .put_skill_record(&id, &record, t(300), 301)
        .expect("put");
    id
}

/// The record [`optimizer_proposal_citing`] lands, unlanded.
fn optimizer_proposal_record_citing(
    vault: &Vault,
    target: &EntityId,
    sources: Value,
    cycle: Option<&str>,
) -> SkillRecord {
    let target_record = stored(vault, target);
    let mut provenance = vec![
        (
            Value::from(PROVENANCE_BIRTH_KEY),
            Value::from(SKILL_OPTIMIZE_BIRTH_PATH),
        ),
        (
            Value::from(PROVENANCE_OPTIMIZE_OF_KEY),
            Value::from(target_record.skill_id.as_str()),
        ),
        (
            Value::from(PROVENANCE_OPTIMIZE_OF_ENTITY_KEY),
            Value::from(target.to_hex()),
        ),
        (
            Value::from(GOAL_ID_KEY),
            Value::from(
                SkillGoalId::of(target, &target_record)
                    .expect("valid target goal")
                    .entity()
                    .to_hex(),
            ),
        ),
        (
            Value::from(PROVENANCE_OPTIMIZE_OF_VERSION_KEY),
            Value::from(target_record.version.as_str()),
        ),
        (
            Value::from(crate::skill_convert::PROVENANCE_SOURCE_MESSAGES_KEY),
            sources,
        ),
    ];
    if let Some(cycle) = cycle {
        provenance.push((
            Value::from(PROVENANCE_OPTIMIZE_CYCLE_KEY),
            Value::from(cycle),
        ));
    }
    let provenance = Value::Map(provenance);
    SkillRecord::new(
        target_record.skill_id.as_str(),
        DRAFTED_DESC,
        "opt-cited",
        ClaimApprovalStatus::Proposed,
        SkillLifecycle::Candidate,
        ClaimSource::Generated,
        0.3,
        true,
        false,
        target_record.dependencies.clone(),
        provenance,
    )
    .with_governance_tier(SkillGovernanceTier::Standard)
}

fn put_message(vault: &Vault, id: &EntityId) {
    // ONE-1686: MESSAGE bodies are gated witness envelopes; the citation
    // fixture only needs the row to exist, so it seeds canonical bytes through
    // the crate's test-only door.
    let body = crate::gate::canonical_witness_message_body_for_test(
        "user",
        "dialogue",
        "cited words",
        true,
        0,
    )
    .expect("canonical message body");
    vault
        .batch()
        .put_canonical_message_for_test(id, t(1), 1, &body)
        .commit()
        .expect("put message");
}

#[test]
fn a_candidate_citing_live_sources_activates_and_one_citing_a_deleted_source_does_not() -> Result<()>
{
    let (_tmp, vault) = temp_vault();
    let (skill, _) = put_standard_active(&vault, "oneiron.skill.cited");
    attribute_defects_across_split(&vault, &skill, "oneiron.skill.cited");

    let live = EntityId::now();
    put_message(&vault, &live);
    let doomed = EntityId::now();
    put_message(&vault, &doomed);

    let grounded = optimizer_proposal_citing(
        &vault,
        &skill,
        Value::Array(vec![Value::from(live.to_hex())]),
    );
    let ungrounded = optimizer_proposal_citing(
        &vault,
        &skill,
        Value::Array(vec![Value::from(doomed.to_hex())]),
    );

    let scorer = StubScorer::improving();
    set_skill_edit_cycle_cap(&vault, 4)?;
    for proposal in [grounded, ungrounded] {
        let verdict = score_gate_skill_edit_in_cycle(
            &vault,
            &proposal,
            &scorer,
            wake(&vault, "wake-1", 10),
            900,
        )?;
        assert_eq!(verdict.disposition, SkillEditDisposition::Accepted);
    }

    // The cited source is erased AFTER the gate passed. ONE-1447's sweep
    // deliberately steps past candidates, so the record carries no mark to
    // read — the admission door has to resolve the id itself.
    assert!(vault.delete_entity_with_options(
        &doomed,
        crate::deletion::DeleteEntityOptions { purge: true }
    )?);
    let target_before = stored(&vault, &skill);

    assert_eq!(
        admit_optimized_skill_revision(&vault, &ungrounded, t(400), 401)
            .expect_err("an ungrounded candidate never becomes canon")
            .kind(),
        ErrorKind::InvalidSkillBody
    );
    let refusal = skill_edit_verdict(&vault, &ungrounded)?.expect("a durable refusal");
    assert_eq!(refusal.disposition, SkillEditDisposition::RefusedSourceLoss);
    assert_eq!(refusal.missing_sources, vec![doomed]);
    let receipt = verdict_receipt(&vault, &refusal);
    assert_eq!(receipt.outcome, "refused_source_loss");
    assert_eq!(
        receipt.fields["skill_edit_missing_sources"],
        doomed.to_hex()
    );

    // ATOMIC: nothing moved — not the candidate, not the active record — and
    // the refusal closed the question it answered in that same transaction.
    assert_eq!(
        stored(&vault, &ungrounded).lifecycle_status,
        SkillLifecycle::Candidate
    );
    assert_eq!(
        stored(&vault, &ungrounded).approval_status,
        ClaimApprovalStatus::Rejected
    );
    assert_eq!(stored(&vault, &skill), target_before);

    // Its well-grounded sibling is unaffected.
    admit_optimized_skill_revision(&vault, &grounded, t(402), 403)?;
    assert_eq!(
        stored(&vault, &grounded).lifecycle_status,
        SkillLifecycle::Active
    );
    Ok(())
}

#[test]
fn a_present_but_malformed_source_linkage_is_refused() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let (skill, _) = put_standard_active(&vault, "oneiron.skill.cited");
    attribute_defects_across_split(&vault, &skill, "oneiron.skill.cited");

    // Present and unreadable is a typed failure, not an absent citation — and
    // it is refused EARLIER than this gate. ONE-1447's source index is
    // maintained at the same chokepoint every SKILL body converges on, and it
    // parses the linkage strictly, so a malformed citation never becomes a
    // stored record at all. That is the strongest possible answer to "malformed
    // present linkage is refused": there is no such candidate to admit.
    let target_before = stored(&vault, &skill);
    let id = EntityId::now();
    let malformed = optimizer_proposal_record_citing(
        &vault,
        &skill,
        Value::Array(vec![Value::from("not-an-entity-id")]),
        HAND_CRAFTED_CYCLE,
    );
    assert_eq!(
        vault
            .put_skill_record(&id, &malformed, t(300), 301)
            .expect_err("a malformed citation is not a missing one")
            .kind(),
        ErrorKind::InvalidSkillBody
    );
    assert!(
        vault.get_skill_record(&id)?.is_none(),
        "the refused body landed nowhere"
    );
    assert_eq!(stored(&vault, &skill), target_before);

    // The admission door keeps its own typed arm for the shape the write door
    // cannot see: a legacy body stored before that index maintenance existed.
    // Absence, by contrast, is not a fabricated citation and passes.
    let uncited = optimizer_proposal_citing(&vault, &skill, Value::Array(Vec::new()));
    let scorer = StubScorer::improving();
    score_gate_skill_edit_in_cycle(&vault, &uncited, &scorer, wake(&vault, "wake-1", 10), 900)?;
    admit_optimized_skill_revision(&vault, &uncited, t(400), 401)?;
    assert_eq!(
        stored(&vault, &uncited).lifecycle_status,
        SkillLifecycle::Active
    );
    Ok(())
}

// ─── ONE-1449: the shapes the gate refuses to rule on ───────────────────

#[test]
fn the_gate_refuses_a_moved_target_and_a_record_it_does_not_own() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let (skill, proposal) = losing_skill_with_proposal(&vault, "oneiron.skill.losing");

    // A user-authored candidate is not this job's business, and the ordinary
    // owner door still activates one — the landed path ONE-1448's fixtures use.
    let user_candidate = EntityId::now();
    put_active(
        &vault,
        &user_candidate,
        &record(
            "oneiron.skill.user",
            Some(SkillGovernanceTier::Standard),
            None,
        ),
    );
    assert_eq!(
        stored(&vault, &user_candidate).lifecycle_status,
        SkillLifecycle::Active
    );
    assert_eq!(
        score_gate_skill_edit_in_cycle(
            &vault,
            &user_candidate,
            &UnreachableScorer,
            wake(&vault, "wake-1", 10),
            900
        )
        .expect_err("this gate rules on optimizer-born proposals only")
        .kind(),
        ErrorKind::InvalidSkillBody
    );

    // The target is re-versioned by its owner while the proposal waits, so the
    // revision the proposal was drafted against no longer exists.
    let mut moved = stored(&vault, &skill);
    moved.desc = "The owner got there first.".to_owned();
    moved.version = "9.9.9".to_owned();
    vault.update_skill_record(&skill, &moved, t(500), 501)?;
    assert_eq!(
        score_gate_skill_edit_in_cycle(
            &vault,
            &proposal,
            &UnreachableScorer,
            wake(&vault, "wake-1", 10),
            901
        )
        .expect_err("a proposal against a revision that moved is dead on arrival")
        .kind(),
        ErrorKind::InvalidSkillBody
    );
    let verdict = skill_edit_verdict(&vault, &proposal)?.expect("a durable refusal");
    assert_eq!(
        verdict.disposition,
        SkillEditDisposition::RefusedStaleTarget
    );
    assert_eq!(
        verdict_receipt(&vault, &verdict).outcome,
        "refused_stale_target"
    );
    // The row and the closure commit together, so a refusal cannot wedge the
    // skill it refused out of the loop.
    assert_eq!(
        stored(&vault, &proposal).approval_status,
        ClaimApprovalStatus::Rejected
    );
    assert!(
        optimize_candidates(&vault)?
            .iter()
            .any(|candidate| candidate.skill == skill),
        "an answered proposal is no longer an open question"
    );
    Ok(())
}

#[test]
fn a_skill_with_no_reserved_evidence_is_never_drafted_for_and_never_closed() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let (skill, _) = put_standard_active(&vault, "oneiron.skill.losing");
    attribute_defects_across_split(&vault, &skill, "oneiron.skill.losing");
    let proposal = run(&vault, &StubAuthor::editing())?
        .proposal
        .expect("a proposal");

    // A DIFFERENT skill, losing on the DEV side by every measure the N dial and
    // the ranking read, and with NOTHING reserved: the split is an independent
    // draw, so this is an ordinary shape, not a corrupt one.
    let (bare, _) = put_standard_active(&vault, "oneiron.skill.bare");
    let mut dev_only = 0u32;
    for index in 0..80u64 {
        let at = 20_000 + index * 10;
        let actor = EntityId::now();
        put_actor(&vault, &actor);
        let receipt = stamped_receipt_version_as(
            &vault,
            "oneiron.skill.bare",
            FIXTURE_VERSION,
            at,
            Some(actor),
        );
        if receipt_is_held_out(&bare, &receipt) {
            continue;
        }
        record_attribution_evidence(
            &vault,
            &OutcomeEvidence::new(&receipt, actor, AttemptOutcome::Failed, at + 5)
                .with_skill(bare)
                .with_routing_facts(true, true),
        )?;
        let cursor = read_attribution_cursor(&vault)?;
        let judgments = run_attribution_projector(&vault, cursor)?;
        project_skill_reliability(&vault, &judgments)?;
        dev_only += 1;
        if dev_only > DEFAULT_SKILL_OPTIMIZE_MIN_OUTCOMES {
            break;
        }
    }
    assert!(
        dev_only > DEFAULT_SKILL_OPTIMIZE_MIN_OUTCOMES,
        "dev evidence"
    );
    assert!(held_out_receipts(&vault, &bare)?.is_empty());

    // SELECTION refuses it: the author is never paid to draft a proposal the
    // gate could not score. That is the whole repair — the old shape drafted,
    // then durably closed the fresh proposal as refused.
    assert!(
        optimize_candidates(&vault)?
            .iter()
            .all(|candidate| candidate.skill != bare),
        "a skill with an empty reserve is not a candidate"
    );

    // …and reached anyway — by a hand-crafted proposal, or by a race that
    // emptied the reserve — the gate ABORTS rather than answering. Nothing is
    // scored, nothing is written, and the question stays open for the wake that
    // finds a reserve.
    let bare_proposal = optimizer_proposal_citing(&vault, &bare, Value::Array(Vec::new()));
    let refused = score_gate_skill_edit_in_cycle(
        &vault,
        &bare_proposal,
        &UnreachableScorer,
        wake(&vault, "wake-1", 10),
        900,
    )
    .expect_err("no reserved evidence, no verdict");
    assert_eq!(refused.kind(), ErrorKind::SkillEditGateRetry);
    assert!(refused.is_retryable());
    assert!(
        skill_edit_verdicts_for_proposal(&vault, &bare_proposal)?.is_empty(),
        "an unscorable question is not an answered one, so it has no row"
    );
    let waiting = stored(&vault, &bare_proposal);
    assert_eq!(waiting.lifecycle_status, SkillLifecycle::Candidate);
    assert_eq!(
        waiting.approval_status,
        ClaimApprovalStatus::Proposed,
        "the proposal is left exactly as a call that never ran would leave it"
    );

    // The evidenced one is unaffected.
    let scorer = StubScorer::improving();
    assert!(
        score_gate_skill_edit_in_cycle(
            &vault,
            &proposal,
            &scorer,
            wake(&vault, "wake-1", 10),
            901
        )?
        .accepted
    );
    Ok(())
}

// ─── ONE-1449 MATERIAL-10 fixtures ──────────────────────────────────────

/// Credits contributing wins until one lands on the RESERVED side, and returns
/// it — the cheapest way to move the held-out set without touching the dev one.
/// Builds a valid pack receipt, then chooses a fresh fixture id in the requested
/// partition before inserting it through the existing receipt-fixture door.
/// A finite number of random draws cannot guarantee a held-out receipt: forty
/// independent misses still occur about once in 7,500 calls.
fn stamped_receipt_in_partition(
    vault: &Vault,
    skill: &EntityId,
    skill_id: &str,
    reserved: bool,
    at: u64,
    actor: Option<EntityId>,
) -> String {
    let template_id = stamped_receipt_version_as(vault, skill_id, FIXTURE_VERSION, at, actor);
    let mut receipt = crate::receipt::attempt_pack_receipt(vault, &template_id)
        .expect("read pack receipt")
        .expect("stamped pack receipt");
    let receipt_id = (0..=u64::MAX)
        .map(|nonce| format!("attempt:{at:016x}{nonce:016x}"))
        .find(|id| {
            receipt_is_held_out(skill, id) == reserved
                && crate::receipt::attempt_pack_receipt(vault, id)
                    .expect("check fixture receipt")
                    .is_none()
        })
        .expect("fixture id space contains a fresh receipt in each partition");
    receipt.receipt_id.clone_from(&receipt_id);
    crate::receipt::overwrite_attempt_pack_receipt_for_test(vault, &receipt)
        .expect("seed partitioned pack receipt");
    if let Some(actor) = actor {
        vault
            .with_write_txn(|txn| {
                crate::skill::resident::bind_receipt_in_txn(vault, txn, &receipt_id, &actor)
            })
            .expect("bind synthetic fixture's executor");
    }
    receipt_id
}

fn reserve_one_more_held_out_receipt(
    vault: &Vault,
    skill: &EntityId,
    skill_id: &str,
    at: u64,
) -> String {
    let receipt = stamped_receipt_in_partition(vault, skill, skill_id, true, at, None);
    record_skill_contributing_win(vault, skill, &receipt, at + 5).expect("credit win");
    receipt
}

fn provenance_entry(record: &SkillRecord, key: &str) -> Option<String> {
    let Value::Map(entries) = &record.provenance else {
        return None;
    };
    entries
        .iter()
        .find(|(entry, _)| entry.as_str() == Some(key))
        .and_then(|(_, value)| value.as_str())
        .map(str::to_owned)
}

fn without_provenance(record: &SkillRecord, key: &str) -> Value {
    let Value::Map(entries) = &record.provenance else {
        panic!("a proposal's provenance is a map");
    };
    Value::Map(
        entries
            .iter()
            .filter(|(entry, _)| entry.as_str() != Some(key))
            .cloned()
            .collect(),
    )
}

fn with_provenance(record: &SkillRecord, key: &str, value: &str) -> Value {
    let Value::Map(entries) = &record.provenance else {
        panic!("a proposal's provenance is a map");
    };
    Value::Map(
        entries
            .iter()
            .map(|(entry, held)| {
                if entry.as_str() == Some(key) {
                    (entry.clone(), Value::from(value))
                } else {
                    (entry.clone(), held.clone())
                }
            })
            .collect(),
    )
}

/// Prunes a queue row, as a retention sweep eventually does.
fn prune_attempt_row(vault: &Vault, attempt: AttemptId) {
    vault
        .with_write_txn(|wtxn| {
            vault
                .store
                .attempt_records
                .delete(wtxn, attempt.as_bytes())?;
            Ok(())
        })
        .expect("prune the queue row");
}

/// A judge that lets a new RESERVED outcome land while it is thinking — the
/// exact window between "the gate read the reserve" and "the gate wrote a row".
struct RacingScorer<'a> {
    vault: &'a Vault,
    skill: EntityId,
    skill_id: &'a str,
    raced: RefCell<bool>,
    /// How many replays this judge was actually paid for, so "the aborted call
    /// spent exactly the pair it had already scored" is checkable.
    scored: RefCell<u32>,
}

impl HeldOutReplayScorer for RacingScorer<'_> {
    fn judge_revision(&self) -> &str {
        "fixture-judge@1"
    }
    fn score(&self, case: &HeldOutReplayCase<'_>) -> Result<f32> {
        *self.scored.borrow_mut() += 1;
        if !self.raced.replace(true) {
            reserve_one_more_held_out_receipt(self.vault, &self.skill, self.skill_id, 6_000);
        }
        Ok(if case.instructions == TARGET_DESC {
            0.40
        } else {
            0.75
        })
    }
    fn structural_audit(&self, _task: &str, _instructions: &str) -> Result<f32> {
        Ok(0.5)
    }
    fn blind_preference(&self, _task: &str, _receipts: &[String]) -> Result<Vec<BlindPreference>> {
        Ok(vec![BlindPreference {
            pair_ref: "fixture-pair".to_owned(),
            preferred: PreferredResponse::First,
        }])
    }
    fn contrastive_audit(
        &self,
        _case: &HeldOutReplayCase<'_>,
        _blind: &[BlindPreference],
    ) -> Result<f32> {
        Ok(0.5)
    }
    fn predict_task_success(&self, case: &HeldOutReplayCase<'_>) -> Result<Vec<f32>> {
        Ok(vec![0.5; case.held_out_receipts.len()])
    }
}

/// A judge that DELIVERS THE SAME GATE CALL AGAIN while it is thinking.
///
/// The deterministic stand-in for two deliveries racing the write door: the
/// inner delivery runs to completion (and writes its row) after the outer one
/// took its snapshot and before the outer one reaches its own write
/// transaction. That is precisely the interleaving that used to append a second
/// row — and no sleeping thread is involved, so it is a regression rather than
/// a coin flip.
struct DuplicatingScorer<'a> {
    vault: &'a Vault,
    proposal: EntityId,
    attempt: AttemptId,
    delivered: RefCell<bool>,
    scored: RefCell<u32>,
}

impl HeldOutReplayScorer for DuplicatingScorer<'_> {
    fn judge_revision(&self) -> &str {
        "fixture-judge@1"
    }
    fn score(&self, case: &HeldOutReplayCase<'_>) -> Result<f32> {
        *self.scored.borrow_mut() += 1;
        if !self.delivered.replace(true) {
            let inner = StubScorer::improving();
            score_gate_skill_edit_in_cycle(self.vault, &self.proposal, &inner, self.attempt, 950)
                .expect("the inner delivery rules");
        }
        Ok(if case.instructions == TARGET_DESC {
            0.40
        } else {
            0.75
        })
    }
    fn structural_audit(&self, _task: &str, _instructions: &str) -> Result<f32> {
        Ok(0.5)
    }
    fn blind_preference(&self, _task: &str, _receipts: &[String]) -> Result<Vec<BlindPreference>> {
        Ok(vec![BlindPreference {
            pair_ref: "fixture-pair".to_owned(),
            preferred: PreferredResponse::First,
        }])
    }
    fn contrastive_audit(
        &self,
        _case: &HeldOutReplayCase<'_>,
        _blind: &[BlindPreference],
    ) -> Result<f32> {
        Ok(0.5)
    }
    fn predict_task_success(&self, case: &HeldOutReplayCase<'_>) -> Result<Vec<f32>> {
        Ok(vec![0.5; case.held_out_receipts.len()])
    }
}

// ─── ONE-1449 M1: an acceptance is about a body, not about an id ────────

#[test]
fn an_acceptance_binds_the_body_the_predecessor_and_the_evidence_it_scored() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let (skill, proposal) = losing_skill_with_proposal(&vault, "oneiron.skill.losing");
    let reserved = held_out_receipts(&vault, &skill)?;
    let scorer = StubScorer::improving();
    let accepted = score_gate_skill_edit_in_cycle(
        &vault,
        &proposal,
        &scorer,
        wake(&vault, "wake-1", 10),
        900,
    )?;
    assert_eq!(accepted.disposition, SkillEditDisposition::Accepted);

    // The ruling names what it ruled over: both bodies, and the exact reserve.
    // Recomputed from the outside, because a binding only this module can check
    // is not an audit trail.
    assert_eq!(
        accepted.proposal_digest,
        skill_body_binding_digest(&stored(&vault, &proposal))?
    );
    assert_eq!(
        accepted.target_digest,
        skill_body_binding_digest(&stored(&vault, &skill))?
    );
    assert_eq!(
        accepted.held_out_digest,
        held_out_receipt_set_digest(&reserved)
    );

    // The body under the acceptance is edited through the ordinary candidate
    // door. That update is lawful on its own terms — and it is a different
    // record from the one the judge was shown.
    let mut swapped = stored(&vault, &proposal);
    swapped.desc = "Instructions nobody ever replayed.".to_owned();
    swapped.version = "opt-swapped".to_owned();
    vault.update_skill_record(&proposal, &swapped, t(400), 401)?;

    let target_before = stored(&vault, &skill);
    assert_eq!(
        admit_optimized_skill_revision(&vault, &proposal, t(402), 403)
            .expect_err("unscored content never rides an old acceptance into canon")
            .kind(),
        ErrorKind::InvalidSkillBody
    );
    let refusal = skill_edit_verdict(&vault, &proposal)?.expect("a durable refusal");
    assert_eq!(
        refusal.disposition,
        SkillEditDisposition::RefusedBindingMismatch
    );
    assert_eq!(refusal.accepted_verdict, Some(accepted.id));
    assert_eq!(
        verdict_receipt(&vault, &refusal).outcome,
        "refused_binding_mismatch"
    );

    // ATOMIC: active canon untouched, and the answered proposal is closed.
    assert_eq!(stored(&vault, &skill), target_before);
    let answered = stored(&vault, &proposal);
    assert_eq!(answered.lifecycle_status, SkillLifecycle::Candidate);
    assert_eq!(answered.approval_status, ClaimApprovalStatus::Rejected);
    Ok(())
}

#[test]
fn evidence_that_arrives_after_the_ruling_is_not_evidence_the_ruling_rests_on() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let (skill, proposal) = losing_skill_with_proposal(&vault, "oneiron.skill.losing");
    let scorer = StubScorer::improving();
    let accepted = score_gate_skill_edit_in_cycle(
        &vault,
        &proposal,
        &scorer,
        wake(&vault, "wake-1", 10),
        900,
    )?;
    assert!(accepted.accepted);

    // One more RESERVED outcome lands between the ruling and the door.
    let arrived = reserve_one_more_held_out_receipt(&vault, &skill, "oneiron.skill.losing", 5_000);
    assert!(held_out_receipts(&vault, &skill)?.contains(&arrived));

    let target_before = stored(&vault, &skill);
    assert_eq!(
        admit_optimized_skill_revision(&vault, &proposal, t(400), 401)
            .expect_err("the reserve that judged it is not the reserve that stands")
            .kind(),
        ErrorKind::InvalidSkillBody
    );
    let refusal = skill_edit_verdict(&vault, &proposal)?.expect("a durable refusal");
    assert_eq!(
        refusal.disposition,
        SkillEditDisposition::RefusedBindingMismatch
    );
    // The refusal carries the acceptance's numbers, not a zero pair.
    assert_eq!(
        (refusal.before, refusal.after),
        (accepted.before, accepted.after)
    );
    assert_eq!(refusal.held_out_digest, accepted.held_out_digest);
    assert_eq!(refusal.accepted_verdict, Some(accepted.id));
    assert_eq!(stored(&vault, &skill), target_before);
    Ok(())
}

// ─── ONE-1449 M2: optimizer birth is not a field ────────────────────────

#[test]
fn optimizer_origin_cannot_be_stripped_and_the_bare_flip_stays_refused() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let (_, proposal) = losing_skill_with_proposal(&vault, "oneiron.skill.losing");
    let born = stored(&vault, &proposal);
    assert_eq!(
        provenance_entry(&born, PROVENANCE_BIRTH_KEY).as_deref(),
        Some(SKILL_OPTIMIZE_BIRTH_PATH)
    );

    // Every edit that would make the record stop being what it is, each one a
    // lawful content revision but for the origin it moves.
    let mut stripped = born.clone();
    stripped.provenance = without_provenance(&born, PROVENANCE_BIRTH_KEY);
    stripped.desc = "Rewritten with no birth path at all.".to_owned();
    stripped.version = "opt-stripped".to_owned();
    let mut retargeted = born.clone();
    retargeted.provenance = with_provenance(
        &born,
        PROVENANCE_OPTIMIZE_OF_ENTITY_KEY,
        &EntityId::now().to_hex(),
    );
    retargeted.version = "opt-retargeted".to_owned();
    let mut relabelled = born.clone();
    relabelled.provenance =
        with_provenance(&born, PROVENANCE_OPTIMIZE_CYCLE_KEY, "run:somebody-elses");
    relabelled.version = "opt-relabelled".to_owned();
    for (index, attempt) in [stripped, retargeted, relabelled].into_iter().enumerate() {
        let at = 400 + u64::try_from(index).expect("index") * 2;
        assert_eq!(
            vault
                .update_skill_record(&proposal, &attempt, t(at), at + 1)
                .expect_err("origin is a birth fact, not a field")
                .kind(),
            ErrorKind::InvalidSkillBody
        );
    }
    assert_eq!(stored(&vault, &proposal), born, "nothing landed");

    // So the two-write bypass has no first write; and the second write — the
    // bare flip — is refused on its own account, as it always was.
    let mut flipped = born.clone();
    flipped.approval_status = ClaimApprovalStatus::Approved;
    flipped.lifecycle_status = SkillLifecycle::Active;
    assert_eq!(
        vault
            .update_skill_record(&proposal, &flipped, t(410), 411)
            .expect_err("an optimizer-born candidate never flips its way to canon")
            .kind(),
        ErrorKind::InvalidSkillBody
    );
    assert_eq!(stored(&vault, &proposal), born);

    // A record born on another road cannot adopt the optimizer's either.
    let owner_skill = EntityId::now();
    put_active(
        &vault,
        &owner_skill,
        &record(
            "oneiron.skill.owned",
            Some(SkillGovernanceTier::Identity),
            None,
        ),
    );
    let owned = stored(&vault, &owner_skill);
    let mut claiming = owned.clone();
    claiming.provenance = Value::Map(vec![(
        Value::from(PROVENANCE_BIRTH_KEY),
        Value::from(SKILL_OPTIMIZE_BIRTH_PATH),
    )]);
    claiming.version = "2.0.0".to_owned();
    assert_eq!(
        vault
            .update_skill_record(&owner_skill, &claiming, t(412), 413)
            .expect_err("a birth path is not something an existing record may adopt")
            .kind(),
        ErrorKind::InvalidSkillBody
    );

    // And the owner's ordinary door over their own protected record is exactly
    // as open as it was: this is a dial on the robot.
    let mut owner_edit = owned;
    owner_edit.desc = "The owner rewrote this by hand.".to_owned();
    owner_edit.version = "3.0.0".to_owned();
    vault.update_skill_record(&owner_skill, &owner_edit, t(414), 415)?;
    let after = stored(&vault, &owner_skill);
    assert_eq!(after.desc, "The owner rewrote this by hand.");
    assert_eq!(after.governance_tier, Some(SkillGovernanceTier::Identity));
    assert_eq!(after.lifecycle_status, SkillLifecycle::Active);
    Ok(())
}

// ─── ONE-1449 M3/R6: the reserve is recomputed where the row commits ────

#[test]
fn evidence_arriving_mid_flight_aborts_retryably_and_writes_nothing() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let (skill, proposal) = losing_skill_with_proposal(&vault, "oneiron.skill.losing");
    let scored_over = held_out_receipts(&vault, &skill)?;
    // K = 1 and a sibling proposal, so "no slot was spent" is a claim this test
    // can actually check rather than assume.
    set_skill_edit_cycle_cap(&vault, 1)?;
    let (_, sibling) = losing_skill_with_proposal(&vault, "oneiron.skill.sibling");

    let racing = RacingScorer {
        vault: &vault,
        skill,
        skill_id: "oneiron.skill.losing",
        raced: RefCell::new(false),
        scored: RefCell::new(0),
    };
    let raced =
        score_gate_skill_edit_in_cycle(&vault, &proposal, &racing, wake(&vault, "wake-1", 10), 900)
            .expect_err("a snapshot that moved is not a ruling");
    assert_eq!(
        raced.kind(),
        ErrorKind::SkillEditGateRetry,
        "the scheduler must be able to tell 'retry me' from 'answered no'"
    );
    assert!(raced.is_retryable());
    assert_ne!(
        held_out_receipts(&vault, &skill)?,
        scored_over,
        "the ledger really did move under the judge"
    );

    // NOTHING was committed: no verdict row, no closure, no cap spend. The
    // proposal is exactly as a call that never ran would have left it.
    assert!(
        skill_edit_verdicts_for_proposal(&vault, &proposal)?.is_empty(),
        "a race is not a ruling, so it has no row"
    );
    let waiting = stored(&vault, &proposal);
    assert_eq!(waiting.lifecycle_status, SkillLifecycle::Candidate);
    assert_eq!(waiting.approval_status, ClaimApprovalStatus::Proposed);
    assert_eq!(
        admit_optimized_skill_revision(&vault, &proposal, t(400), 401)
            .expect_err("an aborted call is not an acceptance")
            .kind(),
        ErrorKind::InvalidSkillBody
    );
    assert_eq!(
        *racing.scored.borrow(),
        2,
        "the aborted call paid for exactly the one pair it had already scored"
    );

    // The one open disposition is the cap deferral, and nothing else.
    assert!(SkillEditDisposition::DeferredCycleCap.leaves_proposal_open());
    for disposition in [
        SkillEditDisposition::Accepted,
        SkillEditDisposition::Rejected,
        SkillEditDisposition::RefusedProtectedTier,
        SkillEditDisposition::RefusedStaleTarget,
        SkillEditDisposition::RefusedSourceLoss,
        SkillEditDisposition::RefusedSourceMalformed,
        SkillEditDisposition::RefusedBindingMismatch,
    ] {
        assert!(
            !disposition.leaves_proposal_open(),
            "{} is not an open question",
            disposition.as_str()
        );
    }

    // The unspent slot is still there for the sibling to take.
    let sibling_scorer = StubScorer::improving();
    assert_eq!(
        score_gate_skill_edit_in_cycle(
            &vault,
            &sibling,
            &sibling_scorer,
            wake(&vault, "wake-1", 10),
            901
        )?
        .disposition,
        SkillEditDisposition::Accepted,
        "the aborted call spent no cap slot"
    );

    // The rerun, over a ledger that is standing still, rules properly on the
    // RECOMPUTED basis and binds the reserve it actually saw. K = 1 is spent by
    // the sibling now, so the deterministic answer here is the cap deferral.
    let settled = StubScorer::improving();
    let deferred = score_gate_skill_edit_in_cycle(
        &vault,
        &proposal,
        &settled,
        wake(&vault, "wake-1", 10),
        902,
    )?;
    assert_eq!(deferred.disposition, SkillEditDisposition::DeferredCycleCap);
    assert_eq!(
        settled.evidence().len(),
        2,
        "the retry re-scores on the fresh snapshot rather than reusing the stale pair"
    );
    assert_eq!(
        deferred.held_out_digest,
        held_out_receipt_set_digest(&held_out_receipts(&vault, &skill)?)
    );

    // And a wake with a budget of its own takes it to canon.
    let next = StubScorer::improving();
    let accepted =
        score_gate_skill_edit_in_cycle(&vault, &proposal, &next, wake(&vault, "wake-2", 20), 903)?;
    assert_eq!(accepted.disposition, SkillEditDisposition::Accepted);
    admit_optimized_skill_revision(&vault, &proposal, t(402), 403)?;
    assert_eq!(
        stored(&vault, &proposal).lifecycle_status,
        SkillLifecycle::Active
    );
    Ok(())
}

#[test]
fn a_terminal_reason_that_stops_holding_aborts_instead_of_refusing() -> Result<()> {
    let (tmp, vault) = temp_vault();
    // Leaked so the race hook — a `'static` thread-local, because the gate that
    // fires it holds no test state — can reach this exact vault. The temp dir
    // is leaked with it: the handle keeps its root registered as open, so
    // deleting the files would free their inodes for a later test's vault and
    // fail that open with DuplicateOpenRoot.
    let _tmp: &'static tempfile::TempDir = Box::leak(Box::new(tmp));
    let vault: &'static Vault = Box::leak(Box::new(vault));
    let (skill, _) = put_standard_active(vault, "oneiron.skill.losing");
    attribute_defects_across_split(vault, &skill, "oneiron.skill.losing");
    let proposal = optimizer_proposal_citing(vault, &skill, Value::Array(Vec::new()));

    // The predecessor is absent when the lock-free pre-read runs, so the reason
    // that read forms is a terminal stale-target refusal. Use internal batch
    // removal rather than an owner hard delete: that permanent marker would
    // correctly forbid the later recreate, obscuring this transaction race.
    vault.batch().delete(&skill).commit()?;
    assert!(
        vault.get_skill_record(&skill)?.is_none(),
        "the target is absent"
    );

    // The window the repair closed: the reason was read BEFORE the transaction
    // that would have written it, and the world moved in between — here the
    // revision comes back, active and byte-identical to the one this proposal
    // was drafted against. The old shape wrote the refusal anyway: a terminal
    // answer about a world that no longer existed, which also closed the
    // proposal.
    let restored = record(
        "oneiron.skill.losing",
        Some(SkillGovernanceTier::Standard),
        None,
    );
    gate::set_pre_score_race_hook(Box::new(move || {
        put_active(vault, &skill, &restored);
    }));
    let raced = score_gate_skill_edit_in_cycle(
        vault,
        &proposal,
        &UnreachableScorer,
        wake(vault, "wake-1", 10),
        900,
    )
    .expect_err("a reason that stopped holding is not a refusal");
    gate::clear_pre_score_race_hook();
    assert_eq!(raced.kind(), ErrorKind::SkillEditGateRetry);
    assert!(
        skill_edit_verdicts_for_proposal(vault, &proposal)?.is_empty(),
        "no false terminal refusal was written"
    );
    let waiting = stored(vault, &proposal);
    assert_eq!(waiting.lifecycle_status, SkillLifecycle::Candidate);
    assert_eq!(
        waiting.approval_status,
        ClaimApprovalStatus::Proposed,
        "and the proposal was not closed by an answer nobody gave"
    );

    // Over the settled ledger the same call rules normally.
    let scorer = StubScorer::improving();
    let verdict =
        score_gate_skill_edit_in_cycle(vault, &proposal, &scorer, wake(vault, "wake-1", 10), 901)?;
    assert_eq!(verdict.disposition, SkillEditDisposition::Accepted);
    Ok(())
}

// ─── ONE-1449 M5: the cycle is a birth fact ─────────────────────────────

#[test]
fn the_drafting_cycle_is_stamped_at_birth_and_outlives_the_queue_row() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let (alpha, _) = put_standard_active(&vault, "oneiron.skill.alpha");
    attribute_defects_across_split(&vault, &alpha, "oneiron.skill.alpha");
    let (beta, _) = put_standard_active(&vault, "oneiron.skill.beta");
    attribute_defects_across_split(&vault, &beta, "oneiron.skill.beta");

    // Two attempts, one wake.
    let first_attempt = enqueue_attempt(&vault, Some("wake-42"), 10);
    let second_attempt = enqueue_attempt(&vault, Some("wake-42"), 20);
    let first = run_skill_optimize(&vault, first_attempt, &StubAuthor::editing(), t(300), 301)?
        .proposal
        .expect("the first draft");
    let second = run_skill_optimize(&vault, second_attempt, &StubAuthor::editing(), t(302), 303)?
        .proposal
        .expect("the second draft");
    assert_ne!(first, second);

    for proposal in [first, second] {
        assert_eq!(
            provenance_entry(&stored(&vault, &proposal), PROVENANCE_OPTIMIZE_CYCLE_KEY).as_deref(),
            Some("run:wake-42"),
            "the RUN, not the attempt: one wake counts against one cap"
        );
        assert_eq!(
            SkillEditCycle::of_proposal(&vault, &proposal)?.as_str(),
            "run:wake-42"
        );
    }

    // The queue rows are pruned, as a retention sweep eventually prunes them.
    // The label is on the proposal, so it does not move.
    prune_attempt_row(&vault, first_attempt);
    prune_attempt_row(&vault, second_attempt);
    assert_eq!(
        SkillEditCycle::of_proposal(&vault, &first)?.as_str(),
        "run:wake-42"
    );

    // And the cap they share is still one cap.
    set_skill_edit_cycle_cap(&vault, 1)?;
    let scorer = StubScorer::improving();
    assert_eq!(
        score_gate_skill_edit_with_scorer(&vault, &first, &scorer)?.disposition,
        SkillEditDisposition::Accepted
    );
    assert_eq!(
        score_gate_skill_edit_with_scorer(&vault, &second, &scorer)?.disposition,
        SkillEditDisposition::DeferredCycleCap,
        "two proposals from one run share one budget"
    );

    // A proposal carrying no stamp at all fails CLOSED at BOTH doors, and no
    // caller-named wake rescues it. An explicit label used to: the caller said
    // "wake-43", the gate believed it, and an unstamped proposal bought a slot
    // in a cycle it could not show it belonged to. The stamp is the proof, so
    // its absence is the answer.
    let unstamped = unstamped_optimizer_proposal(&vault, &beta);
    assert!(provenance_entry(&stored(&vault, &unstamped), PROVENANCE_OPTIMIZE_CYCLE_KEY).is_none());
    assert_eq!(
        SkillEditCycle::of_proposal(&vault, &unstamped)
            .expect_err("no stamp, no cycle")
            .kind(),
        ErrorKind::InvalidSkillBody
    );
    assert_eq!(
        score_gate_skill_edit_with_scorer(&vault, &unstamped, &UnreachableScorer)
            .expect_err("and no ruling either")
            .kind(),
        ErrorKind::InvalidSkillBody
    );
    assert_eq!(
        score_gate_skill_edit_in_cycle(
            &vault,
            &unstamped,
            &UnreachableScorer,
            wake(&vault, "wake-43", 30),
            900
        )
        .expect_err("naming a real wake does not stamp a birth that never happened")
        .kind(),
        ErrorKind::InvalidSkillBody
    );
    assert!(
        skill_edit_verdicts_for_proposal(&vault, &unstamped)?.is_empty(),
        "refusing to RULE is not the same as ruling: an unstamped proposal gets no row"
    );
    assert_eq!(
        admit_optimized_skill_revision(&vault, &unstamped, t(400), 401)
            .expect_err("and it is never admitted")
            .kind(),
        ErrorKind::InvalidSkillBody
    );

    // A cycle nothing durable proves is not a cycle either: the door takes an
    // attempt id, and a pruned attempt names no wake. (A free-form label is
    // unrepresentable — `SkillEditCycle` has no public constructor.)
    let pruned = enqueue_attempt(&vault, Some("wake-44"), 40);
    prune_attempt_row(&vault, pruned);
    assert_eq!(
        score_gate_skill_edit_in_cycle(&vault, &second, &UnreachableScorer, pruned, 901)
            .expect_err("no stored attempt row, no provable cycle")
            .kind(),
        ErrorKind::InvalidSkillBody
    );

    // The later-cycle pickup, under a wake that CAN be proven: the cap-deferred
    // proposal is re-scored and counted against the cycle that picked it up.
    let promoted =
        score_gate_skill_edit_in_cycle(&vault, &second, &scorer, wake(&vault, "wake-45", 50), 902)?;
    assert_eq!(promoted.disposition, SkillEditDisposition::Accepted);
    assert_eq!(
        promoted.cycle, "run:wake-45",
        "the row records the cycle actually used, not the birth stamp"
    );
    assert_eq!(
        provenance_entry(&stored(&vault, &second), PROVENANCE_OPTIMIZE_CYCLE_KEY).as_deref(),
        Some("run:wake-42"),
        "and the immutable birth stamp is untouched by the pickup"
    );
    Ok(())
}

#[test]
fn a_draft_whose_attempt_row_is_gone_is_never_born_into_a_private_cycle() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let (skill, _) = put_standard_active(&vault, "oneiron.skill.losing");
    attribute_defects_across_split(&vault, &skill, "oneiron.skill.losing");

    // The queue row is pruned between the enqueue and the draft, exactly as a
    // retention sweep eventually prunes it. The old shape read the absence as
    // "this attempt names no run" and handed the proposal a private cap.
    let attempt = enqueue_attempt(&vault, Some("wake-1"), 10);
    prune_attempt_row(&vault, attempt);
    assert_eq!(
        run_skill_optimize(&vault, attempt, &StubAuthor::editing(), t(300), 301)
            .expect_err("an unprovable cycle is not a cycle")
            .kind(),
        ErrorKind::InvalidSkillBody
    );
    assert!(
        optimize_candidates(&vault)?
            .iter()
            .any(|candidate| candidate.skill == skill),
        "nothing was drafted, so the skill still has no open question"
    );

    // An attempt id that was never enqueued at all is the same answer.
    assert_eq!(
        run_skill_optimize(
            &vault,
            AttemptId::now(),
            &StubAuthor::editing(),
            t(302),
            303
        )
        .expect_err("an attempt nobody scheduled proves nothing")
        .kind(),
        ErrorKind::InvalidSkillBody
    );
    Ok(())
}

// ─── ONE-1449 M6: delivery is idempotent ────────────────────────────────

#[test]
fn a_repeated_cap_deferral_returns_the_standing_row_and_re_scores_nothing() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    set_skill_edit_cycle_cap(&vault, 1)?;
    let (_, first) = losing_skill_with_proposal(&vault, "oneiron.skill.first");
    let (_, second) = losing_skill_with_proposal(&vault, "oneiron.skill.second");
    let scorer = StubScorer::improving();
    let wake_one = wake(&vault, "wake-1", 10);

    // The one slot is spent, so the sibling's PASSING proposal is deferred.
    assert_eq!(
        score_gate_skill_edit_in_cycle(&vault, &first, &scorer, wake_one, 900)?.disposition,
        SkillEditDisposition::Accepted
    );
    let deferred = score_gate_skill_edit_in_cycle(&vault, &second, &scorer, wake_one, 901)?;
    assert_eq!(deferred.disposition, SkillEditDisposition::DeferredCycleCap);
    let replays = scorer.evidence().len();

    // The redelivery — same proposal, same basis, same cycle, cap still full.
    // A deferral is a RULING already made, so it is returned rather than
    // re-earned: no second replay is paid and no second row is appended. The
    // acceptance arm has always been idempotent; this is the other half.
    let again = score_gate_skill_edit_in_cycle(&vault, &second, &scorer, wake_one, 902)?;
    assert_eq!(
        again, deferred,
        "the standing deferral itself, not a new one"
    );
    assert_eq!(
        scorer.evidence().len(),
        replays,
        "a duplicate delivery asks the judge nothing"
    );
    assert_eq!(
        skill_edit_verdicts_for_proposal(&vault, &second)?.len(),
        1,
        "exactly one deferral row exists"
    );
    // Still open, and still not admissible: idempotence changes no state.
    let waiting = stored(&vault, &second);
    assert_eq!(waiting.lifecycle_status, SkillLifecycle::Candidate);
    assert_eq!(waiting.approval_status, ClaimApprovalStatus::Proposed);

    // The CONCURRENT duplicate: a second delivery that got past the pre-score
    // read before the first wrote anything still finds the row at the write
    // door. Simulated deterministically by delivering from inside the scorer —
    // the same interleaving two threads would produce, with no sleeping.
    let (_, third) = losing_skill_with_proposal(&vault, "oneiron.skill.third");
    let racing = DuplicatingScorer {
        vault: &vault,
        proposal: third,
        attempt: wake_one,
        delivered: RefCell::new(false),
        scored: RefCell::new(0),
    };
    let outer = score_gate_skill_edit_in_cycle(&vault, &third, &racing, wake_one, 903)?;
    assert_eq!(outer.disposition, SkillEditDisposition::DeferredCycleCap);
    assert_eq!(
        *racing.scored.borrow(),
        2,
        "the losing delivery paid for its own pair and then stopped"
    );
    assert_eq!(
        skill_edit_verdicts_for_proposal(&vault, &third)?.len(),
        1,
        "two deliveries racing the write door produce ONE deferral row"
    );
    assert_eq!(
        outer,
        skill_edit_verdict(&vault, &third)?.expect("the standing deferral"),
        "the loser of the race returns the winner's row rather than writing its own"
    );

    // A later, PROVABLE cycle is not suppressed by any of it: it re-scores and
    // is counted against the wake that picked the proposal up.
    let next = StubScorer::improving();
    let promoted =
        score_gate_skill_edit_in_cycle(&vault, &second, &next, wake(&vault, "wake-2", 20), 904)?;
    assert_eq!(promoted.disposition, SkillEditDisposition::Accepted);
    assert_eq!(promoted.cycle, "run:wake-2");
    assert_eq!(
        next.evidence().len(),
        2,
        "a genuine later-cycle pickup does ask the judge again"
    );
    Ok(())
}

// ─── ONE-1449 M7: the author is a dev-view-only consumer ────────────────

#[test]
fn selection_and_the_brief_are_derived_from_the_dev_partition_only() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let (skill, _) = put_standard_active(&vault, "oneiron.skill.losing");
    attribute_defects_across_split(&vault, &skill, "oneiron.skill.losing");
    let dev = dev_receipts(&vault, &skill)?;
    let reserved = held_out_receipts(&vault, &skill)?;
    assert!(!dev.is_empty() && !reserved.is_empty());

    let candidate = optimize_candidates(&vault)?
        .into_iter()
        .next()
        .expect("a losing skill");
    assert_eq!(
        usize::try_from(candidate.attributed_outcomes).expect("count"),
        dev.len()
    );
    // The posterior is the prior folded with the DEV losses and nothing else.
    let mut expected = candidate.prior;
    for _ in &dev {
        expected.apply(false);
    }
    assert_eq!(candidate.posterior, expected);
    // The whole-ledger posterior is a heavier, different number — the one the
    // ranking used to read, and the one a held-out outcome moves.
    let whole =
        crate::skill_reliability::skill_reliability_posterior(&vault, &skill)?.expect("projected");
    assert!(whole.observations() > candidate.posterior.observations());

    // LEAKAGE NEGATIVE: a new RESERVED outcome moves nothing the selector or
    // the author can see.
    let first = reserve_one_more_held_out_receipt(&vault, &skill, "oneiron.skill.losing", 5_000);
    let second = reserve_one_more_held_out_receipt(&vault, &skill, "oneiron.skill.losing", 5_000);
    let extended_reserve = held_out_receipts(&vault, &skill)?;
    assert_ne!(first, second);
    assert!(extended_reserve.contains(&first) && extended_reserve.contains(&second));
    assert_eq!(extended_reserve.len(), reserved.len() + 2);
    let unmoved = optimize_candidates(&vault)?
        .into_iter()
        .next()
        .expect("still losing");
    assert_eq!(unmoved.posterior, candidate.posterior);
    assert_eq!(unmoved.attributed_outcomes, candidate.attributed_outcomes);

    // …while a DEV outcome does, which is what makes the negative meaningful.
    attribute_defects(&vault, &skill, "oneiron.skill.losing", 1);
    let moved = optimize_candidates(&vault)?
        .into_iter()
        .next()
        .expect("still losing");
    assert_eq!(
        moved.attributed_outcomes,
        candidate.attributed_outcomes + 1,
        "the dev side is the side that counts"
    );

    // The brief the author is handed carries the dev reading, receipts and
    // aggregates alike.
    let author = StubAuthor::editing();
    run(&vault, &author)?;
    let brief = author.brief();
    let dev_now = dev_receipts(&vault, &skill)?;
    let reserved_now = held_out_receipts(&vault, &skill)?;
    assert_eq!(brief.posterior, moved.posterior);
    assert_eq!(
        usize::try_from(brief.attributed_outcomes).expect("count"),
        dev_now.len()
    );
    assert!(
        brief
            .cited_receipts
            .iter()
            .all(|receipt| !reserved_now.contains(receipt))
    );
    assert!(
        brief
            .defect_receipts
            .iter()
            .all(|receipt| !reserved_now.contains(receipt))
    );
    Ok(())
}

// ─── ONE-1449 M9: a refusal reports what it refuses ─────────────────────

#[test]
fn a_post_score_refusal_keeps_the_pair_and_the_basis_it_refuses() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let (skill, proposal) = losing_skill_with_proposal(&vault, "oneiron.skill.losing");
    let scorer = StubScorer::improving();
    let accepted = score_gate_skill_edit_in_cycle(
        &vault,
        &proposal,
        &scorer,
        wake(&vault, "wake-1", 10),
        900,
    )?;
    assert!(accepted.improvement() > 0.0);

    // The owner marks the target protected between the ruling and the door.
    let mut marked = stored(&vault, &skill);
    marked.governance_tier = Some(SkillGovernanceTier::Identity);
    vault.update_skill_record(&skill, &marked, t(400), 401)?;

    assert_eq!(
        admit_optimized_skill_revision(&vault, &proposal, t(402), 403)
            .expect_err("the owner's newer ruling wins")
            .kind(),
        ErrorKind::InvalidSkillBody
    );
    let refusal = skill_edit_verdict(&vault, &proposal)?.expect("a durable refusal");
    assert_eq!(
        refusal.disposition,
        SkillEditDisposition::RefusedProtectedTier
    );
    assert_ne!(refusal.id, accepted.id);
    assert_eq!(
        (refusal.before, refusal.after),
        (accepted.before, accepted.after)
    );
    assert!(
        refusal.improvement() > 0.0,
        "refused EVEN THOUGH it improved — never a zero pair that reads as a tie"
    );
    assert_eq!(refusal.held_out_receipts, accepted.held_out_receipts);
    assert_eq!(refusal.held_out_count, accepted.held_out_count);
    assert_eq!(refusal.held_out_digest, accepted.held_out_digest);
    assert_eq!(refusal.proposal_digest, accepted.proposal_digest);
    assert_eq!(refusal.target_digest, accepted.target_digest);
    assert_eq!(refusal.cycle, accepted.cycle);
    assert_eq!(refusal.accepted_verdict, Some(accepted.id));

    let receipt = verdict_receipt(&vault, &refusal);
    assert_eq!(receipt.outcome, "refused_protected_tier");
    assert_eq!(
        receipt.fields["skill_edit_accepted_verdict"],
        accepted.id.to_hex()
    );
    assert_eq!(
        receipt.fields["skill_edit_score_after"],
        format!("{:.6}", accepted.after)
    );
    assert_eq!(
        receipt.fields["skill_edit_held_out_digest"],
        accepted.held_out_digest
    );
    Ok(())
}

// ─── ONE-1449 R1: optimizer birth outlives the BODY, not just the record ─

/// Whether the durable optimizer-birth marker stands at `id`.
fn origin_marked(vault: &Vault, id: &EntityId) -> bool {
    let rtxn = vault.store.env.read_txn().expect("read txn");
    vault
        .store
        .vault_meta
        .get(&rtxn, &gate::optimizer_origin_marker_key(id))
        .expect("marker read")
        .is_some()
}

/// A plain, non-optimizer candidate continuing `target`'s `skillId` — the
/// laundered body a recreate would smuggle in under an already-gated id.
fn plain_candidate(vault: &Vault, target: &EntityId) -> Vec<u8> {
    let target_record = stored(vault, target);
    let record = SkillRecord::new(
        target_record.skill_id.as_str(),
        "Instructions no gate ever scored.",
        "opt-laundered",
        ClaimApprovalStatus::Proposed,
        SkillLifecycle::Candidate,
        ClaimSource::UserStated,
        0.5,
        false,
        true,
        target_record.dependencies.clone(),
        provenance(None),
    )
    .with_governance_tier(SkillGovernanceTier::Standard);
    crate::skill::encode_skill_record(&record).expect("encode")
}

#[test]
fn a_same_batch_delete_and_recreate_cannot_launder_an_optimizer_born_id() {
    let (_tmp, vault) = temp_vault();
    let (skill, proposal) = losing_skill_with_proposal(&vault, "oneiron.skill.losing");
    let born = stored(&vault, &proposal);
    assert!(
        origin_marked(&vault, &proposal),
        "an optimizer-born create is marked at birth"
    );

    // ONE transaction: the delete drops the body and the put re-presents the id
    // as a virgin create, so the update door's origin law never runs. The
    // marker outlives the body, so the CREATE door asks the same question —
    // and there is no window between the two ops for anything to race.
    let laundered = plain_candidate(&vault, &skill);
    assert_eq!(
        vault
            .batch()
            .delete(&proposal)
            .put(&proposal, ENTITY_TYPE_SKILL, t(400), 401, &laundered)
            .commit()
            .expect_err("origin is a birth fact the ID keeps")
            .kind(),
        ErrorKind::InvalidSkillBody
    );
    assert_eq!(
        stored(&vault, &proposal),
        born,
        "the whole batch rolled back; nothing was staged"
    );
    assert!(origin_marked(&vault, &proposal));
}

#[test]
fn a_recreate_carrying_the_same_origin_is_still_gated_and_still_admissible() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let (_, proposal) = losing_skill_with_proposal(&vault, "oneiron.skill.losing");
    let scorer = StubScorer::improving();
    let accepted = score_gate_skill_edit_in_cycle(
        &vault,
        &proposal,
        &scorer,
        wake(&vault, "wake-1", 10),
        900,
    )?;
    assert_eq!(accepted.disposition, SkillEditDisposition::Accepted);

    // Delete and recreate the SAME body: honest, and admitted. What comes back
    // is optimizer-born again, so every rule that governed it still does.
    let born = stored(&vault, &proposal);
    let same = crate::skill::encode_skill_record(&born)?;
    vault
        .batch()
        .delete(&proposal)
        .put(&proposal, ENTITY_TYPE_SKILL, t(400), 401, &same)
        .commit()?;
    assert_eq!(stored(&vault, &proposal), born);

    // The bare flip is refused exactly as before — the recreate bought nothing.
    let mut flipped = born;
    flipped.approval_status = ClaimApprovalStatus::Approved;
    flipped.lifecycle_status = SkillLifecycle::Active;
    assert_eq!(
        vault
            .update_skill_record(&proposal, &flipped, t(402), 403)
            .expect_err("a recreated optimizer-born candidate never flips its way to canon")
            .kind(),
        ErrorKind::InvalidSkillBody
    );
    assert_eq!(
        stored(&vault, &proposal).lifecycle_status,
        SkillLifecycle::Candidate
    );

    // …and the gate's own door still works, on the acceptance it already had.
    admit_optimized_skill_revision(&vault, &proposal, t(404), 405)?;
    assert_eq!(
        stored(&vault, &proposal).lifecycle_status,
        SkillLifecycle::Active
    );
    Ok(())
}

#[test]
fn the_birth_marker_survives_deletion_and_refuses_a_later_recreate() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let (skill, proposal) = losing_skill_with_proposal(&vault, "oneiron.skill.losing");
    assert!(origin_marked(&vault, &proposal));

    // The most destructive door there is, and then a whole separate batch.
    assert!(vault.delete_entity_with_options(
        &proposal,
        crate::deletion::DeleteEntityOptions { purge: true }
    )?);
    assert!(
        vault.get_skill_record(&proposal)?.is_none(),
        "the body really is gone"
    );
    assert!(
        origin_marked(&vault, &proposal),
        "the marker is not the body, and no delete road clears it"
    );

    let laundered = plain_candidate(&vault, &skill);
    assert_eq!(
        vault
            .batch()
            .put(&proposal, ENTITY_TYPE_SKILL, t(400), 401, &laundered)
            .commit()
            .expect_err("a later batch is the same road")
            .kind(),
        ErrorKind::InvalidSkillBody
    );
    assert!(
        vault.get_skill_record(&proposal)?.is_none(),
        "the refused body landed nowhere"
    );
    Ok(())
}

// ─── ONE-1449 R2: the PROPOSAL's tier is bound and rechecked ────────────

#[test]
fn an_owner_mark_on_the_proposal_is_refused_at_the_admission_door() -> Result<()> {
    for tier in [
        SkillGovernanceTier::Identity,
        SkillGovernanceTier::Alignment,
    ] {
        let (_tmp, vault) = temp_vault();
        let (skill, proposal) = losing_skill_with_proposal(&vault, "oneiron.skill.losing");
        let scorer = StubScorer::improving();
        let accepted = score_gate_skill_edit_in_cycle(
            &vault,
            &proposal,
            &scorer,
            wake(&vault, "wake-1", 10),
            900,
        )?;
        assert_eq!(
            accepted.proposal_tier,
            Some(SkillGovernanceTier::Standard),
            "the acceptance BINDS the tier it ruled the proposal under"
        );

        // The owner marks the CANDIDATE — the body one write from canon —
        // after the gate passed. A tier mark is a state flip the body digest
        // deliberately normalizes away, so nothing but the bound tier can see
        // it, and the target-side recheck never looks at this record at all.
        let mut marked = stored(&vault, &proposal);
        marked.governance_tier = Some(tier);
        vault.update_skill_record(&proposal, &marked, t(400), 401)?;
        let canon_before = stored(&vault, &skill);

        assert_eq!(
            admit_optimized_skill_revision(&vault, &proposal, t(402), 403)
                .expect_err("the owner's newer ruling wins")
                .kind(),
            ErrorKind::InvalidSkillBody
        );
        let refusal = skill_edit_verdict(&vault, &proposal)?.expect("a durable refusal");
        assert_eq!(
            refusal.disposition,
            SkillEditDisposition::RefusedProtectedTier
        );
        // M9 shape: the real pair, the evidence identity, both digests and the
        // acceptance it answers all travel with the refusal.
        assert_eq!(
            (refusal.before, refusal.after),
            (accepted.before, accepted.after)
        );
        assert!(refusal.improvement() > 0.0);
        assert_eq!(refusal.held_out_digest, accepted.held_out_digest);
        assert_eq!(refusal.held_out_count, accepted.held_out_count);
        assert_eq!(refusal.proposal_digest, accepted.proposal_digest);
        assert_eq!(refusal.target_digest, accepted.target_digest);
        assert_eq!(refusal.accepted_verdict, Some(accepted.id));

        assert_eq!(
            stored(&vault, &skill),
            canon_before,
            "active canon is byte-unchanged"
        );
        let answered = stored(&vault, &proposal);
        assert_eq!(answered.lifecycle_status, SkillLifecycle::Candidate);
        assert_eq!(
            answered.approval_status,
            ClaimApprovalStatus::Rejected,
            "a refusal closes the proposal in the same transaction"
        );
    }
    Ok(())
}

#[test]
fn a_proposal_whose_tier_is_stripped_after_acceptance_fails_closed() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let (skill, proposal) = losing_skill_with_proposal(&vault, "oneiron.skill.losing");
    let scorer = StubScorer::improving();
    let accepted = score_gate_skill_edit_in_cycle(
        &vault,
        &proposal,
        &scorer,
        wake(&vault, "wake-1", 10),
        900,
    )?;

    // Unmarked and machine-born: provenance cannot vouch for it, so the tier
    // resolves AMBIGUOUS — which is not `standard`, and never was.
    let mut stripped = stored(&vault, &proposal);
    stripped.governance_tier = None;
    vault.update_skill_record(&proposal, &stripped, t(400), 401)?;
    assert_eq!(
        skill_governance_tier(&vault, &proposal)?,
        SkillTierVerdict::Ambiguous
    );

    let canon_before = stored(&vault, &skill);
    assert_eq!(
        admit_optimized_skill_revision(&vault, &proposal, t(402), 403)
            .expect_err("an ambiguous tier is not a tier the loop may author")
            .kind(),
        ErrorKind::InvalidSkillBody
    );
    let refusal = skill_edit_verdict(&vault, &proposal)?.expect("a durable refusal");
    assert_eq!(
        refusal.disposition,
        SkillEditDisposition::RefusedProtectedTier
    );
    assert_eq!(refusal.accepted_verdict, Some(accepted.id));
    assert_eq!(stored(&vault, &skill), canon_before);
    assert_eq!(
        stored(&vault, &proposal).approval_status,
        ClaimApprovalStatus::Rejected
    );
    Ok(())
}

#[test]
fn a_proposal_marked_protected_before_the_gate_is_refused_with_its_pair() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let (skill, proposal) = losing_skill_with_proposal(&vault, "oneiron.skill.losing");
    let mut marked = stored(&vault, &proposal);
    marked.governance_tier = Some(SkillGovernanceTier::Identity);
    vault.update_skill_record(&proposal, &marked, t(400), 401)?;
    let canon_before = stored(&vault, &skill);

    let scorer = StubScorer::improving();
    assert_eq!(
        score_gate_skill_edit_in_cycle(&vault, &proposal, &scorer, wake(&vault, "wake-1", 10), 900)
            .expect_err("a protected proposal is refused at accept time")
            .kind(),
        ErrorKind::InvalidSkillBody
    );
    let verdict = skill_edit_verdict(&vault, &proposal)?.expect("a durable refusal");
    assert_eq!(
        verdict.disposition,
        SkillEditDisposition::RefusedProtectedTier
    );
    assert!(
        verdict.after > verdict.before,
        "refused EVEN THOUGH it improved — the receipt has to be able to say so"
    );
    assert_eq!(
        verdict.proposal_tier,
        Some(SkillGovernanceTier::Identity),
        "the row names the tier it refused"
    );
    assert_eq!(stored(&vault, &skill), canon_before);
    assert_eq!(
        stored(&vault, &proposal).approval_status,
        ClaimApprovalStatus::Rejected
    );
    assert_eq!(
        admit_optimized_skill_revision(&vault, &proposal, t(402), 403)
            .expect_err("and it is never admitted")
            .kind(),
        ErrorKind::InvalidSkillBody
    );
    Ok(())
}

/// Rewrites the ONE stored verdict row through `edit`, so a test can present a
/// row from a schema this build no longer speaks.
fn rewrite_verdict_row(vault: &Vault, edit: impl Fn(&mut [(Value, Value)])) {
    let (key, mut entries) = {
        let rtxn = vault.store.env.read_txn().expect("read txn");
        let mut rows = vault
            .store
            .vault_meta
            .prefix_iter(&rtxn, gate::VERDICT_PREFIX)
            .expect("verdict rows");
        let (key, raw) = rows.next().expect("one verdict row").expect("row");
        let value = rmpv::decode::read_value(&mut std::io::Cursor::new(raw)).expect("decode");
        let Value::Map(entries) = value else {
            panic!("a verdict row is a map");
        };
        (key.to_vec(), entries)
    };
    edit(&mut entries);
    let mut encoded = Vec::new();
    rmpv::encode::write_value(&mut encoded, &Value::Map(entries)).expect("encode");
    vault
        .with_write_txn(|wtxn| {
            vault.store.vault_meta.put(wtxn, &key, &encoded)?;
            Ok(())
        })
        .expect("rewrite the row");
}

fn set_row_field(entries: &mut [(Value, Value)], key: &str, value: &Value) {
    for (name, held) in entries.iter_mut() {
        if name.as_str() == Some(key) {
            *held = value.clone();
            return;
        }
    }
    panic!("the row names {key}");
}

fn rename_row_field(entries: &mut [(Value, Value)], from: &str, to: &str) {
    for (name, _) in entries.iter_mut() {
        if name.as_str() == Some(from) {
            *name = Value::from(to);
            return;
        }
    }
    panic!("the row names {from}");
}

#[test]
fn a_verdict_row_is_schema_v7_and_every_older_row_fails_closed() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let (_, proposal) = losing_skill_with_proposal(&vault, "oneiron.skill.losing");
    let scorer = StubScorer::improving();
    let accepted = score_gate_skill_edit_in_cycle(
        &vault,
        &proposal,
        &scorer,
        wake(&vault, "wake-1", 10),
        900,
    )?;
    assert_eq!(
        skill_edit_verdict(&vault, &proposal)?.expect("a standing verdict"),
        accepted,
        "a v7 row round-trips with measurements, judge provenance, goal identity and tier"
    );
    assert_eq!(accepted.proposal_tier, Some(SkillGovernanceTier::Standard));

    // A v2 row binds no proposal tier, so a reader that accepted one would be
    // trusting an acceptance it cannot check. Prerelease: no shim, no dual
    // decode, no migration — it is simply unreadable.
    rewrite_verdict_row(&vault, |entries: &mut [(Value, Value)]| {
        set_row_field(entries, "v", &Value::from(2u64));
    });
    assert_eq!(
        skill_edit_verdicts(&vault)
            .expect_err("a v2 row is not decodable by this build")
            .kind(),
        ErrorKind::CorruptedIndex
    );

    // A v3 row has no judge measurements and cannot claim this schema.
    rewrite_verdict_row(&vault, |entries: &mut [(Value, Value)]| {
        set_row_field(entries, "v", &Value::from(3u64));
    });
    assert_eq!(
        skill_edit_verdicts(&vault)
            .expect_err("v3 is missing measurements")
            .kind(),
        ErrorKind::CorruptedIndex
    );

    // V4 has measurements but no goal vector. It cannot authorize an edit.
    rewrite_verdict_row(&vault, |entries: &mut [(Value, Value)]| {
        set_row_field(entries, "v", &Value::from(4u64));
    });
    assert_eq!(
        skill_edit_verdicts(&vault)
            .expect_err("v4 has no scored goal vector")
            .kind(),
        ErrorKind::CorruptedIndex
    );

    // A v5 row carries a judge revision but no goal vector, goal revision or
    // goal identity, so it cannot say which goal admitted the edit.
    rewrite_verdict_row(&vault, |entries| {
        set_row_field(entries, "v", &Value::from(5u64));
    });
    assert_eq!(
        skill_edit_verdicts(&vault)
            .expect_err("v5 lacks the scored goal vector")
            .kind(),
        ErrorKind::CorruptedIndex
    );
    // The same v5 shape relabelled v7 is still missing the goal fields.
    let goal_keys = [
        "goal_axes",
        "goal_revision",
        "goal_id",
        "tradeoff_resolution",
    ];
    rewrite_verdict_row(&vault, |entries| {
        set_row_field(entries, "v", &Value::from(7u64));
        for key in goal_keys {
            rename_row_field(entries, key, &format!("v5_{key}"));
        }
    });
    assert_eq!(
        skill_edit_verdicts(&vault)
            .expect_err("a v5-shaped row cannot claim v7")
            .kind(),
        ErrorKind::CorruptedIndex
    );
    rewrite_verdict_row(&vault, |entries| {
        for key in goal_keys {
            rename_row_field(entries, &format!("v5_{key}"), key);
        }
    });
    assert!(
        skill_edit_verdicts(&vault).is_ok(),
        "restoring the goal fields restores the v7 row"
    );

    // A v6 row has no ladder rung and no bound Jev verdict, so it cannot say
    // which rung settled a tradeoff (ONE-2115).
    rewrite_verdict_row(&vault, |entries| {
        set_row_field(entries, "v", &Value::from(6u64));
    });
    assert_eq!(
        skill_edit_verdicts(&vault)
            .expect_err("v6 lacks the tradeoff ladder fields")
            .kind(),
        ErrorKind::CorruptedIndex
    );
    // The same v6 shape relabelled v7 is still missing the Jev field.
    rewrite_verdict_row(&vault, |entries| {
        set_row_field(entries, "v", &Value::from(7u64));
        rename_row_field(entries, "tradeoff_jev", "v6_tradeoff_jev");
    });
    assert_eq!(
        skill_edit_verdicts(&vault)
            .expect_err("a v6-shaped row cannot claim v7")
            .kind(),
        ErrorKind::CorruptedIndex
    );
    rewrite_verdict_row(&vault, |entries| {
        rename_row_field(entries, "v6_tradeoff_jev", "tradeoff_jev");
    });
    assert!(
        skill_edit_verdicts(&vault).is_ok(),
        "restoring the Jev field restores the v7 row"
    );

    // …and so is the retired disposition, whatever schema claims to carry it.
    rewrite_verdict_row(&vault, |entries: &mut [(Value, Value)]| {
        set_row_field(entries, "v", &Value::from(7u64));
        set_row_field(
            entries,
            "disposition",
            &Value::from("deferred_evidence_changed"),
        );
    });
    assert_eq!(
        skill_edit_verdicts(&vault)
            .expect_err("the evidence race is not a durable disposition any more")
            .kind(),
        ErrorKind::CorruptedIndex
    );
    rewrite_verdict_row(&vault, |entries: &mut [(Value, Value)]| {
        set_row_field(entries, "disposition", &Value::from("accepted"));
    });
    // A judged v7 verdict cannot carry an absent or nil audit pair.
    rewrite_verdict_row(&vault, |entries: &mut [(Value, Value)]| {
        set_row_field(entries, "v", &Value::from(7u64));
        set_row_field(entries, "measurements", &Value::Nil);
    });
    assert_eq!(
        skill_edit_verdicts(&vault)
            .expect_err("judged row lost its audits")
            .kind(),
        ErrorKind::CorruptedIndex
    );

    Ok(())
}

// ─── ONE-1449 R3: a pre-score answer commits where it is decided ────────

#[test]
fn a_target_purged_after_acceptance_refuses_with_the_pair_it_earned() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let (skill, proposal) = losing_skill_with_proposal(&vault, "oneiron.skill.losing");
    let scorer = StubScorer::improving();
    let accepted = score_gate_skill_edit_in_cycle(
        &vault,
        &proposal,
        &scorer,
        wake(&vault, "wake-1", 10),
        900,
    )?;

    // The predecessor is erased between the acceptance and the door. The old
    // shape exited on a bare `EntityNotFound`, which left the acceptance
    // standing, the proposal open, and the real pair unrecorded.
    assert!(vault.delete_entity_with_options(
        &skill,
        crate::deletion::DeleteEntityOptions { purge: true }
    )?);
    assert_eq!(
        admit_optimized_skill_revision(&vault, &proposal, t(400), 401)
            .expect_err("a purged predecessor is not one this candidate can supersede")
            .kind(),
        ErrorKind::InvalidSkillBody
    );
    let refusal = skill_edit_verdict(&vault, &proposal)?.expect("a durable refusal");
    assert_eq!(
        refusal.disposition,
        SkillEditDisposition::RefusedStaleTarget
    );
    assert_eq!(
        (refusal.before, refusal.after),
        (accepted.before, accepted.after),
        "the refusal carries the acceptance's numbers, never a zero pair"
    );
    assert_eq!(refusal.held_out_digest, accepted.held_out_digest);
    assert_eq!(refusal.accepted_verdict, Some(accepted.id));
    let answered = stored(&vault, &proposal);
    assert_eq!(answered.lifecycle_status, SkillLifecycle::Candidate);
    assert_eq!(
        answered.approval_status,
        ClaimApprovalStatus::Rejected,
        "row and closure commit together"
    );
    assert!(
        !skill_edit_verdict(&vault, &proposal)?
            .expect("standing")
            .disposition
            .admits(),
        "and the acceptance no longer stands"
    );
    Ok(())
}

#[test]
fn a_gate_call_against_an_unreadable_target_refuses_durably_and_closes_it() -> Result<()> {
    let (_tmp, vault) = temp_vault();

    // Purged: the target row is simply gone.
    let (purged, orphan) = losing_skill_with_proposal(&vault, "oneiron.skill.purged");
    assert!(vault.delete_entity_with_options(
        &purged,
        crate::deletion::DeleteEntityOptions { purge: true }
    )?);
    assert_eq!(
        score_gate_skill_edit_in_cycle(
            &vault,
            &orphan,
            &UnreachableScorer,
            wake(&vault, "wake-1", 10),
            900
        )
        .expect_err("there is nothing left to score against")
        .kind(),
        ErrorKind::InvalidSkillBody
    );
    let verdict = skill_edit_verdict(&vault, &orphan)?.expect("a durable refusal");
    assert_eq!(
        verdict.disposition,
        SkillEditDisposition::RefusedStaleTarget
    );
    assert_eq!(
        (verdict.before, verdict.after),
        (0.0, 0.0),
        "nothing was replayed, so the pair is honestly zero"
    );
    assert_eq!(
        verdict.proposal_tier, None,
        "a pre-score refusal binds no basis at all"
    );
    assert_eq!(
        stored(&vault, &orphan).approval_status,
        ClaimApprovalStatus::Rejected,
        "the answer closed the question in the transaction that wrote it"
    );

    // An unreadable SHELL: an entity of another kind now occupies the id.
    let (shelled, shell_proposal) = losing_skill_with_proposal(&vault, "oneiron.skill.shelled");
    assert!(vault.delete_entity_with_options(
        &shelled,
        crate::deletion::DeleteEntityOptions { purge: true }
    )?);
    put_actor(&vault, &shelled);
    assert_eq!(
        score_gate_skill_edit_in_cycle(
            &vault,
            &shell_proposal,
            &UnreachableScorer,
            wake(&vault, "wake-1", 10),
            901
        )
        .expect_err("a row of another kind is not the revision this revises")
        .kind(),
        ErrorKind::InvalidSkillBody
    );
    assert_eq!(
        skill_edit_verdict(&vault, &shell_proposal)?
            .expect("a durable refusal")
            .disposition,
        SkillEditDisposition::RefusedStaleTarget
    );
    assert_eq!(
        stored(&vault, &shell_proposal).approval_status,
        ClaimApprovalStatus::Rejected
    );
    Ok(())
}

// ─── ONE-1449 K3: the material repairs ──────────────────────────────────

/// A judge that EDITS THE PROPOSAL while it is thinking.
///
/// The deterministic stand-in for a second writer touching the candidate in the
/// window the scorer holds no lock over. The judge is answering about bytes that
/// no longer exist by the time the row would commit, which is a fact about the
/// CALL, not about the proposal.
struct ProposalEditingScorer<'a> {
    vault: &'a Vault,
    proposal: EntityId,
    edited: RefCell<bool>,
}

const RE_EDITED_DESC: &str = "A second author rewrote this while the judge read.";

impl HeldOutReplayScorer for ProposalEditingScorer<'_> {
    fn judge_revision(&self) -> &str {
        "fixture-judge@1"
    }
    fn score(&self, case: &HeldOutReplayCase<'_>) -> Result<f32> {
        if !self.edited.replace(true) {
            let mut edited = stored(self.vault, &self.proposal);
            edited.desc = RE_EDITED_DESC.to_owned();
            edited.version = "opt-re-edited".to_owned();
            self.vault
                .update_skill_record(&self.proposal, &edited, t(500), 501)
                .expect("an open candidate is revisable through the ordinary door");
        }
        Ok(if case.instructions == TARGET_DESC {
            0.40
        } else {
            0.75
        })
    }
    fn structural_audit(&self, _task: &str, _instructions: &str) -> Result<f32> {
        Ok(0.5)
    }
    fn blind_preference(&self, _task: &str, _receipts: &[String]) -> Result<Vec<BlindPreference>> {
        Ok(vec![BlindPreference {
            pair_ref: "fixture-pair".to_owned(),
            preferred: PreferredResponse::First,
        }])
    }
    fn contrastive_audit(
        &self,
        _case: &HeldOutReplayCase<'_>,
        _blind: &[BlindPreference],
    ) -> Result<f32> {
        Ok(0.5)
    }
    fn predict_task_success(&self, case: &HeldOutReplayCase<'_>) -> Result<Vec<f32>> {
        Ok(vec![0.5; case.held_out_receipts.len()])
    }
}

/// M-1: a proposal that MOVED under the scorer is a retry, not an answer.
#[test]
fn a_proposal_edited_under_the_scorer_aborts_instead_of_being_closed() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let (_, proposal) = losing_skill_with_proposal(&vault, "oneiron.skill.losing");
    let editing = ProposalEditingScorer {
        vault: &vault,
        proposal,
        edited: RefCell::new(false),
    };

    let raced = score_gate_skill_edit_in_cycle(
        &vault,
        &proposal,
        &editing,
        wake(&vault, "wake-1", 10),
        900,
    )
    .expect_err("the judge scored bytes this transaction can no longer see");
    assert_eq!(
        raced.kind(),
        ErrorKind::SkillEditGateRetry,
        "a moved PROPOSAL is 'nothing was learned', not 'the target moved'"
    );
    assert!(raced.is_retryable());

    // Nothing committed: no row, no closure, no cap spend. The freshly edited
    // candidate — which no judge has ever seen — is still an open question.
    assert!(
        skill_edit_verdicts_for_proposal(&vault, &proposal)?.is_empty(),
        "a race is not a ruling, so it has no row"
    );
    let waiting = stored(&vault, &proposal);
    assert_eq!(waiting.desc, RE_EDITED_DESC);
    assert_eq!(waiting.lifecycle_status, SkillLifecycle::Candidate);
    assert_eq!(waiting.approval_status, ClaimApprovalStatus::Proposed);

    // The rerun, over a body that is standing still, rules on the bytes it
    // actually scored.
    let settled = StubScorer::improving();
    let verdict = score_gate_skill_edit_in_cycle(
        &vault,
        &proposal,
        &settled,
        wake(&vault, "wake-2", 20),
        901,
    )?;
    assert_eq!(verdict.disposition, SkillEditDisposition::Accepted);
    assert_eq!(
        verdict.proposal_digest,
        skill_body_binding_digest(&waiting)?
    );
    Ok(())
}

/// M-2: a malformed array in a stored verdict is corruption, not a shorter row.
#[test]
fn a_verdict_row_with_a_malformed_array_fails_closed_instead_of_shortening() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let (_, proposal) = losing_skill_with_proposal(&vault, "oneiron.skill.losing");
    let scorer = StubScorer::improving();
    let accepted = score_gate_skill_edit_in_cycle(
        &vault,
        &proposal,
        &scorer,
        wake(&vault, "wake-1", 10),
        900,
    )?;
    assert!(!accepted.held_out_receipts.is_empty());

    // A non-string member of the display list. Dropping it silently left a
    // standing ACCEPTANCE whose evidence list no longer matched the count and
    // digest standing beside it in the same row.
    rewrite_verdict_row(&vault, |entries: &mut [(Value, Value)]| {
        set_row_field(entries, "held_out", &Value::Array(vec![Value::from(7u64)]));
    });
    assert_eq!(
        skill_edit_verdicts(&vault)
            .expect_err("a row that cannot say what it ruled over is corrupt")
            .kind(),
        ErrorKind::CorruptedIndex
    );
    assert_eq!(
        admit_optimized_skill_revision(&vault, &proposal, t(400), 401)
            .expect_err("an unreadable ruling admits nothing")
            .kind(),
        ErrorKind::CorruptedIndex
    );
    assert_eq!(
        stored(&vault, &proposal).lifecycle_status,
        SkillLifecycle::Candidate
    );

    // …and the same for a missing-source id that does not parse: a refusal that
    // lost the very id it refuses over is an audit record nobody can audit.
    rewrite_verdict_row(&vault, |entries: &mut [(Value, Value)]| {
        set_row_field(
            entries,
            "held_out",
            &Value::Array(vec![Value::from("receipt-1")]),
        );
        set_row_field(
            entries,
            "missing_sources",
            &Value::Array(vec![Value::from("not-an-entity-id")]),
        );
    });
    assert_eq!(
        skill_edit_verdicts(&vault)
            .expect_err("an unparseable source id is corruption, not absence")
            .kind(),
        ErrorKind::CorruptedIndex
    );
    Ok(())
}

/// M-5: remat is where a replica first meets an optimizer-born id, so it is
/// where the durable origin marker has to be born.
#[test]
fn a_rematerialized_optimizer_born_id_is_marked_and_cannot_be_laundered() -> Result<()> {
    let (_tmp, origin) = temp_vault();
    let (skill, proposal) = losing_skill_with_proposal(&origin, "oneiron.skill.losing");
    let born = stored(&origin, &proposal);
    let target_body = crate::skill::encode_skill_record(&stored(&origin, &skill))?;
    let proposal_body = crate::skill::encode_skill_record(&born)?;

    // The replica has never seen either id: both arrive as sync-remat creates,
    // and the peer's bytes are stored exactly as sent.
    let (_replica_tmp, replica) = temp_vault();
    replica
        .batch()
        .put_replicated(&skill, ENTITY_TYPE_SKILL, t(400), 401, &target_body)
        .put_replicated(&proposal, ENTITY_TYPE_SKILL, t(400), 401, &proposal_body)
        .commit()?;
    assert_eq!(stored(&replica, &proposal), born);
    assert!(
        origin_marked(&replica, &proposal),
        "the replica records the origin of an id it is meeting for the first time"
    );

    // So the laundering road is closed on the replica too: remove the body
    // without an owner hard-delete marker, then re-present it as an ordinary
    // candidate. The optimizer birth marker itself must still enforce this.
    replica.batch().delete(&proposal).commit()?;
    assert!(
        replica.get_skill_record(&proposal)?.is_none(),
        "the body is gone"
    );
    assert!(
        origin_marked(&replica, &proposal),
        "no delete road clears the marker"
    );
    let laundered = plain_candidate(&replica, &skill);
    assert_eq!(
        replica
            .batch()
            .put(&proposal, ENTITY_TYPE_SKILL, t(402), 403, &laundered)
            .commit()
            .expect_err("an id born on the optimize road keeps that birth")
            .kind(),
        ErrorKind::InvalidSkillBody
    );
    assert!(replica.get_skill_record(&proposal)?.is_none());

    // The same-origin replay is admitted, but a local hard delete still
    // dominates its older body. The immutable origin marker survives either
    // outcome; accepting a replay is not authority to resurrect an ID.
    replica
        .batch()
        .put_replicated(&proposal, ENTITY_TYPE_SKILL, t(404), 405, &proposal_body)
        .commit()?;
    assert!(
        replica
            .get_skill_record(&proposal)?
            .is_none_or(|record| record == born)
    );
    assert!(origin_marked(&replica, &proposal));
    Ok(())
}

/// M-6: the replicated update door is held to the origin law, and to what a
/// settled admission actually looks like.
#[test]
fn a_replicated_update_can_neither_edit_origin_nor_activate_new_content() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let (_, proposal) = losing_skill_with_proposal(&vault, "oneiron.skill.losing");
    let born = stored(&vault, &proposal);
    let replicate = |record: &SkillRecord, at: u64| -> Result<()> {
        let body = crate::skill::encode_skill_record(record)?;
        vault
            .batch()
            .put_replicated(&proposal, ENTITY_TYPE_SKILL, t(at), at + 1, &body)
            .commit()
    };

    // A peer's row that strips the birth path: the laundering the local door
    // has always refused, arriving by sync instead of by the owner's hand.
    let mut stripped = born.clone();
    stripped.provenance = without_provenance(&born, PROVENANCE_BIRTH_KEY);
    stripped.desc = "Rewritten with no birth path at all.".to_owned();
    stripped.version = "opt-stripped".to_owned();
    assert_eq!(
        replicate(&stripped, 400)
            .expect_err("settled remote state is not a licence to rewrite a birth fact")
            .kind(),
        ErrorKind::InvalidSkillBody
    );
    assert_eq!(stored(&vault, &proposal), born, "nothing landed");

    // An activation that also moves content: unscored bytes reaching canon
    // through a state flip is the one thing this floor exists to stop.
    let mut rewritten = born.clone();
    rewritten.desc = "Instructions no gate ever scored.".to_owned();
    rewritten.version = "opt-unscored".to_owned();
    rewritten.approval_status = ClaimApprovalStatus::Approved;
    rewritten.lifecycle_status = SkillLifecycle::Active;
    assert_eq!(
        replicate(&rewritten, 402)
            .expect_err("a peer that re-drafted sends a new revision, not a rewrite")
            .kind(),
        ErrorKind::InvalidSkillBody
    );
    assert_eq!(stored(&vault, &proposal), born);

    // The LOCAL bare flip is refused exactly as before — the replicated road
    // bought it nothing.
    let mut flipped = born.clone();
    flipped.approval_status = ClaimApprovalStatus::Approved;
    flipped.lifecycle_status = SkillLifecycle::Active;
    assert_eq!(
        vault
            .update_skill_record(&proposal, &flipped, t(404), 405)
            .expect_err("an optimizer-born candidate never flips its way to canon")
            .kind(),
        ErrorKind::InvalidSkillBody
    );

    // …while the lawful peer ADMISSION — the same body, the two state axes
    // moved and nothing else — still converges. A replica that quarantined this
    // would diverge over an edit the gate really did rule on.
    replicate(&flipped, 406)?;
    let admitted = stored(&vault, &proposal);
    assert_eq!(admitted.lifecycle_status, SkillLifecycle::Active);
    assert_eq!(admitted.approval_status, ClaimApprovalStatus::Approved);
    assert_eq!(
        skill_body_binding_digest(&admitted)?,
        skill_body_binding_digest(&born)?,
        "a settled admission moves the state axes and nothing else"
    );
    Ok(())
}

/// Records ONE `Discovery` outcome whose receipt falls on the requested side of
/// this skill's split, and returns that receipt.
///
/// Discovery is the verdict that mints a SK-04 edit PROPOSAL (`§4`: it is not a
/// claim), which is the author-facing payload under test.
fn discovery_proposal_receipt(
    vault: &Vault,
    skill: &EntityId,
    skill_id: &str,
    reserved: bool,
    at: u64,
) -> String {
    let actor = EntityId::now();
    put_actor(vault, &actor);
    let receipt = stamped_receipt_in_partition(vault, skill, skill_id, reserved, at, Some(actor));
    record_attribution_evidence(
        vault,
        &OutcomeEvidence::new(&receipt, actor, AttemptOutcome::Failed, at + 5)
            .with_skill(*skill)
            .with_routing_facts(true, false),
    )
    .expect("record evidence");
    let cursor = read_attribution_cursor(vault).expect("cursor");
    run_attribution_projector(vault, cursor).expect("attribution pass");
    receipt
}

/// M-8: every receipt-bearing payload the author is handed is dev-side, not
/// just the two flat receipt lists.
#[test]
fn a_proposal_resting_on_reserved_evidence_never_reaches_the_author() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let (skill, _) = put_standard_active(&vault, "oneiron.skill.losing");
    attribute_defects_across_split(&vault, &skill, "oneiron.skill.losing");
    let shown = discovery_proposal_receipt(&vault, &skill, "oneiron.skill.losing", false, 30_000);
    let reserved = discovery_proposal_receipt(&vault, &skill, "oneiron.skill.losing", true, 40_000);
    let durable: Vec<String> = pending_edit_proposals(&vault)?
        .into_iter()
        .filter(|proposal| proposal.skill == skill)
        .flat_map(|proposal| proposal.evidence_receipts)
        .collect();
    assert!(
        durable.contains(&shown) && durable.contains(&reserved),
        "both proposals are durable; it is the READ that is partitioned"
    );

    let candidate = optimize_candidates(&vault)?
        .into_iter()
        .find(|candidate| candidate.skill == skill)
        .expect("a losing skill");
    let brief = optimize_brief(&vault, &candidate)?;
    let cited: Vec<String> = brief
        .discovery_proposals
        .iter()
        .flat_map(|proposal| proposal.evidence_receipts.clone())
        .collect();
    assert!(cited.contains(&shown), "dev-side proposals still inform");
    assert!(
        !cited.contains(&reserved),
        "a reserved id must not reach the author, whatever payload carries it"
    );

    // The rule itself, over the three shapes a proposal ledger can hand it.
    assert!(rests_only_on_dev(&skill, std::slice::from_ref(&shown)));
    assert!(
        !rests_only_on_dev(&skill, &[shown, reserved]),
        "one reserved citation taints the payload it justifies"
    );
    assert!(
        !rests_only_on_dev(&skill, &[]),
        "a payload that cites nothing has shown nothing"
    );
    Ok(())
}

/// M-3: the longest run id the queue admits still names a cycle.
#[test]
fn the_longest_queue_accepted_run_id_still_names_a_cycle() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let longest = "r".repeat(SKILL_EDIT_CYCLE_MAX_BYTES - SKILL_EDIT_CYCLE_RUN_PREFIX.len());
    let attempt = enqueue_attempt(&vault, Some(longest.as_str()), 10);
    let cycle = proven_cycle(&vault, attempt)?;
    assert_eq!(
        cycle.as_str(),
        format!("{SKILL_EDIT_CYCLE_RUN_PREFIX}{longest}")
    );
    assert_eq!(
        cycle.as_str().len(),
        SKILL_EDIT_CYCLE_MAX_BYTES,
        "the queue's bound and the cycle's are one contract, not two"
    );

    // …and a proposal drafted in that run is gated under it, which is the thing
    // the overflow used to make impossible after the author had been paid.
    let (_, proposal) = losing_skill_with_proposal(&vault, "oneiron.skill.losing");
    let verdict =
        score_gate_skill_edit_in_cycle(&vault, &proposal, &StubScorer::improving(), attempt, 900)?;
    assert_eq!(verdict.cycle, cycle.as_str());
    assert_eq!(verdict.disposition, SkillEditDisposition::Accepted);
    Ok(())
}

// OF-214: audit measurements do not vote on scalar admission. World labels,
// unlike rubric scores, come from the outcome ledger and are scored per axis.
struct MeasuredScorer {
    phases: RefCell<Vec<&'static str>>,
}

impl HeldOutReplayScorer for MeasuredScorer {
    fn judge_revision(&self) -> &str {
        "fixture-judge@1"
    }
    fn score(&self, case: &HeldOutReplayCase<'_>) -> Result<f32> {
        self.phases.borrow_mut().push("score");
        Ok(if case.instructions == TARGET_DESC {
            0.40
        } else {
            0.75
        })
    }

    fn structural_audit(&self, _task: &str, instructions: &str) -> Result<f32> {
        self.phases.borrow_mut().push("structural");
        Ok(if instructions == TARGET_DESC {
            0.9
        } else {
            0.1
        })
    }

    fn blind_preference(&self, _task: &str, _receipts: &[String]) -> Result<Vec<BlindPreference>> {
        self.phases.borrow_mut().push("blind");
        Ok(vec![BlindPreference {
            pair_ref: "fixture-pair".to_owned(),
            preferred: PreferredResponse::First,
        }])
    }
    fn contrastive_audit(
        &self,
        case: &HeldOutReplayCase<'_>,
        blind: &[BlindPreference],
    ) -> Result<f32> {
        assert_eq!(blind[0].preferred, PreferredResponse::First);
        self.phases.borrow_mut().push("contrastive");
        Ok(if case.instructions == TARGET_DESC {
            0.8
        } else {
            0.2
        })
    }

    fn predict_task_success(&self, case: &HeldOutReplayCase<'_>) -> Result<Vec<f32>> {
        self.phases.borrow_mut().push("predict");
        let prediction = if case.instructions == TARGET_DESC {
            0.1
        } else {
            0.9
        };
        Ok(vec![prediction; case.held_out_receipts.len()])
    }
}

#[test]
fn decoevo_audits_are_receipted_measurements_and_world_scores_follow_labels() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let (skill, proposal) = losing_skill_with_proposal(&vault, "oneiron.skill.measured");
    let reserved = held_out_receipts(&vault, &skill)?;
    let rtxn = vault.store.env.read_txn()?;
    let outcomes = crate::skill_reliability::attributed_outcome_results(&vault, &rtxn, &skill)?;
    let truth: Vec<bool> = outcomes
        .into_iter()
        .filter(|(receipt, _)| reserved.contains(receipt))
        .map(|(_, won)| won)
        .collect();
    drop(rtxn);
    assert!(!truth.is_empty());
    let scorer = MeasuredScorer {
        phases: RefCell::new(Vec::new()),
    };
    let verdict = score_gate_skill_edit_in_cycle(
        &vault,
        &proposal,
        &scorer,
        wake(&vault, "measurement", 10),
        900,
    )?;
    assert_eq!(verdict.disposition, SkillEditDisposition::Accepted);
    assert_eq!(
        scorer.phases.borrow().as_slice(),
        [
            "blind",
            "structural",
            "structural",
            "contrastive",
            "contrastive",
            "predict",
            "predict",
            "score",
            "score"
        ]
    );
    let measurement = verdict
        .measurements
        .as_ref()
        .expect("judged verdict has measurements");
    assert_eq!(
        measurement.structural,
        AuditPair {
            before: 0.9,
            after: 0.1
        }
    );
    assert_eq!(
        measurement.contrastive,
        AuditPair {
            before: 0.8,
            after: 0.2
        }
    );
    assert_eq!(measurement.blind_preferences.len(), 1);
    assert_eq!(measurement.blind_preferences[0].pair_ref, "fixture-pair");
    let axis = &measurement.world_axes["task_success"];
    assert_eq!(axis.labelled_receipts, truth.len() as u64);
    let wins = truth.iter().filter(|won| **won).count() as f32;
    let expected_before = (wins * 0.1 + (truth.len() as f32 - wins) * 0.9) / truth.len() as f32;
    let expected_after = (wins * 0.9 + (truth.len() as f32 - wins) * 0.1) / truth.len() as f32;
    assert!((axis.before - expected_before).abs() < 0.000_001);
    assert!((axis.after - expected_after).abs() < 0.000_001);
    let stored = skill_edit_verdict(&vault, &proposal)?.expect("durable verdict");
    assert_eq!(stored.measurements, verdict.measurements);
    let receipt = verdict_receipt(&vault, &verdict);
    let projected: JudgeMeasurements =
        serde_json::from_str(&receipt.fields["skill_edit_measurements"])
            .expect("receipt carries typed measurement JSON");
    assert_eq!(projected, *measurement);
    Ok(())
}

#[test]
fn judged_verdict_rejects_unsupported_world_axes_and_unbound_counts() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let (_, proposal) = losing_skill_with_proposal(&vault, "oneiron.skill.corrupt_axes");
    let verdict = score_gate_skill_edit_in_cycle(
        &vault,
        &proposal,
        &StubScorer::improving(),
        wake(&vault, "axes", 10),
        900,
    )?;
    let original = serde_json::to_value(verdict.measurements.expect("judged row"))
        .expect("serialize measurements");
    // Every case leaves the body and evidence digests intact. Decoding must
    // still reject a receipt that names an unsupported axis or invents labels.
    for alteration in 0..3 {
        let mut changed = original.clone();
        let axes = changed["world_axes"].as_object_mut().expect("axis map");
        match alteration {
            0 => {
                let score = axes.remove("task_success").expect("supported axis");
                axes.insert(String::new(), score);
            }
            1 => {
                axes.insert("not_a_world_axis".to_owned(),
                    serde_json::json!({"before": 0.5, "after": 0.5, "labelled_receipts": verdict.held_out_count}));
            }
            _ => {
                axes.get_mut("task_success").expect("supported axis")["labelled_receipts"] =
                    serde_json::json!(verdict.held_out_count + 1);
            }
        }
        let json = serde_json::to_string(&changed).expect("measurement JSON");
        rewrite_verdict_row(&vault, |entries| {
            set_row_field(entries, "measurements", &Value::from(json.as_str()));
        });
        assert_eq!(
            skill_edit_verdicts(&vault)
                .expect_err("invalid world axis is corrupt")
                .kind(),
            ErrorKind::CorruptedIndex,
        );
        assert_eq!(
            vault
                .receipts(crate::receipt::ReceiptQuery::default())
                .expect_err("receipt projection must not repeat the false measurement")
                .kind(),
            ErrorKind::CorruptedIndex,
        );
    }
    Ok(())
}

fn vector_owner(vault: &Vault) -> crate::consent::AuthenticatedOwner {
    let id = EntityId::now();
    vault
        .put_entity(&id, ENTITY_TYPE_PERSON, t(1), 1, b"goal owner")
        .expect("person");
    vault
        .authenticate_owner(
            id,
            "principal:goal-owner",
            true,
            crate::store::GateDecisionId::now(),
        )
        .expect("owner")
}

fn vector_axes() -> Vec<GoalAxisSpec> {
    vec![
        GoalAxisSpec {
            name: "held_out".into(),
            kind: GoalAxisKind::Primary,
        },
        GoalAxisSpec {
            name: "quality".into(),
            kind: GoalAxisKind::Primary,
        },
        GoalAxisSpec {
            name: "safety".into(),
            kind: GoalAxisKind::Floor,
        },
        GoalAxisSpec {
            name: "human_minutes".into(),
            kind: GoalAxisKind::Cost,
        },
    ]
}

fn put_narrowing_goal_manifest(vault: &Vault, id: EntityId, axes: Vec<GoalAxisSpec>) -> Result<()> {
    let baseline = crate::gate::default_policy_manifest().unwrap();
    let Value::Map(mut entries) = rmpv::decode::read_value(&mut std::io::Cursor::new(baseline))
        .expect("shipped manifest decodes")
    else {
        panic!("manifest map")
    };
    let (_, policy) = entries
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some("skill_edit_goal_policy"))
        .expect("shipped goal policy row");
    let mut narrowed = vec![GoalAxisSpec {
        name: "held_out".into(),
        kind: GoalAxisKind::Primary,
    }];
    narrowed.extend(axes);
    *policy = rmpv::ext::to_value(serde_json::json!({
        "precedence": "nested_narrowing", "holder_max_scope": "vault", "axes": narrowed
    }))
    .expect("encode policy value");
    let parsed = crate::gate::SkillEditGoalPolicy::decode(policy.clone())
        .expect("goal-policy fixture value roundtrips");
    assert_eq!(parsed.precedence, "nested_narrowing");
    let mut encoded = Vec::new();
    rmpv::encode::write_value(&mut encoded, &Value::Map(entries)).expect("encode manifest");
    crate::test_util::put_policy_manifest_bytes(vault, id, &encoded)
}

// ONE-2114: a headline win is not an admission when any goal axis regresses.
struct VectorScorer {
    primary: (f32, f32),
    floor: (f32, f32),
    cost: (f32, f32),
    baseline: &'static str,
    axes: Option<Vec<GoalAxisSpec>>,
    seen: RefCell<Vec<(String, String, Vec<String>)>>,
}

impl VectorScorer {
    fn new(primary: (f32, f32), floor: (f32, f32), cost: (f32, f32)) -> Self {
        Self {
            primary,
            floor,
            cost,
            baseline: TARGET_DESC,
            axes: None,
            seen: RefCell::new(Vec::new()),
        }
    }

    fn with_baseline(mut self, baseline: &'static str) -> Self {
        self.baseline = baseline;
        self
    }

    fn with_axes(mut self, axes: Vec<GoalAxisSpec>) -> Self {
        self.axes = Some(axes);
        self
    }
}

impl HeldOutReplayScorer for VectorScorer {
    fn judge_revision(&self) -> &str {
        "fixture-judge@1"
    }
    fn score(&self, _: &HeldOutReplayCase<'_>) -> Result<f32> {
        panic!("a multi-axis scorer cannot fall back to a scalar")
    }
    fn goal_axes(&self, _: &HeldOutReplayCase<'_>) -> Result<Vec<GoalAxisSpec>> {
        Ok(self.axes.clone().unwrap_or_else(vector_axes))
    }
    fn score_goal_axis(&self, case: &HeldOutReplayCase<'_>, axis: &GoalAxisSpec) -> Result<f32> {
        self.seen.borrow_mut().push((
            axis.name.clone(),
            case.instructions.to_owned(),
            case.held_out_receipts.to_vec(),
        ));
        let (before, after) = match axis.name.as_str() {
            "quality" | "held_out" => self.primary,
            "safety" => self.floor,
            "human_minutes" => self.cost,
            _ => panic!("unknown axis"),
        };
        Ok(if case.instructions == self.baseline {
            before
        } else {
            after
        })
    }
    fn structural_audit(&self, _: &str, _: &str) -> Result<f32> {
        Ok(0.5)
    }
    fn blind_preference(&self, _: &str, _: &[String]) -> Result<Vec<BlindPreference>> {
        Ok(vec![BlindPreference {
            pair_ref: "pair".into(),
            preferred: PreferredResponse::First,
        }])
    }
    fn contrastive_audit(&self, _: &HeldOutReplayCase<'_>, _: &[BlindPreference]) -> Result<f32> {
        Ok(0.5)
    }
    fn predict_task_success(&self, case: &HeldOutReplayCase<'_>) -> Result<Vec<f32>> {
        Ok(vec![0.5; case.held_out_receipts.len()])
    }
}

#[test]
fn goal_vector_dominance_admits_rejects_regressions_and_defers_tradeoffs() -> Result<()> {
    for (label, primary, floor, cost, expected) in [
        (
            "dominates",
            (0.4, 0.7),
            (0.8, 0.8),
            (0.5, 0.6),
            SkillEditDisposition::Accepted,
        ),
        (
            "dominated",
            (0.7, 0.4),
            (0.8, 0.8),
            (0.6, 0.5),
            SkillEditDisposition::Rejected,
        ),
        (
            "tie",
            (0.4, 0.4),
            (0.8, 0.8),
            (0.5, 0.5),
            SkillEditDisposition::Rejected,
        ),
        (
            "floor",
            (0.4, 0.9),
            (0.8, 0.7),
            (0.5, 0.6),
            SkillEditDisposition::Rejected,
        ),
        (
            "cost",
            (0.4, 0.9),
            (0.8, 0.8),
            (0.6, 0.5),
            SkillEditDisposition::NeedsTradeoffDecision,
        ),
        (
            "quality_cost_tradeoff",
            (0.7, 0.4),
            (0.8, 0.8),
            (0.5, 0.7),
            SkillEditDisposition::NeedsTradeoffDecision,
        ),
    ] {
        let (_tmp, vault) = temp_vault();
        let (skill, proposal) =
            losing_skill_with_proposal(&vault, &format!("oneiron.skill.vector.{label}"));
        let owner = vector_owner(&vault);
        set_skill_edit_goal_axes(&vault, &owner, &skill, vector_axes())?;
        let scorer = VectorScorer::new(primary, floor, cost);
        let verdict = score_gate_skill_edit_in_cycle(
            &vault,
            &proposal,
            &scorer,
            wake(&vault, label, 10),
            900,
        )?;
        assert_eq!(verdict.disposition, expected, "{label}");
        assert_eq!(verdict.accepted, expected.admits(), "{label}");
        assert_eq!(verdict.goal_axes["quality"].before, primary.0);
        assert_eq!(verdict.goal_axes["quality"].after, primary.1);
        assert_eq!(verdict.goal_axes["safety"].kind, GoalAxisKind::Floor);
        assert_eq!(verdict.goal_axes["human_minutes"].kind, GoalAxisKind::Cost);
        assert_eq!(
            scorer.seen.borrow().len(),
            8,
            "both bodies on all four axes"
        );
        let reserved = held_out_receipts(&vault, &skill)?;
        assert!(
            scorer
                .seen
                .borrow()
                .iter()
                .all(|(_, _, receipts)| *receipts == reserved)
        );
        assert_eq!(
            skill_edit_verdict(&vault, &proposal)?.unwrap().goal_axes,
            verdict.goal_axes
        );
        let receipt = verdict_receipt(&vault, &verdict);
        let projected: std::collections::BTreeMap<String, GoalAxisScore> =
            serde_json::from_str(&receipt.fields["skill_edit_goal_axes"]).expect("receipt vector");
        assert_eq!(projected, verdict.goal_axes);
        if expected == SkillEditDisposition::NeedsTradeoffDecision {
            assert_eq!(
                stored(&vault, &proposal).approval_status,
                ClaimApprovalStatus::Proposed
            );
            assert_eq!(
                score_gate_skill_edit_in_cycle(
                    &vault,
                    &proposal,
                    &UnreachableScorer,
                    wake(&vault, "tradeoff-retry", 20),
                    901,
                )?,
                verdict,
                "a pending tradeoff is not re-scored in a later cycle"
            );
            assert_eq!(
                skill_edit_verdicts_for_proposal(&vault, &proposal)?.len(),
                1
            );
        }
    }
    Ok(())
}

#[test]
fn an_accepted_vector_cannot_be_rewritten_to_regress_a_floor() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let (skill, proposal) = losing_skill_with_proposal(&vault, "oneiron.skill.vector.corrupt");
    set_skill_edit_goal_axes(&vault, &vector_owner(&vault), &skill, vector_axes())?;
    score_gate_skill_edit_in_cycle(
        &vault,
        &proposal,
        &VectorScorer::new((0.4, 0.7), (0.8, 0.8), (0.5, 0.6)),
        wake(&vault, "vector-corrupt", 10),
        900,
    )?;
    rewrite_verdict_row(&vault, |entries| {
        let axes = serde_json::json!({
            "quality": {"kind":"primary","before":0.4,"after":0.7},
            "safety": {"kind":"floor","before":0.8,"after":0.7},
            "human_minutes": {"kind":"cost","before":0.5,"after":0.6}
        });
        set_row_field(entries, "goal_axes", &Value::from(axes.to_string()));
    });
    assert_eq!(
        skill_edit_verdicts(&vault)
            .expect_err("accepted floor regression is corrupt")
            .kind(),
        ErrorKind::CorruptedIndex
    );
    Ok(())
}

#[test]
fn a_new_goal_floor_revokes_cached_acceptance_before_admission() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let (skill, proposal) = losing_skill_with_proposal(&vault, "oneiron.skill.vector.goal_change");
    let accepted = score_gate_skill_edit_in_cycle(
        &vault,
        &proposal,
        &StubScorer::improving(),
        wake(&vault, "goal-A", 10),
        900,
    )?;
    assert_eq!(accepted.disposition, SkillEditDisposition::Accepted);
    let owner = vector_owner(&vault);
    let revision = set_skill_edit_goal_axes(&vault, &owner, &skill, vector_axes())?;
    assert_ne!(accepted.goal_revision, revision);
    assert_eq!(
        admit_optimized_skill_revision(&vault, &proposal, t(400), 401)
            .expect_err("old permission cannot cross a goal change")
            .kind(),
        ErrorKind::InvalidSkillBody
    );
    assert_eq!(
        stored(&vault, &proposal).lifecycle_status,
        SkillLifecycle::Candidate
    );
    // A gate retry must use the NEW scorer and cannot reuse the old acceptance.
    // The admission refusal closes this proposal; use a second fixture to
    // verify rescore of a still-open accepted candidate.
    let (_other_tmp, other_vault) = temp_vault();
    let (other, other_proposal) =
        losing_skill_with_proposal(&other_vault, "oneiron.skill.vector.rescore");
    let other_accepted = score_gate_skill_edit_in_cycle(
        &other_vault,
        &other_proposal,
        &StubScorer::improving(),
        wake(&other_vault, "goal-C", 20),
        900,
    )?;
    set_skill_edit_goal_axes(
        &other_vault,
        &vector_owner(&other_vault),
        &other,
        vector_axes(),
    )?;
    let rescored = score_gate_skill_edit_in_cycle(
        &other_vault,
        &other_proposal,
        &VectorScorer::new((0.4, 0.9), (0.8, 0.7), (0.5, 0.6)),
        wake(&other_vault, "goal-D", 30),
        901,
    )?;
    assert_eq!(rescored.disposition, SkillEditDisposition::Rejected);
    assert_ne!(rescored.id, other_accepted.id);
    assert_ne!(rescored.goal_revision, other_accepted.goal_revision);
    assert_eq!(
        skill_edit_verdicts_for_proposal(&other_vault, &other_proposal)?.len(),
        2
    );
    Ok(())
}

#[test]
fn authenticated_tradeoff_resolution_approves_rejects_and_refuses_stale_decisions() -> Result<()> {
    for choice in [TradeoffChoice::Approve, TradeoffChoice::Reject] {
        let (_tmp, vault) = temp_vault();
        let (skill, proposal) =
            losing_skill_with_proposal(&vault, "oneiron.skill.vector.resolution");
        let owner = vector_owner(&vault);
        set_skill_edit_goal_axes(&vault, &owner, &skill, vector_axes())?;
        let pending = score_gate_skill_edit_in_cycle(
            &vault,
            &proposal,
            &VectorScorer::new((0.4, 0.8), (0.9, 0.9), (0.7, 0.4)),
            wake(&vault, "resolution", 10),
            900,
        )?;
        assert_eq!(
            pending.disposition,
            SkillEditDisposition::NeedsTradeoffDecision
        );
        let resolved = resolve_skill_edit_tradeoff(
            &vault,
            &proposal,
            pending.id,
            &owner,
            "human-pick:123",
            choice,
            901,
        )?;
        assert_eq!(resolved.goal_axes, pending.goal_axes);
        assert_eq!(
            resolved.tradeoff_resolution.as_ref().unwrap().pending,
            pending.id
        );
        assert_eq!(
            resolved,
            resolve_skill_edit_tradeoff(
                &vault,
                &proposal,
                pending.id,
                &owner,
                "human-pick:123",
                choice,
                902
            )?
        );
        assert_eq!(
            skill_edit_verdicts_for_proposal(&vault, &proposal)?.len(),
            2
        );
        assert!(
            verdict_receipt(&vault, &resolved)
                .fields
                .contains_key("skill_edit_tradeoff_resolution")
        );
        match choice {
            TradeoffChoice::Approve => {
                assert_eq!(resolved.disposition, SkillEditDisposition::AcceptedTradeoff);
                admit_optimized_skill_revision(&vault, &proposal, t(400), 401)?;
                assert_eq!(
                    stored(&vault, &proposal).lifecycle_status,
                    SkillLifecycle::Active
                );
                assert_eq!(
                    resolve_skill_edit_tradeoff(
                        &vault,
                        &proposal,
                        pending.id,
                        &owner,
                        "human-pick:123",
                        choice,
                        903
                    )?,
                    resolved
                );
            }
            TradeoffChoice::Reject => {
                assert_eq!(resolved.disposition, SkillEditDisposition::RejectedTradeoff);
                assert_eq!(
                    stored(&vault, &proposal).approval_status,
                    ClaimApprovalStatus::Rejected
                );
                assert_eq!(
                    admit_optimized_skill_revision(&vault, &proposal, t(400), 401)
                        .expect_err("rejected choice cannot activate")
                        .kind(),
                    ErrorKind::InvalidSkillBody
                );
            }
        }
    }
    for protect in [false, true] {
        let (_tmp, vault) = temp_vault();
        let (skill, proposal) =
            losing_skill_with_proposal(&vault, "oneiron.skill.vector.stale_decision");
        let owner = vector_owner(&vault);
        set_skill_edit_goal_axes(&vault, &owner, &skill, vector_axes())?;
        let pending = score_gate_skill_edit_in_cycle(
            &vault,
            &proposal,
            &VectorScorer::new((0.4, 0.8), (0.9, 0.9), (0.7, 0.4)),
            wake(&vault, "stale", 10),
            900,
        )?;
        if protect {
            let mut marked = stored(&vault, &skill);
            marked.governance_tier = Some(SkillGovernanceTier::Identity);
            vault.update_skill_record(&skill, &marked, t(400), 401)?;
        } else {
            set_skill_edit_goal_axes(&vault, &owner, &skill, vector_axes())?;
        }
        assert_eq!(
            resolve_skill_edit_tradeoff(
                &vault,
                &proposal,
                pending.id,
                &owner,
                "human-pick:stale",
                TradeoffChoice::Approve,
                902
            )
            .expect_err("stale choice cannot authorize")
            .kind(),
            ErrorKind::InvalidSkillBody
        );
        assert_eq!(
            skill_edit_verdicts_for_proposal(&vault, &proposal)?.len(),
            1
        );
        assert_eq!(
            stored(&vault, &proposal).approval_status,
            ClaimApprovalStatus::Proposed
        );
    }
    Ok(())
}

fn successor_goal_proposal(vault: &Vault, target: &EntityId) -> EntityId {
    let id = EntityId::now();
    let mut record = optimizer_proposal_record_citing(
        vault,
        target,
        Value::Array(Vec::new()),
        HAND_CRAFTED_CYCLE,
    );
    record.desc = "Next generation instructions.".to_owned();
    vault
        .put_skill_record(&id, &record, t(300), 301)
        .expect("put successor proposal");
    id
}

#[test]
fn a_tradeoff_scored_by_a_displaced_judge_cannot_be_resolved() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let (skill, proposal) = losing_skill_with_proposal(&vault, "oneiron.skill.vector.displaced");
    let owner = vector_owner(&vault);
    set_skill_edit_goal_axes(&vault, &owner, &skill, vector_axes())?;
    let pending = score_gate_skill_edit_in_cycle(
        &vault,
        &proposal,
        &VectorScorer::new((0.4, 0.8), (0.9, 0.9), (0.7, 0.4)),
        wake(&vault, "displaced", 10),
        900,
    )?;
    assert_eq!(
        pending.disposition,
        SkillEditDisposition::NeedsTradeoffDecision
    );
    assert_eq!(
        supersede_skill_edit_judge(&vault, "fixture-judge@1", "fixture-judge@2")?,
        vec![pending.id]
    );
    assert_eq!(
        resolve_skill_edit_tradeoff(
            &vault,
            &proposal,
            pending.id,
            &owner,
            "human-pick:123",
            TradeoffChoice::Approve,
            901,
        )
        .expect_err("a retired judge's vector is not a permission")
        .kind(),
        ErrorKind::InvalidSkillBody
    );
    assert_eq!(
        skill_edit_verdicts_for_proposal(&vault, &proposal)?.len(),
        1
    );
    assert_eq!(
        stored(&vault, &proposal).lifecycle_status,
        SkillLifecycle::Candidate
    );
    assert_eq!(
        admit_optimized_skill_revision(&vault, &proposal, t(400), 401)
            .expect_err("nothing admits the proposal")
            .kind(),
        ErrorKind::InvalidSkillBody
    );
    Ok(())
}

#[test]
fn inherited_policy_floor_change_revokes_a_cached_acceptance_and_scores_fresh() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let (skill, proposal) = losing_skill_with_proposal(&vault, "oneiron.skill.policy_change");
    let old = score_gate_skill_edit_in_cycle(
        &vault,
        &proposal,
        &StubScorer::improving(),
        wake(&vault, "policy-old", 10),
        900,
    )?;
    assert_eq!(old.disposition, SkillEditDisposition::Accepted);
    put_narrowing_goal_manifest(
        &vault,
        crate::gate::default_policy_manifest_id()?,
        vec![GoalAxisSpec {
            name: "safety".into(),
            kind: GoalAxisKind::Floor,
        }],
    )?;
    let policy = crate::gate::resolve_policy_manifest(&vault.store, &vault.store.env.read_txn()?)?;
    assert!(
        policy.skill_edit_goal_policies().is_some(),
        "policy diagnostics: {:?}; contributions: {:?}",
        policy.diagnostics(),
        vault.manifest_contributions()?
    );
    assert_eq!(
        admit_optimized_skill_revision(&vault, &proposal, t(400), 401)
            .expect_err("inherited floor change revokes old acceptance")
            .kind(),
        ErrorKind::InvalidSkillBody
    );
    assert_eq!(
        stored(&vault, &proposal).lifecycle_status,
        SkillLifecycle::Candidate
    );
    let fresh = optimizer_proposal_citing(&vault, &skill, Value::Array(Vec::new()));
    let new = score_gate_skill_edit_in_cycle(
        &vault,
        &fresh,
        &VectorScorer::new((0.4, 0.9), (0.8, 0.7), (0.5, 0.6)).with_axes(vec![
            GoalAxisSpec {
                name: "held_out".into(),
                kind: GoalAxisKind::Primary,
            },
            GoalAxisSpec {
                name: "safety".into(),
                kind: GoalAxisKind::Floor,
            },
        ]),
        wake(&vault, "policy-new", 20),
        902,
    )?;
    assert_eq!(new.disposition, SkillEditDisposition::Rejected);
    assert_ne!(new.goal_revision, old.goal_revision);
    assert!(new.goal_axes["safety"].after < new.goal_axes["safety"].before);
    Ok(())
}

fn seed_successor_outcome(vault: &Vault, skill: &EntityId) -> Result<()> {
    let receipt = (0u64..)
        .map(|n| format!("portable-goal-reserve:{n}"))
        .find(|id| receipt_is_held_out(skill, id))
        .expect("held-out id exists");
    let mut encoded = Vec::new();
    rmpv::encode::write_value(
        &mut encoded,
        &Value::Map(vec![
            (Value::from("schema_version"), Value::from(1u64)),
            (Value::from("win"), Value::Boolean(false)),
            (Value::from("at"), Value::from(500u64)),
        ]),
    )
    .expect("encode outcome");
    vault.with_write_txn(|txn| {
        let mut key = b"skill_reliability:outcome:v1:".to_vec();
        key.extend_from_slice(skill.as_bytes());
        key.extend_from_slice(receipt.as_bytes());
        vault.store.vault_meta.put(txn, &key, &encoded)?;
        Ok(())
    })
}

#[test]
fn portable_goal_survives_replayed_activation_and_first_active_rematerialization() -> Result<()> {
    for first_active in [false, true] {
        let (_origin_tmp, origin) = temp_vault();
        let (a, b) = losing_skill_with_proposal(&origin, "oneiron.skill.portable_goal");
        let candidate = stored(&origin, &b);
        let mut active = candidate.clone();
        active.approval_status = ClaimApprovalStatus::Approved;
        active.lifecycle_status = SkillLifecycle::Active;
        let (_receiver_tmp, receiver) = temp_vault();
        let a_body = crate::skill::encode_skill_record(&stored(&origin, &a))?;
        receiver
            .batch()
            .put_replicated(&a, ENTITY_TYPE_SKILL, t(400), 401, &a_body)
            .commit()?;
        let owner = vector_owner(&receiver);
        let original = set_skill_edit_goal_axes(&receiver, &owner, &a, vector_axes())?;
        if !first_active {
            let candidate_body = crate::skill::encode_skill_record(&candidate)?;
            receiver
                .batch()
                .put_replicated(&b, ENTITY_TYPE_SKILL, t(402), 403, &candidate_body)
                .commit()?;
            let active_body = crate::skill::encode_skill_record(&active)?;
            receiver
                .batch()
                .put_replicated(&b, ENTITY_TYPE_SKILL, t(404), 405, &active_body)
                .commit()?;
            assert!(receiver.delete_entity(&a)?);
        } else {
            // The receiver never saw B before and A has already been erased.
            assert!(receiver.delete_entity(&a)?);
            let active_body = crate::skill::encode_skill_record(&active)?;
            receiver
                .batch()
                .put_replicated(&b, ENTITY_TYPE_SKILL, t(404), 405, &active_body)
                .commit()?;
            receiver
                .batch()
                .put_replicated(&b, ENTITY_TYPE_SKILL, t(406), 407, &active_body)
                .commit()?;
        }
        assert_eq!(
            stored(&receiver, &b).lifecycle_status,
            SkillLifecycle::Active
        );
        seed_successor_outcome(&receiver, &b)?;
        let c = successor_goal_proposal(&receiver, &b);
        let lost_floor = score_gate_skill_edit_in_cycle(
            &receiver,
            &c,
            &VectorScorer::new((0.4, 0.9), (0.8, 0.7), (0.5, 0.6)).with_baseline(DRAFTED_DESC),
            wake(&receiver, "portable-c", 10),
            900,
        )?;
        assert_eq!(lost_floor.disposition, SkillEditDisposition::Rejected);
        assert!(lost_floor.goal_axes["safety"].after < lost_floor.goal_axes["safety"].before);
        let d = successor_goal_proposal(&receiver, &b);
        let pending = score_gate_skill_edit_in_cycle(
            &receiver,
            &d,
            &VectorScorer::new((0.4, 0.9), (0.8, 0.8), (0.6, 0.5)).with_baseline(DRAFTED_DESC),
            wake(&receiver, "portable-d", 20),
            901,
        )?;
        assert_eq!(
            pending.disposition,
            SkillEditDisposition::NeedsTradeoffDecision
        );
        let changed = set_skill_edit_goal_axes(&receiver, &owner, &b, vector_axes())?;
        assert_ne!(original, changed);
        assert_eq!(
            resolve_skill_edit_tradeoff(
                &receiver,
                &d,
                pending.id,
                &owner,
                "pick:stale",
                TradeoffChoice::Approve,
                902
            )
            .expect_err("goal change revokes pending tradeoff")
            .kind(),
            ErrorKind::InvalidSkillBody
        );
        let e = successor_goal_proposal(&receiver, &b);
        let accepted = score_gate_skill_edit_in_cycle(
            &receiver,
            &e,
            &VectorScorer::new((0.4, 0.8), (0.8, 0.8), (0.5, 0.6)).with_baseline(DRAFTED_DESC),
            wake(&receiver, "portable-e", 30),
            903,
        )?;
        assert_eq!(accepted.disposition, SkillEditDisposition::Accepted);
        set_skill_edit_goal_axes(&receiver, &owner, &b, vector_axes())?;
        assert_eq!(
            admit_optimized_skill_revision(&receiver, &e, t(410), 411)
                .expect_err("goal change revokes acceptance")
                .kind(),
            ErrorKind::InvalidSkillBody
        );
    }
    Ok(())
}

#[test]
fn optimizer_goal_identity_is_strict_on_birth_update_and_same_id_recreate() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let (a, b) = losing_skill_with_proposal(&vault, "oneiron.skill.goal_guard");
    let born = stored(&vault, &b);
    let mut missing = born.clone();
    missing.provenance = without_provenance(&missing, GOAL_ID_KEY);
    let mut malformed = born.clone();
    let Value::Map(entries) = &mut malformed.provenance else {
        panic!("provenance")
    };
    for (name, value) in entries {
        if name.as_str() == Some(GOAL_ID_KEY) {
            *value = Value::from("not-an-id");
        }
    }
    let mut conflicting = born.clone();
    let Value::Map(entries) = &mut conflicting.provenance else {
        panic!("provenance")
    };
    for (name, value) in entries {
        if name.as_str() == Some(GOAL_ID_KEY) {
            *value = Value::from(EntityId::now().to_hex());
        }
    }
    let mut duplicate = born.clone();
    let Value::Map(entries) = &mut duplicate.provenance else {
        panic!("provenance")
    };
    entries.push((Value::from(GOAL_ID_KEY), Value::from(a.to_hex())));
    // The public codec itself refuses duplicate provenance keys before a body
    // can reach any write door. The other cases exercise the shared guard.
    assert_eq!(
        crate::skill::encode_skill_record(&duplicate)
            .expect_err("duplicate goal identity cannot encode")
            .kind(),
        ErrorKind::InvalidSkillBody
    );
    for row in [&missing, &malformed, &conflicting] {
        let fresh = EntityId::now();
        let body = crate::skill::encode_skill_record(row)?;
        assert_eq!(
            vault
                .batch()
                .put(&fresh, ENTITY_TYPE_SKILL, t(400), 401, &body)
                .commit()
                .expect_err("local birth must bind the parent goal")
                .kind(),
            ErrorKind::InvalidSkillBody
        );
        assert_eq!(
            vault
                .batch()
                .put_replicated(&fresh, ENTITY_TYPE_SKILL, t(400), 401, &body)
                .commit()
                .expect_err("known predecessor constrains replay")
                .kind(),
            ErrorKind::InvalidSkillBody
        );
        assert!(vault.get_skill_record(&fresh)?.is_none());
        assert_eq!(
            vault
                .update_skill_record(&b, row, t(402), 403)
                .expect_err("goal identity is immutable on update")
                .kind(),
            ErrorKind::InvalidSkillBody
        );
    }
    let saved = crate::skill::encode_skill_record(&born)?;
    // Internal removal, as in the birth-marker tests: a user delete keeps a
    // shell and an owner hard delete retires the ID, so neither re-presents it.
    vault.batch().delete(&b).commit()?;
    assert!(vault.get_skill_record(&b)?.is_none(), "the body is gone");
    assert_eq!(
        vault
            .batch()
            .put(
                &b,
                ENTITY_TYPE_SKILL,
                t(404),
                405,
                &crate::skill::encode_skill_record(&conflicting)?
            )
            .commit()
            .expect_err("delete and recreate cannot rebind goal")
            .kind(),
        ErrorKind::InvalidSkillBody
    );
    vault
        .batch()
        .put(&b, ENTITY_TYPE_SKILL, t(406), 407, &saved)
        .commit()?;
    assert_eq!(SkillGoalId::of(&b, &stored(&vault, &b))?.entity(), a);
    Ok(())
}

#[test]
fn orphaned_replay_checks_erased_parent_origin_before_accepting_a_goal() -> Result<()> {
    for erase_root in [false, true] {
        let (_tmp, vault) = temp_vault();
        let (a, b) = losing_skill_with_proposal(&vault, "oneiron.skill.retained_parent_goal");
        let owner = vector_owner(&vault);
        set_skill_edit_goal_axes(&vault, &owner, &a, vector_axes())?;
        score_gate_skill_edit_in_cycle(
            &vault,
            &b,
            &VectorScorer::new((0.4, 0.8), (0.8, 0.8), (0.5, 0.6)),
            wake(&vault, "retained-parent", 10),
            900,
        )?;
        admit_optimized_skill_revision(&vault, &b, t(400), 401)?;
        let c = EntityId::now();
        let mut settled = optimizer_proposal_record_citing(
            &vault,
            &b,
            Value::Array(Vec::new()),
            HAND_CRAFTED_CYCLE,
        );
        settled.approval_status = ClaimApprovalStatus::Approved;
        settled.lifecycle_status = SkillLifecycle::Active;
        assert!(vault.delete_entity(&b)?);
        if erase_root {
            assert!(vault.delete_entity(&a)?);
        }
        let mut contradictory = settled.clone();
        let Value::Map(entries) = &mut contradictory.provenance else {
            panic!("provenance map")
        };
        for (name, value) in entries {
            if name.as_str() == Some(GOAL_ID_KEY) {
                *value = Value::from(EntityId::now().to_hex());
            }
        }
        let bad_body = crate::skill::encode_skill_record(&contradictory)?;
        assert_eq!(
            vault
                .batch()
                .put_replicated(&c, ENTITY_TYPE_SKILL, t(402), 403, &bad_body)
                .commit()
                .expect_err("retained B origin knows C's proposed ruler is wrong")
                .kind(),
            ErrorKind::InvalidSkillBody
        );
        assert!(vault.get_skill_record(&c)?.is_none());
        let marker_key = gate::optimizer_origin_marker_key(&b);
        let retained = {
            let txn = vault.store.env.read_txn()?;
            vault
                .store
                .vault_meta
                .get(&txn, &marker_key)?
                .expect("B retains a birth marker")
                .to_vec()
        };
        vault.with_write_txn(|txn| {
            vault
                .store
                .vault_meta
                .put(txn, &marker_key, b"invalid retained origin")?;
            Ok(())
        })?;
        let good_body = crate::skill::encode_skill_record(&settled)?;
        assert_eq!(
            vault
                .batch()
                .put_replicated(&c, ENTITY_TYPE_SKILL, t(404), 405, &good_body)
                .commit()
                .expect_err("malformed retained parent fact fails closed")
                .kind(),
            ErrorKind::CorruptedIndex
        );
        assert!(vault.get_skill_record(&c)?.is_none());
        vault.with_write_txn(|txn| {
            vault.store.vault_meta.put(txn, &marker_key, &retained)?;
            Ok(())
        })?;
        // The same new id with the correct portable goal still materializes.
        vault
            .batch()
            .put_replicated(&c, ENTITY_TYPE_SKILL, t(404), 405, &good_body)
            .commit()?;
        assert_eq!(SkillGoalId::of(&c, &stored(&vault, &c))?.entity(), a);
        seed_successor_outcome(&vault, &c)?;
        let d = successor_goal_proposal(&vault, &c);
        let floor_loss = score_gate_skill_edit_in_cycle(
            &vault,
            &d,
            &VectorScorer::new((0.4, 0.9), (0.8, 0.7), (0.5, 0.6)).with_baseline(DRAFTED_DESC),
            wake(&vault, "retained-child", 20),
            901,
        )?;
        assert_eq!(floor_loss.disposition, SkillEditDisposition::Rejected);
        assert!(floor_loss.goal_axes["safety"].after < floor_loss.goal_axes["safety"].before);
    }
    Ok(())
}

#[test]
fn replacing_candidate_judge_retains_scores_but_removes_standing_acceptance() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let (_skill, proposal) = losing_skill_with_proposal(&vault, "judge.swap.fixture");
    let first = StubScorer::improving();
    let accepted = score_gate_skill_edit_with_scorer(&vault, &proposal, &first)?;
    assert!(accepted.accepted);
    assert_eq!(accepted.judge_revision.as_deref(), Some("fixture-judge@1"));
    assert_eq!(
        verdict_receipt(&vault, &accepted).fields["skill_edit_judge_revision"],
        "fixture-judge@1"
    );
    let marked = supersede_skill_edit_judge(&vault, "fixture-judge@1", "fixture-judge@2")?;
    assert!(marked.contains(&accepted.id));
    let historical = skill_edit_verdict(&vault, &proposal)?.unwrap();
    assert_eq!(
        (historical.before, historical.after),
        (accepted.before, accepted.after)
    );
    assert_eq!(
        historical.displaced_by_revision.as_deref(),
        Some("fixture-judge@2")
    );
    let receipt = verdict_receipt(&vault, &accepted);
    assert_eq!(
        receipt.fields["skill_edit_judge_displaced_by"],
        "fixture-judge@2"
    );
    assert!(admit_optimized_skill_revision(&vault, &proposal, t(999), 999).is_err());
    assert_eq!(
        stored(&vault, &proposal).lifecycle_status,
        SkillLifecycle::Candidate
    );
    let replacement = StubScorer::improving().with_revision("fixture-judge@2");
    let ruled = score_gate_skill_edit_with_scorer(&vault, &proposal, &replacement)?;
    assert_ne!(ruled.id, accepted.id);
    assert!(ruled.accepted);
    assert_eq!(ruled.judge_revision.as_deref(), Some("fixture-judge@2"));
    assert_eq!(replacement.evidence().len(), 2);
    assert_eq!(
        supersede_skill_edit_judge(&vault, "fixture-judge@1", "fixture-judge@2")?,
        marked
    );
    assert!(supersede_skill_edit_judge(&vault, "fixture-judge@1", "fixture-judge@3").is_err());
    Ok(())
}

// ─── OF-495 goal-axis measurements ──────────────────────────────────────

struct AxisJudge {
    events: RefCell<Vec<String>>,
    bad_offline: bool,
    bad_minutes: bool,
}

impl AxisJudge {
    fn new() -> Self {
        Self {
            events: RefCell::new(Vec::new()),
            bad_offline: false,
            bad_minutes: false,
        }
    }
}

impl GoalAxisScorer for AxisJudge {
    fn offline_score(&self, axis: &str, case: &HeldOutReplayCase<'_>) -> Result<f64> {
        assert!(!case.held_out_receipts.is_empty());
        assert!(
            case.held_out_receipts
                .iter()
                .all(|receipt| receipt_is_held_out(&case.skill, receipt))
        );
        self.events
            .borrow_mut()
            .push(format!("offline:{axis}:{}", case.version));
        Ok(if self.bad_offline {
            f64::NAN
        } else if case.version == FIXTURE_VERSION {
            0.4
        } else {
            0.8
        })
    }

    fn human_minutes(&self, case: &HeldOutReplayCase<'_>) -> Result<f64> {
        self.events
            .borrow_mut()
            .push(format!("minutes:{}", case.version));
        Ok(if self.bad_minutes {
            -1.0
        } else if case.version == FIXTURE_VERSION {
            3.5
        } else {
            1.25
        })
    }
}

struct AxisBanditStub {
    events: RefCell<Vec<AxisArm>>,
    separated: bool,
    invalid_bound: bool,
}

impl AxisBanditStub {
    fn new(separated: bool) -> Self {
        Self {
            events: RefCell::new(Vec::new()),
            separated,
            invalid_bound: false,
        }
    }
}

impl GoalAxisBandit for AxisBanditStub {
    fn pull(&self, _axis: &str, arm: AxisArm) -> Result<OnlineAxisSample> {
        self.events.borrow_mut().push(arm);
        Ok(OnlineAxisSample {
            success: arm == AxisArm::Candidate,
            human_minutes: if arm == AxisArm::Candidate { 0.25 } else { 0.5 },
        })
    }

    fn confidence_interval(
        &self,
        _axis: &str,
        arm: AxisArm,
        _wins: u32,
        _pulls: u32,
    ) -> Result<ConfidenceInterval> {
        Ok(if self.invalid_bound {
            ConfidenceInterval {
                lower: f64::NAN,
                upper: 1.0,
            }
        } else if self.separated {
            match arm {
                AxisArm::Incumbent => ConfidenceInterval {
                    lower: 0.1,
                    upper: 0.3,
                },
                AxisArm::Candidate => ConfidenceInterval {
                    lower: 0.7,
                    upper: 0.9,
                },
            }
        } else {
            ConfidenceInterval {
                lower: 0.2,
                upper: 0.8,
            }
        })
    }
}

fn goal_axis_plan(pulls_per_axis: u32) -> GoalAxisPlan {
    GoalAxisPlan {
        offline: vec!["quality".to_owned(), "safety".to_owned()],
        online: vec!["world_outcome".to_owned()],
        pulls_per_axis,
    }
}

#[test]
fn goal_axes_score_held_out_first_then_bounded_live_slice_with_human_cost() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let (skill, incumbent) = put_standard_active(&vault, "goal-axis-test");
    attribute_defects_across_split(&vault, &skill, "goal-axis-test");
    let mut candidate = incumbent.clone();
    candidate.version = "2.0.0".to_owned();
    candidate.desc = DRAFTED_DESC.to_owned();
    let judge = AxisJudge::new();
    let bandit = AxisBanditStub::new(true);
    let report = measure_goal_axes(
        &vault,
        skill,
        &incumbent,
        &candidate,
        &goal_axis_plan(6),
        &judge,
        &bandit,
    )?;
    assert_eq!(report.offline.len(), 2);
    assert_eq!(
        report.offline[0].1,
        AxisScores {
            before: 0.4,
            after: 0.8
        }
    );
    assert_eq!(
        report.human_minutes,
        AxisScores {
            before: 4.0,
            after: 1.5
        }
    );
    assert_eq!(report.online[0].outcome, OnlineAxisOutcome::CandidateBetter);
    assert_eq!(
        report.online[0].human_minutes,
        AxisScores {
            before: 0.5,
            after: 0.25
        }
    );
    assert_eq!(
        (report.online[0].before_pulls, report.online[0].after_pulls),
        (1, 1)
    );
    assert_eq!(
        bandit.events.borrow().as_slice(),
        &[AxisArm::Incumbent, AxisArm::Candidate]
    );
    assert_eq!(
        judge.events.borrow().as_slice(),
        &[
            "offline:quality:1.0.0",
            "offline:quality:2.0.0",
            "offline:safety:1.0.0",
            "offline:safety:2.0.0",
            "minutes:1.0.0",
            "minutes:2.0.0",
        ]
    );
    assert_eq!(report.held_out_receipts, held_out_receipts(&vault, &skill)?);
    assert!(
        report
            .held_out_receipts
            .iter()
            .all(|receipt| !dev_receipts(&vault, &skill).unwrap().contains(receipt))
    );
    Ok(())
}

#[test]
fn displaced_candidate_judge_cannot_commit_a_score_started_before_replacement() -> Result<()> {
    struct SlowOld<'a> {
        vault: &'a Vault,
        displaced: std::cell::Cell<bool>,
    }
    impl HeldOutReplayScorer for SlowOld<'_> {
        fn judge_revision(&self) -> &str {
            "old-candidate@1"
        }
        fn score(&self, case: &HeldOutReplayCase<'_>) -> Result<f32> {
            if !self.displaced.replace(true) {
                // The scorer runs outside the write txn. Replacement commits
                // before this callback hands its stale answer back.
                supersede_skill_edit_judge(self.vault, "old-candidate@1", "new-candidate@2")?;
            }
            Ok(if case.instructions == TARGET_DESC {
                0.4
            } else {
                0.8
            })
        }
        fn structural_audit(&self, _: &str, _: &str) -> Result<f32> {
            Ok(0.5)
        }
        fn blind_preference(&self, _: &str, _: &[String]) -> Result<Vec<BlindPreference>> {
            Ok(vec![BlindPreference {
                pair_ref: "race".into(),
                preferred: PreferredResponse::First,
            }])
        }
        fn contrastive_audit(
            &self,
            _: &HeldOutReplayCase<'_>,
            _: &[BlindPreference],
        ) -> Result<f32> {
            Ok(0.5)
        }
        fn predict_task_success(&self, case: &HeldOutReplayCase<'_>) -> Result<Vec<f32>> {
            Ok(vec![0.5; case.held_out_receipts.len()])
        }
    }
    let (_tmp, vault) = temp_vault();
    let (_skill, proposal) = losing_skill_with_proposal(&vault, "judge.inflight");
    let old = SlowOld {
        vault: &vault,
        displaced: std::cell::Cell::new(false),
    };
    assert!(score_gate_skill_edit_with_scorer(&vault, &proposal, &old).is_err());
    assert!(skill_edit_verdict(&vault, &proposal)?.is_none());
    assert!(admit_optimized_skill_revision(&vault, &proposal, t(900), 900).is_err());
    assert!(score_gate_skill_edit_with_scorer(&vault, &proposal, &old).is_err());
    let new = StubScorer::improving().with_revision("new-candidate@2");
    assert!(score_gate_skill_edit_with_scorer(&vault, &proposal, &new)?.accepted);
    Ok(())
}

#[test]
fn context_recipe_workflow_keeps_manifest_attribution_after_improver_edit() -> Result<()> {
    struct RecipeScorer;
    impl HeldOutReplayScorer for RecipeScorer {
        fn judge_revision(&self) -> &str {
            "fixture-recipe-judge@1"
        }
        fn score(&self, case: &HeldOutReplayCase<'_>) -> Result<f32> {
            Ok(if case.instructions == DRAFTED_DESC {
                0.75
            } else {
                0.40
            })
        }
        fn structural_audit(&self, _task: &str, _instructions: &str) -> Result<f32> {
            Ok(0.5)
        }
        fn blind_preference(
            &self,
            _task: &str,
            _receipts: &[String],
        ) -> Result<Vec<BlindPreference>> {
            Ok(vec![BlindPreference {
                pair_ref: "fixture-pair".to_owned(),
                preferred: PreferredResponse::First,
            }])
        }
        fn contrastive_audit(
            &self,
            _case: &HeldOutReplayCase<'_>,
            _blind: &[BlindPreference],
        ) -> Result<f32> {
            Ok(0.5)
        }
        fn predict_task_success(&self, case: &HeldOutReplayCase<'_>) -> Result<Vec<f32>> {
            Ok(vec![0.5; case.held_out_receipts.len()])
        }
    }
    let (_tmp, vault) = temp_vault();
    let skill = EntityId::now();
    let mut recipe = record(
        "fixture.context-recipe",
        Some(SkillGovernanceTier::Standard),
        None,
    )
    .with_role(crate::skill::SkillRole::Workflow, None);
    recipe.desc = "Load task index, then the matched sources; shed examples first.".into();
    let files = vec![
        HubFile::new(
            "SKILL.md",
            format!(
                "---\nname: {}\ndescription: {}\nversion: {}\nrole: workflow\n---\n{}\n",
                recipe.skill_id, recipe.desc, recipe.version, recipe.desc
            )
            .into_bytes(),
        ),
        HubFile::new("references/ordering.txt", b"context order fixture".to_vec()),
    ];
    recipe.content_hash = Some(crate::skill::canonical_skill_tree_hash(
        files
            .iter()
            .map(|file| (file.path.as_str(), file.content.as_slice())),
    )?);
    let mut package = HubPackage::new(recipe.clone(), files, SkillCapabilitySurface::default());
    package.format = crate::skill_hub::SkillPackageFormat::Native;
    vault.with_write_txn(|txn| {
        vault.put_skill_record_in_txn(txn, &skill, &recipe, t(10), 11)?;
        vault.persist_hub_package_in_txn(txn, &skill, &package)
    })?;
    let mut before = recipe;
    before.lifecycle_status = SkillLifecycle::Active;
    vault.update_skill_record(&skill, &before, t(12), 13)?;
    let evidence = attribute_defects(&vault, &skill, &before.skill_id, 5);
    let outcome = run(&vault, &StubAuthor::editing()).expect("recipe improver");
    let proposal_id = outcome.proposal.expect("improver drafts a recipe edit");
    let proposed = stored(&vault, &proposal_id);
    assert_eq!(proposed.role, crate::skill::SkillRole::Workflow);
    assert_eq!(proposed.lifecycle_status, SkillLifecycle::Candidate);
    assert_eq!(proposed.approval_status, ClaimApprovalStatus::Proposed);
    assert_eq!(proposed.skill_id, before.skill_id);
    assert!(
        matches!(&proposed.provenance, Value::Map(entries) if entries.iter().any(|(key, value)|
        key.as_str() == Some(PROVENANCE_OPTIMIZE_RECEIPTS_KEY)
        && value.as_array().is_some_and(|rows| rows.iter().any(|row| evidence.iter().any(|r| row.as_str() == Some(r))))))
    );
    score_gate_skill_edit_in_cycle(
        &vault,
        &proposal_id,
        &RecipeScorer,
        wake(&vault, "recipe-wake", 10),
        900,
    )
    .expect("recipe held-out score");
    admit_optimized_skill_revision(&vault, &proposal_id, t(400), 401).expect("recipe admission");
    vault.supersede_skill_record(&skill, &proposal_id, t(404), 405)?;
    let queue = AttemptQueue::new(&vault);
    let EnqueueOutcome::Enqueued(attempt) = queue.enqueue(EnqueueAttempt {
        kind: "recipe.attempt".into(),
        payload: vec![],
        dedupe_key: None,
        run_id: None,
        now: 500,
    })?
    else {
        panic!("fresh recipe attempt")
    };
    let ClaimOutcome::Claimed(leased) = queue.claim(ClaimAttempt {
        lease_owner: "recipe-worker".into(),
        now: 501,
    })?
    else {
        panic!("leased recipe attempt")
    };
    let loaded = vault.load_attempt_skill_pack(
        attempt.id,
        &proposal_id,
        "recipe-worker",
        leased.attempt_count,
        "fixture-recipe-model@1",
        501,
    )?;
    let source = loaded
        .source_files
        .expect("source-backed recipe stays source-backed");
    assert!(source.iter().any(|file| file.path == "SKILL.md"
        && String::from_utf8_lossy(&file.content).contains(DRAFTED_DESC)));
    assert!(
        source
            .iter()
            .any(|file| file.path == "references/ordering.txt"
                && file.content == b"context order fixture")
    );
    assert!(matches!(
        queue.complete(CompleteAttempt {
            id: attempt.id,
            lease_owner: "recipe-worker".into(),
            attempt_count: leased.attempt_count,
            now: 502,
        })?,
        CompleteOutcome::Completed(_)
    ));
    let receipt = attempt_pack_receipt_id(&attempt.id);
    record_skill_contributing_win(&vault, &proposal_id, &receipt, 503)?;
    assert!(crate::skill_reliability::skill_reliability_posterior(&vault, &proposal_id)?.is_none());
    // The attributed outcome is held under the NEW skill entity and exact
    // revision, never copied from the previous recipe's receipt history.
    assert_eq!(
        crate::skill_reliability::attributed_outcome_receipts(
            &vault,
            &vault.store.env.read_txn()?,
            &proposal_id
        )?,
        vec![receipt]
    );
    Ok(())
}

// ONE-2115: a pending tradeoff climbs rule → Jev band → responsible A/B.
fn tradeoff_owner(vault: &Vault) -> crate::consent::AuthenticatedOwner {
    let person = EntityId::now();
    vault
        .put_entity(&person, ENTITY_TYPE_PERSON, t(1), 1, b"responsible")
        .unwrap();
    vault
        .authenticate_owner(
            person,
            &person.to_hex(),
            true,
            crate::store::GateDecisionId::now(),
        )
        .unwrap()
}

const LADDER_BAND: crate::llm::decision::DecisionBand = crate::llm::decision::DecisionBand {
    low: 0.35,
    high: 0.65,
};

/// The signature [`LadderScorer`] produces: both primaries gain, cost loses.
fn quality_for_minutes(choice: TradeoffChoice) -> TradeoffRule {
    TradeoffRule {
        gains: ["held_out".into(), "quality".into()].into(),
        losses: ["human_minutes".into()].into(),
        choice,
    }
}

fn ladder_goal(
    vault: &Vault,
    owner: &crate::consent::AuthenticatedOwner,
    skill: &EntityId,
    rules: Vec<TradeoffRule>,
) -> Result<String> {
    set_skill_edit_goal_axes(vault, owner, skill, vector_axes())?;
    set_skill_tradeoff_preferences(vault, owner, skill, rules, LADDER_BAND)
}

fn axes_with_minutes_floor() -> Vec<GoalAxisSpec> {
    let mut axes = vector_axes();
    for axis in &mut axes {
        if axis.name == "human_minutes" {
            axis.kind = GoalAxisKind::Floor;
        }
    }
    axes
}

/// A vector judge on [`vector_axes`] with a Jev seam. By default both primaries
/// gain and the cost axis loses; `inverted` swaps them.
struct LadderScorer {
    jev: Option<(f64, bool)>, // confidence, corrupt question binding
    choice: TradeoffChoice,
    baseline: &'static str,
    inverted: bool,
    floor_loss: bool,
    axes: Vec<GoalAxisSpec>,
    callbacks: RefCell<usize>,
    jev_calls: RefCell<usize>,
}

impl LadderScorer {
    fn new(jev: Option<(f64, bool)>) -> Self {
        Self {
            jev,
            choice: TradeoffChoice::Approve,
            baseline: TARGET_DESC,
            inverted: false,
            floor_loss: false,
            axes: vector_axes(),
            callbacks: RefCell::new(0),
            jev_calls: RefCell::new(0),
        }
    }
    fn with_baseline(mut self, baseline: &'static str) -> Self {
        self.baseline = baseline;
        self
    }
    fn with_axes(mut self, axes: Vec<GoalAxisSpec>) -> Self {
        self.axes = axes;
        self
    }
    fn called(&self) {
        *self.callbacks.borrow_mut() += 1;
    }
}

impl HeldOutReplayScorer for LadderScorer {
    fn judge_revision(&self) -> &str {
        "fixture-judge@1"
    }
    fn score(&self, _: &HeldOutReplayCase<'_>) -> Result<f32> {
        panic!("a multi-axis scorer cannot fall back to a scalar")
    }
    fn goal_axes(&self, _: &HeldOutReplayCase<'_>) -> Result<Vec<GoalAxisSpec>> {
        self.called();
        Ok(self.axes.clone())
    }
    fn score_goal_axis(&self, case: &HeldOutReplayCase<'_>, axis: &GoalAxisSpec) -> Result<f32> {
        self.called();
        let (before, after) = match (axis.name.as_str(), self.inverted) {
            ("held_out" | "quality", false) | ("human_minutes", true) => (0.4, 0.75),
            ("held_out" | "quality", true) | ("human_minutes", false) => (0.75, 0.4),
            ("safety", _) if self.floor_loss => (0.8, 0.7),
            ("safety", _) => (0.8, 0.8),
            _ => panic!("unknown axis"),
        };
        Ok(if case.instructions == self.baseline {
            before
        } else {
            after
        })
    }
    fn structural_audit(&self, _: &str, _: &str) -> Result<f32> {
        self.called();
        Ok(0.5)
    }
    fn blind_preference(&self, _: &str, _: &[String]) -> Result<Vec<BlindPreference>> {
        self.called();
        Ok(vec![BlindPreference {
            pair_ref: "pair".into(),
            preferred: PreferredResponse::First,
        }])
    }
    fn contrastive_audit(&self, _: &HeldOutReplayCase<'_>, _: &[BlindPreference]) -> Result<f32> {
        self.called();
        Ok(0.5)
    }
    fn predict_task_success(&self, case: &HeldOutReplayCase<'_>) -> Result<Vec<f32>> {
        self.called();
        Ok(vec![0.5; case.held_out_receipts.len()])
    }
    fn jev_tradeoff(&self, question: &SkillTradeoffQuestion) -> Result<Option<JevTradeoffVerdict>> {
        self.called();
        *self.jev_calls.borrow_mut() += 1;
        self.jev
            .map(|(probability, corrupt)| {
                Ok(JevTradeoffVerdict {
                    question_digest: if corrupt {
                        "0".repeat(64)
                    } else {
                        question.digest()?
                    },
                    choice: self.choice,
                    probability,
                    pin: crate::llm::decision::ProviderPin {
                        rung: crate::llm::decision::DecisionRung::SystemOne,
                        model: "jev".into(),
                        version: "pinned-1".into(),
                    },
                })
            })
            .transpose()
    }
}

#[test]
fn jev_band_is_bound_and_only_outside_band_settles() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let (skill, proposal) = losing_skill_with_proposal(&vault, "oneiron.skill.tradeoff.jev");
    let owner = tradeoff_owner(&vault);
    ladder_goal(&vault, &owner, &skill, Vec::new())?;
    let bad = LadderScorer::new(Some((0.95, true)));
    assert!(
        score_gate_skill_edit_in_cycle(
            &vault,
            &proposal,
            &bad,
            wake(&vault, "tradeoff-bad", 10),
            900
        )
        .is_err()
    );
    assert!(skill_edit_verdict(&vault, &proposal)?.is_none());
    let good = LadderScorer::new(Some((0.95, false)));
    let decided = score_gate_skill_edit_in_cycle(
        &vault,
        &proposal,
        &good,
        wake(&vault, "tradeoff-good", 20),
        901,
    )?;
    assert_eq!(decided.disposition, SkillEditDisposition::AcceptedTradeoff);
    let jev = decided.tradeoff_jev.as_ref().unwrap();
    assert_eq!(jev.pin.model, "jev");
    let resolution = decided.tradeoff_resolution.as_ref().unwrap();
    assert_eq!(resolution.rung, TradeoffRung::Jev);
    assert_eq!(resolution.evidence, jev.question_digest);
    assert_eq!(resolution.authentication, "jev@pinned-1");
    assert_eq!(
        skill_edit_verdict(&vault, &proposal)?.unwrap(),
        decided,
        "the Jev rung round-trips through the ledger"
    );
    assert!(
        verdict_receipt(&vault, &decided)
            .fields
            .contains_key("skill_edit_tradeoff_jev")
    );
    assert!(skill_tradeoff_ask(&vault, &proposal)?.is_none());
    Ok(())
}

#[test]
fn responsible_pick_is_durable_and_settles_the_next_axis_tie() -> Result<()> {
    let (tmp, vault) = temp_vault();
    let (skill, proposal) = losing_skill_with_proposal(&vault, "oneiron.skill.tradeoff.ask");
    let owner = tradeoff_owner(&vault);
    ladder_goal(&vault, &owner, &skill, Vec::new())?;
    let scorer = LadderScorer::new(Some((0.5, false)));
    let first = score_gate_skill_edit_in_cycle(
        &vault,
        &proposal,
        &scorer,
        wake(&vault, "tradeoff-ask", 10),
        900,
    )?;
    assert_eq!(
        first.disposition,
        SkillEditDisposition::NeedsTradeoffDecision
    );
    assert_eq!(first.tradeoff_jev.as_ref().unwrap().pin.model, "jev");
    let ask = skill_tradeoff_ask(&vault, &proposal)?.unwrap();
    assert_eq!(ask.pending, first.id);
    assert_eq!(ask.question.responsible, owner.actor());
    assert_eq!(ask.question.proposal, proposal);
    assert_eq!(ask.jev, first.tradeoff_jev);
    let ask_digest = ask.question.digest()?;
    let stranger = tradeoff_owner(&vault);
    assert!(
        settle_skill_tradeoff_ask(
            &vault,
            &stranger,
            &proposal,
            &ask_digest,
            TradeoffChoice::Approve,
            901
        )
        .is_err()
    );
    assert_eq!(skill_tradeoff_ask(&vault, &proposal)?.unwrap(), ask);
    // Re-delivery returns the exact ruling without repeating any scorer
    // callback, appending a verdict, or creating another question.
    let callbacks = *scorer.callbacks.borrow();
    let history = skill_edit_verdicts_for_proposal(&vault, &proposal)?;
    let receipt_count = || -> Result<usize> {
        Ok(vault
            .receipts(crate::receipt::ReceiptQuery::default())?
            .into_iter()
            .filter(|receipt| {
                is_skill_edit_verdict_receipt(receipt)
                    && receipt.fields.get("skill_edit_proposal") == Some(&proposal.to_hex())
            })
            .count())
    };
    let receipts = receipt_count()?;
    let again = score_gate_skill_edit_in_cycle(
        &vault,
        &proposal,
        &scorer,
        wake(&vault, "tradeoff-redelivery", 20),
        901,
    )?;
    assert_eq!(again, first);
    assert_eq!(*scorer.callbacks.borrow(), callbacks);
    assert_eq!(
        skill_edit_verdicts_for_proposal(&vault, &proposal)?,
        history
    );
    assert_eq!(receipt_count()?, receipts);
    assert_eq!(skill_tradeoff_ask(&vault, &proposal)?.unwrap(), ask);
    let picked = settle_skill_tradeoff_ask(
        &vault,
        &owner,
        &proposal,
        &ask_digest,
        TradeoffChoice::Approve,
        902,
    )?;
    assert_eq!(picked.disposition, SkillEditDisposition::AcceptedTradeoff);
    let resolution = picked.tradeoff_resolution.as_ref().unwrap();
    assert_eq!(resolution.rung, TradeoffRung::Person);
    assert_eq!(resolution.pending, first.id);
    assert_eq!(resolution.evidence, ask_digest);
    assert_eq!(
        picked.tradeoff_jev, first.tradeoff_jev,
        "the uncertain Jev verdict stays on the record after the pick"
    );
    assert!(skill_tradeoff_ask(&vault, &proposal)?.is_none());
    assert_eq!(
        skill_tradeoff_preferences(&vault, &skill)?.unwrap().learned,
        [quality_for_minutes(TradeoffChoice::Approve)]
    );
    let next = optimizer_proposal_citing(&vault, &skill, Value::Array(vec![]));
    drop(vault);
    let reopened = Vault::open(tmp.path(), VaultConfig::default())?;
    let verdict = score_gate_skill_edit_in_cycle(
        &reopened,
        &next,
        &scorer,
        wake(&reopened, "tradeoff-next", 30),
        903,
    )?;
    assert_eq!(verdict.disposition, SkillEditDisposition::AcceptedTradeoff);
    let learned = verdict.tradeoff_resolution.as_ref().unwrap();
    assert_eq!(learned.rung, TradeoffRung::Preference);
    assert_eq!(learned.authentication, "learned_rule:0");
    assert_eq!(
        *scorer.jev_calls.borrow(),
        1,
        "learned preference silences Jev"
    );
    // The pick moved the goal revision, and the answered proposal carries it.
    admit_optimized_skill_revision(&reopened, &proposal, t(904), 904)?;
    Ok(())
}

#[test]
fn newer_goal_replaces_an_unanswered_ab_question() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let (skill, proposal) = losing_skill_with_proposal(&vault, "oneiron.skill.tradeoff.newgoal");
    let owner = tradeoff_owner(&vault);
    let first_goal = ladder_goal(&vault, &owner, &skill, Vec::new())?;
    let scorer = LadderScorer::new(Some((0.5, false)));
    let old = score_gate_skill_edit_in_cycle(
        &vault,
        &proposal,
        &scorer,
        wake(&vault, "old-goal", 10),
        900,
    )?;
    assert_eq!(old.disposition, SkillEditDisposition::NeedsTradeoffDecision);
    let question_one = skill_tradeoff_ask(&vault, &proposal)?.unwrap();
    assert_eq!(question_one.question.goal_revision, first_goal);
    let digest_one = question_one.question.digest()?;
    let second_goal =
        set_skill_tradeoff_preferences(&vault, &owner, &skill, Vec::new(), LADDER_BAND)?;
    assert!(skill_tradeoff_ask(&vault, &proposal)?.is_none());
    let new = score_gate_skill_edit_in_cycle(
        &vault,
        &proposal,
        &scorer,
        wake(&vault, "new-goal", 20),
        901,
    )?;
    assert_eq!(new.disposition, SkillEditDisposition::NeedsTradeoffDecision);
    assert_ne!(new.id, old.id);
    let question_two = skill_tradeoff_ask(&vault, &proposal)?.unwrap();
    assert_eq!(question_two.question.goal_revision, second_goal);
    let digest_two = question_two.question.digest()?;
    assert_ne!(digest_one, digest_two);
    assert!(
        settle_skill_tradeoff_ask(
            &vault,
            &owner,
            &proposal,
            &digest_one,
            TradeoffChoice::Approve,
            902
        )
        .is_err()
    );
    assert_eq!(
        skill_tradeoff_ask(&vault, &proposal)?.unwrap(),
        question_two
    );
    let accepted = settle_skill_tradeoff_ask(
        &vault,
        &owner,
        &proposal,
        &digest_two,
        TradeoffChoice::Approve,
        903,
    )?;
    assert_eq!(accepted.disposition, SkillEditDisposition::AcceptedTradeoff);
    assert_eq!(accepted.tradeoff_resolution.unwrap().pending, new.id);
    assert!(skill_tradeoff_ask(&vault, &proposal)?.is_none());
    Ok(())
}

#[test]
fn owner_goal_edit_between_admission_and_supersession_reaches_successor() -> Result<()> {
    const NEXT_DESC: &str = "A new instruction tested after owner goal revision.";
    let (tmp, vault) = temp_vault();
    let (old, successor) = losing_skill_with_proposal(&vault, "oneiron.skill.tradeoff.goal-window");
    let owner = tradeoff_owner(&vault);
    ladder_goal(
        &vault,
        &owner,
        &old,
        vec![quality_for_minutes(TradeoffChoice::Approve)],
    )?;
    assert_eq!(
        score_gate_skill_edit_in_cycle(
            &vault,
            &successor,
            &LadderScorer::new(None),
            wake(&vault, "goal-window-admit", 10),
            900
        )?
        .disposition,
        SkillEditDisposition::AcceptedTradeoff
    );
    admit_optimized_skill_revision(&vault, &successor, t(901), 901)?;
    // The predecessor stays Active until supersession. A lawful owner edit in
    // that window lands on the shared goal identity the successor carries.
    set_skill_edit_goal_axes(&vault, &owner, &old, axes_with_minutes_floor())?;
    set_skill_tradeoff_preferences(&vault, &owner, &old, Vec::new(), LADDER_BAND)?;
    vault.supersede_skill_record(&old, &successor, t(902), 902)?;
    drop(vault);
    let reopened = Vault::open(tmp.path(), VaultConfig::default())?;
    seed_successor_outcome(&reopened, &successor)?;
    let proposal = EntityId::now();
    let mut draft = optimizer_proposal_record_citing(
        &reopened,
        &successor,
        Value::Array(vec![]),
        HAND_CRAFTED_CYCLE,
    );
    draft.version = "goal-window-next".into();
    draft.desc = NEXT_DESC.into();
    reopened.put_skill_record(&proposal, &draft, t(903), 903)?;
    let scorer = LadderScorer::new(Some((0.95, false)))
        .with_baseline(DRAFTED_DESC)
        .with_axes(axes_with_minutes_floor());
    let verdict = score_gate_skill_edit_in_cycle(
        &reopened,
        &proposal,
        &scorer,
        wake(&reopened, "goal-window-next", 20),
        904,
    )?;
    assert_eq!(verdict.disposition, SkillEditDisposition::Rejected);
    assert_eq!(verdict.goal_axes["human_minutes"].kind, GoalAxisKind::Floor);
    assert_eq!(
        *scorer.jev_calls.borrow(),
        0,
        "new floor refuses before Jev"
    );
    Ok(())
}

mod resident;
