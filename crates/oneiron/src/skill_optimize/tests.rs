use std::cell::RefCell;

use super::*;

use crate::attempt_queue::{
    AttemptQueue, ClaimAttempt, ClaimOutcome, CompleteAttempt, CompleteOutcome, EnqueueAttempt,
    EnqueueOutcome, ManifestEntry, ManifestKind,
};
use crate::config::VaultConfig;
use crate::dreamer_runner::{
    AdmitDreamerAttempt, CompleteDreamerAttempt, CompleteDreamerAttemptOutcome,
    DREAMER_SKILL_OPTIMIZE_ATTEMPT_KIND, DreamerAdmissionOutcome, DreamerRunnerStore,
    EnqueueDreamerAttemptOutcome, EnqueueDreamerSkillOptimizeAttempt,
};
use crate::edge::EdgeKind;
use crate::error::ErrorKind;
use crate::receipt::attempt_pack_receipt_id;
use crate::registry::ENTITY_TYPE_PERSON;
use crate::skill_attribution::{
    AttemptOutcome, OutcomeEvidence, read_attribution_cursor, record_attribution_evidence,
    run_attribution_projector,
};
use crate::skill_convert::CONVERT_BIRTH_PATH;
use crate::skill_hub::{HubFile, HubPackage, HubPin, HubRef, SkillCapabilitySurface};
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

/// An unmarked IMPORTED record, for the hub-import road.
fn imported_record(skill_id: &str) -> SkillRecord {
    SkillRecord::new(
        skill_id,
        "Imported instructions.",
        FIXTURE_VERSION,
        ClaimApprovalStatus::Approved,
        SkillLifecycle::Candidate,
        ClaimSource::Imported,
        0.5,
        false,
        true,
        Vec::new(),
        provenance(None),
    )
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

/// Runs one attempt whose pack loaded `skill_id@1.0.0` to its terminal door
/// and returns the receipt id its close STAMPED.
fn stamped_receipt(vault: &Vault, skill_id: &str, now: u64) -> String {
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
    queue
        .append_manifest_entry(
            attempt.id,
            ManifestEntry::new(ManifestKind::Skill, skill_id, FIXTURE_VERSION, now),
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
    attempt_pack_receipt_id(&attempt.id)
}

/// Attributes SK-04 skill DEFECTS until the DEV partition holds `count` more of
/// them, projecting the posterior as it goes.
///
/// `count` is stated in DEV outcomes, not in attributed ones, because that is
/// the quantity the job under test actually reads: ONE-1449 makes the N dial,
/// the ranking and the brief dev-partition-only, so a fixture that attributed
/// exactly five and then asserted the job saw five would be asserting a
/// one-in-five coin flip five times over. Every attributed receipt is still
/// returned, both sides of the split together, so a caller can still reason
/// about the partition as a whole.
fn attribute_defects(vault: &Vault, skill: &EntityId, skill_id: &str, count: u32) -> Vec<String> {
    let actor = EntityId::now();
    put_actor(vault, &actor);
    let target = dev_receipts(vault, skill).expect("dev split").len()
        + usize::try_from(count).expect("count fits");
    let mut receipts = Vec::new();
    let mut minted = 0u32;
    while dev_receipts(vault, skill).expect("dev split").len() < target {
        assert!(
            minted < count * 12 + 12,
            "a four-in-five dev draw reaches {count} long before {minted} attempts"
        );
        let at = 100 + u64::from(minted) * 10;
        let receipt = stamped_receipt(vault, skill_id, at);
        record_attribution_evidence(
            vault,
            &OutcomeEvidence::new(&receipt, actor, AttemptOutcome::Failed, at + 5)
                .with_skill(*skill)
                .with_routing_facts(true, true),
        )
        .expect("record evidence");
        receipts.push(receipt);
        minted += 1;
        let cursor = read_attribution_cursor(vault).expect("cursor");
        let judgments = run_attribution_projector(vault, cursor).expect("attribution pass");
        project_skill_reliability(vault, &judgments).expect("reliability pass");
    }
    receipts
}

/// Credits `count` contributing WINS, so the fixture reads healthy.
fn attribute_wins(vault: &Vault, skill: &EntityId, skill_id: &str, count: u32) {
    for index in 0..count {
        let at = 100 + u64::from(index) * 10;
        let receipt = stamped_receipt(vault, skill_id, at);
        record_skill_contributing_win(vault, skill, &receipt, at + 5).expect("credit win");
    }
    crate::skill_reliability::project_skill_reliability_for(vault, skill, 200).expect("project");
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

    fn declining() -> Self {
        Self {
            answer: SkillEditDraft::Decline {
                rationale: "the defects blame the executor, not the text".to_owned(),
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
/// [`attribute_defects`] already guarantees the dev side; what this adds is the
/// RESERVED side, which the gate needs and the selector does not.
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
    seen: RefCell<Vec<(String, Vec<String>)>>,
}

impl StubScorer {
    fn new(before: f32, after: f32) -> Self {
        Self {
            before,
            after,
            seen: RefCell::new(Vec::new()),
        }
    }

    /// The proposed text replays better than the text it replaces.
    fn improving() -> Self {
        Self::new(0.40, 0.75)
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
}

/// A scorer that must never be reached.
struct UnreachableScorer;

impl HeldOutReplayScorer for UnreachableScorer {
    fn score(&self, _case: &HeldOutReplayCase<'_>) -> Result<f32> {
        panic!("a refused proposal must not reach the replay tier");
    }
}

/// Enqueues one real attempt row — the durable scheduler identity every cycle
/// label is now derived from. `run` names the wake when the attempt belongs to
/// one; a runless attempt is its own cycle.
///
/// The row is claimed and completed straight away rather than left READY,
/// because [`stamped_receipt`] claims whatever the queue offers next: a wake row
/// idling in the ready set would be leased out from under it. What proves the
/// cycle is the stored ROW, and that outlives any lease.
fn enqueue_attempt(vault: &Vault, run: Option<&str>, now: u64) -> AttemptId {
    let queue = AttemptQueue::new(vault);
    let EnqueueOutcome::Enqueued(attempt) = queue
        .enqueue(EnqueueAttempt {
            kind: "skill-opt.wake".to_owned(),
            payload: Vec::new(),
            dedupe_key: None,
            run_id: run.map(str::to_owned),
            now,
        })
        .expect("enqueue")
    else {
        panic!("a fresh dedupe-free enqueue is never Existing");
    };
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

// ─── the Dreamer job registration ───────────────────────────────────────

#[test]
fn skill_optimize_attempts_enqueue_admit_and_complete_on_their_own_kind() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let runner = DreamerRunnerStore::new(&vault);

    let EnqueueDreamerAttemptOutcome::Enqueued(queued) =
        runner.enqueue_skill_optimize(EnqueueDreamerSkillOptimizeAttempt {
            input: Value::from("wake:maintenance"),
            parent_attempt: None,
            dedupe_key: Some("wake:1".to_owned()),
            run_id: None,
            now: 10,
        })?
    else {
        panic!("a fresh dedupe key never coalesces");
    };
    assert_eq!(queued.attempt.kind, DREAMER_SKILL_OPTIMIZE_ATTEMPT_KIND);
    assert_eq!(
        queued.payload.attempt_type, DREAMER_SKILL_OPTIMIZE_ATTEMPT_KIND,
        "the payload job_type and the queue kind are one string"
    );

    // The advisory floor holds on this kind exactly as it does on the others.
    let EnqueueDreamerAttemptOutcome::Existing(again) =
        runner.enqueue_skill_optimize(EnqueueDreamerSkillOptimizeAttempt {
            input: Value::from("wake:maintenance"),
            parent_attempt: None,
            dedupe_key: Some("wake:1".to_owned()),
            run_id: None,
            now: 11,
        })?
    else {
        panic!("a repeated dedupe key coalesces");
    };
    assert_eq!(again.attempt.id, queued.attempt.id);

    let DreamerAdmissionOutcome::Admitted(admitted) =
        runner.admit_next_skill_optimize(AdmitDreamerAttempt {
            lease_owner: "skill-opt-runner".to_owned(),
            now: 12,
            budget_id: "wake:skill_optimize".to_owned(),
            budget_total_units: 10,
            reserve_units: 1,
            started_milestone: None,
        })?
    else {
        panic!("the queued attempt is admissible");
    };
    assert_eq!(admitted.status.attempt.id, queued.attempt.id);
    assert_eq!(admitted.budget.remaining_units, 9);

    let CompleteDreamerAttemptOutcome::Completed(done) =
        runner.complete(CompleteDreamerAttempt {
            id: queued.attempt.id,
            lease_owner: "skill-opt-runner".to_owned(),
            attempt_count: admitted.status.attempt.attempt_count,
            now: 13,
        })?
    else {
        panic!("a leased attempt completes exactly once");
    };
    assert_eq!(done.attempt.id, queued.attempt.id);

    // Its own lane: admitting SKILL-OPT never drains the generic queue.
    assert!(matches!(
        runner.admit_next_skill_optimize(AdmitDreamerAttempt {
            lease_owner: "skill-opt-runner".to_owned(),
            now: 14,
            budget_id: "wake:skill_optimize".to_owned(),
            budget_total_units: 10,
            reserve_units: 1,
            started_milestone: None,
        })?,
        DreamerAdmissionOutcome::Empty
    ));
    Ok(())
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

#[test]
fn a_healthy_skill_never_reaches_the_authoring_tier() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let (skill, _) = put_standard_active(&vault, "oneiron.skill.healthy");
    attribute_wins(&vault, &skill, "oneiron.skill.healthy", 5);

    let posterior =
        crate::skill_reliability::skill_reliability_posterior(&vault, &skill)?.expect("projected");
    assert!(posterior.mean() > skill_reliability_prior(&vault, &skill)?.mean());

    assert!(optimize_candidates(&vault)?.is_empty());
    let outcome = run(&vault, &UnreachableAuthor)?;
    assert_eq!(outcome.skill, None);
    assert_eq!(outcome.proposal, None);
    Ok(())
}

#[test]
fn an_author_may_decline_and_nothing_is_written() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let (skill, _) = put_standard_active(&vault, "oneiron.skill.losing");
    attribute_defects(&vault, &skill, "oneiron.skill.losing", 5);
    let before = stored(&vault, &skill);

    let outcome = run(&vault, &StubAuthor::declining())?;
    assert_eq!(outcome.skill, Some(skill));
    assert_eq!(outcome.proposal, None);
    assert_eq!(stored(&vault, &skill), before);
    Ok(())
}

#[test]
fn evidence_below_the_n_dial_is_not_enough_to_edit_on() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let (skill, _) = put_standard_active(&vault, "oneiron.skill.thin");
    attribute_defects(&vault, &skill, "oneiron.skill.thin", 3);

    assert_eq!(skill_optimize_min_outcomes(&vault)?, 5);
    assert!(
        optimize_candidates(&vault)?.is_empty(),
        "three losses is a losing posterior on too little evidence"
    );

    // The dial is the only thing standing between them.
    set_skill_optimize_min_outcomes(&vault, 3)?;
    let candidates = optimize_candidates(&vault)?;
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].skill, skill);
    assert_eq!(candidates[0].attributed_outcomes, 3);

    assert_eq!(
        set_skill_optimize_min_outcomes(&vault, 0)
            .expect_err("evidence is the point")
            .kind(),
        ErrorKind::InvalidSkillBody
    );
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

#[test]
fn an_unmarked_record_is_eligible_only_when_provenance_can_say_so() -> Result<()> {
    let (_tmp, vault) = temp_vault();

    // Unmarked, and born on a road nobody can name: ambiguous, fail-closed.
    let ambiguous = EntityId::now();
    put_active(
        &vault,
        &ambiguous,
        &record("oneiron.skill.ambiguous", None, None),
    );
    attribute_defects(&vault, &ambiguous, "oneiron.skill.ambiguous", 5);
    assert_eq!(
        skill_governance_tier(&vault, &ambiguous)?,
        SkillTierVerdict::Ambiguous
    );
    assert_eq!(skill_governance_tier(&vault, &ambiguous)?.tier(), None);

    // Unmarked, but the record itself says it was converted from a
    // conversation: the legacy default resolves to `standard`.
    let converted = EntityId::now();
    put_active(
        &vault,
        &converted,
        &record("oneiron.skill.converted", None, Some(CONVERT_BIRTH_PATH)),
    );
    attribute_defects(&vault, &converted, "oneiron.skill.converted", 5);
    assert_eq!(
        skill_governance_tier(&vault, &converted)?,
        SkillTierVerdict::LegacyStandard
    );

    let candidates = optimize_candidates(&vault)?;
    assert_eq!(
        candidates.len(),
        1,
        "only the explainable record is a candidate"
    );
    assert_eq!(candidates[0].skill, converted);
    Ok(())
}

#[test]
fn a_hub_import_carries_its_own_answer_and_a_bare_imported_stamp_does_not() -> Result<()> {
    let (_tmp, vault) = temp_vault();

    // Through the REAL hub door, which writes the `skill.hub_provenance`
    // alias the legacy default reads.
    let package = HubPackage::new(
        imported_record("oneiron.skill.hubbed"),
        vec![HubFile::new("SKILL.md", b"# hubbed fixture\n".to_vec())],
        SkillCapabilitySurface::default(),
    );
    let hub_ref = HubRef::new(EntityId::now(), "skill-opt/pack", HubPin::None).expect("hub ref");
    let imported = vault.import_skill_from_hub(&hub_ref, &package, t(10), 11)?;
    assert_eq!(
        skill_governance_tier(&vault, &imported)?,
        SkillTierVerdict::LegacyStandard
    );

    // An `imported` STAMP with no hub behind it is an assertion about a road
    // nobody travelled, so it answers nothing.
    let asserted = EntityId::now();
    put_active(
        &vault,
        &asserted,
        &imported_record("oneiron.skill.asserted"),
    );
    assert_eq!(vault.skill_hub_provenance_count(&asserted)?, 0);
    assert_eq!(
        skill_governance_tier(&vault, &asserted)?,
        SkillTierVerdict::Ambiguous
    );
    Ok(())
}

#[test]
fn the_owner_marks_a_tier_through_the_ordinary_update_door() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let ambiguous = EntityId::now();
    let stored = put_active(
        &vault,
        &ambiguous,
        &record("oneiron.skill.ambiguous", None, None),
    );
    attribute_defects(&vault, &ambiguous, "oneiron.skill.ambiguous", 5);
    assert!(optimize_candidates(&vault)?.is_empty());

    // Marking a tier is a STATE flip: same version, no content revision.
    let mut marked = vault.get_skill_record(&ambiguous)?.expect("stored");
    marked.governance_tier = Some(SkillGovernanceTier::Standard);
    vault.update_skill_record(&ambiguous, &marked, t(500), 501)?;
    let after = vault.get_skill_record(&ambiguous)?.expect("stored");
    assert_eq!(after.version, stored.version);
    assert_eq!(
        skill_governance_tier(&vault, &ambiguous)?,
        SkillTierVerdict::Marked(SkillGovernanceTier::Standard)
    );
    assert_eq!(optimize_candidates(&vault)?.len(), 1);

    // And the owner can rule the other way, which takes it back out.
    let mut protected = after;
    protected.governance_tier = Some(SkillGovernanceTier::Identity);
    vault.update_skill_record(&ambiguous, &protected, t(502), 503)?;
    assert!(optimize_candidates(&vault)?.is_empty());
    Ok(())
}

#[test]
fn an_imported_pack_marks_its_tier_without_a_version_bump() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let id = EntityId::now();
    let active = put_active(&vault, &id, &imported_record("oneiron.skill.imported"));

    // Imported CONTENT never changes in place — which is exactly why the tier
    // must not be content: otherwise the packs most in need of an identity
    // mark could never receive one.
    let mut marked = active.clone();
    marked.governance_tier = Some(SkillGovernanceTier::Identity);
    vault.update_skill_record(&id, &marked, t(500), 501)?;
    assert_eq!(
        skill_governance_tier(&vault, &id)?,
        SkillTierVerdict::Marked(SkillGovernanceTier::Identity)
    );

    let mut edited = active;
    edited.desc = "Rewritten in place.".to_owned();
    edited.version = "2.0.0".to_owned();
    assert_eq!(
        vault
            .update_skill_record(&id, &edited, t(502), 503)
            .expect_err("the fork law still holds")
            .kind(),
        ErrorKind::InvalidSkillBody
    );
    Ok(())
}

// ─── selection ──────────────────────────────────────────────────────────

#[test]
fn the_worst_posterior_is_the_one_skill_the_attempt_takes() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let (mild, _) = put_standard_active(&vault, "oneiron.skill.mild");
    let (severe, _) = put_standard_active(&vault, "oneiron.skill.severe");
    attribute_defects(&vault, &mild, "oneiron.skill.mild", 5);
    attribute_defects(&vault, &severe, "oneiron.skill.severe", 9);

    let candidates = optimize_candidates(&vault)?;
    assert_eq!(candidates.len(), 2);
    assert_eq!(
        candidates[0].skill, severe,
        "worst posterior mean ranks first"
    );
    assert!(candidates[0].posterior.mean() < candidates[1].posterior.mean());

    let author = StubAuthor::editing();
    let outcome = run(&vault, &author)?;
    assert_eq!(outcome.skill, Some(severe));
    assert_eq!(author.seen.borrow().len(), 1, "one skill per attempt");
    Ok(())
}

#[test]
fn a_candidate_revision_is_never_the_target_and_never_a_candidate() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let (skill, _) = put_standard_active(&vault, "oneiron.skill.losing");
    attribute_defects(&vault, &skill, "oneiron.skill.losing", 5);
    let proposal = run(&vault, &StubAuthor::editing())?
        .proposal
        .expect("a proposal");

    // The drafted revision is `candidate`, so it never loads as canon and
    // never enters the ranking — a proposal cannot propose against itself.
    let stored = vault.get_skill_record(&proposal)?.expect("proposal");
    assert!(!stored.lifecycle_status.loads_as_canon());
    assert!(
        optimize_candidates(&vault)?.is_empty(),
        "the open question suppresses both revisions of the skill"
    );
    Ok(())
}

#[test]
fn a_draft_that_restates_the_instructions_is_refused() {
    let (_tmp, vault) = temp_vault();
    let (skill, _) = put_standard_active(&vault, "oneiron.skill.losing");
    attribute_defects(&vault, &skill, "oneiron.skill.losing", 5);
    let before = stored(&vault, &skill);

    let author = StubAuthor {
        answer: SkillEditDraft::Edit {
            desc: before.desc.clone(),
            rationale: "no change at all".to_owned(),
        },
        seen: RefCell::new(Vec::new()),
    };
    assert_eq!(
        run(&vault, &author).expect_err("not an edit").kind(),
        ErrorKind::InvalidSkillBody
    );
    assert_eq!(stored(&vault, &skill), before);
}

// ─── ONE-1449: the held-out split ───────────────────────────────────────

#[test]
fn the_split_is_deterministic_disjoint_and_invisible_to_the_author() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let (skill, _) = put_standard_active(&vault, "oneiron.skill.losing");
    let attributed = attribute_defects_across_split(&vault, &skill, "oneiron.skill.losing");

    // Same skill, same answer — every time, with no state between the reads.
    let reserved = held_out_receipts(&vault, &skill)?;
    assert_eq!(reserved, held_out_receipts(&vault, &skill)?);
    assert_eq!(reserved, held_out_receipts(&vault, &skill)?);
    let dev = dev_receipts(&vault, &skill)?;
    assert_eq!(dev, dev_receipts(&vault, &skill)?);

    // Disjoint, and a partition of the attributed set rather than two samples
    // of it: there is no receipt in both and none in neither.
    assert!(
        dev.iter().all(|receipt| !reserved.contains(receipt)),
        "the two views never overlap"
    );
    let mut union: Vec<String> = dev.iter().chain(&reserved).cloned().collect();
    union.sort();
    let mut all = attributed;
    all.sort();
    assert_eq!(union, all);
    assert!(
        reserved
            .iter()
            .all(|receipt| receipt_is_held_out(&skill, receipt))
    );
    assert!(
        dev.iter()
            .all(|receipt| !receipt_is_held_out(&skill, receipt))
    );

    // LEAKAGE NEGATIVE: adding a receipt the DEV side claims cannot move the
    // gate's view. The reserve is chosen by the receipt's own identity, so a
    // dev row has no vote in which receipts will score an edit.
    //
    // The baseline is re-read before EACH addition, because a rejected draw
    // (one that lands reserved) legitimately grows the held-out set — the
    // claim under test is about the dev row, not about the loop.
    let mut proved = false;
    for _ in 0..24 {
        let baseline = held_out_receipts(&vault, &skill)?;
        let receipt = stamped_receipt(&vault, "oneiron.skill.losing", 5_000);
        let actor = EntityId::now();
        put_actor(&vault, &actor);
        record_skill_contributing_win(&vault, &skill, &receipt, 5_005)?;
        if !receipt_is_held_out(&skill, &receipt) {
            assert_eq!(
                held_out_receipts(&vault, &skill)?,
                baseline,
                "a dev-only receipt does not change the held-out selection"
            );
            assert!(dev_receipts(&vault, &skill)?.contains(&receipt));
            proved = true;
            break;
        }
    }
    assert!(
        proved,
        "one in five reserved means dev rows are the common case"
    );
    Ok(())
}

// ─── ONE-1449: the strict-improvement gate ──────────────────────────────

#[test]
fn an_improving_replay_score_makes_the_proposal_eligible_and_nothing_more() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let (skill, proposal) = losing_skill_with_proposal(&vault, "oneiron.skill.losing");
    let target_before = stored(&vault, &skill);
    let reserved = held_out_receipts(&vault, &skill)?;

    let scorer = StubScorer::improving();
    let verdict = score_gate_skill_edit_in_cycle(
        &vault,
        &proposal,
        &scorer,
        wake(&vault, "wake-1", 10),
        900,
    )?;
    assert!(verdict.accepted);
    assert_eq!(verdict.disposition, SkillEditDisposition::Accepted);
    assert!(verdict.after > verdict.before);
    assert_eq!(verdict.proposal, proposal);
    assert_eq!(verdict.skill, skill);
    assert_eq!(verdict.held_out_receipts, reserved);

    // Both cases were replayed against the SAME reserved evidence, which the
    // gate recomputed — the proposal supplied no list at all.
    assert_eq!(scorer.evidence(), vec![reserved.clone(), reserved.clone()]);

    // ELIGIBLE, not admitted: the score gate writes no canon.
    let staged = stored(&vault, &proposal);
    assert_eq!(staged.lifecycle_status, SkillLifecycle::Candidate);
    assert_eq!(staged.approval_status, ClaimApprovalStatus::Proposed);
    assert_eq!(stored(&vault, &skill), target_before);

    // And the ordinary door cannot stand in for admission on this record.
    let mut flipped = staged;
    flipped.approval_status = ClaimApprovalStatus::Approved;
    flipped.lifecycle_status = SkillLifecycle::Active;
    assert_eq!(
        vault
            .update_skill_record(&proposal, &flipped, t(400), 401)
            .expect_err("an optimizer-born candidate never flips its way to canon")
            .kind(),
        ErrorKind::InvalidSkillBody
    );
    assert_eq!(
        stored(&vault, &proposal).lifecycle_status,
        SkillLifecycle::Candidate
    );

    // The verdict receipt carries the pair and the evidence it rested on.
    let receipt = verdict_receipt(&vault, &verdict);
    assert_eq!(receipt.outcome, "accepted");
    assert_eq!(receipt.occurred_at, 900);
    assert_eq!(
        receipt.fields["skill_edit_score_before"],
        format!("{:.6}", verdict.before)
    );
    assert_eq!(
        receipt.fields["skill_edit_score_after"],
        format!("{:.6}", verdict.after)
    );
    assert_eq!(
        receipt.fields["skill_edit_held_out_receipts"],
        reserved.join(",")
    );
    assert_eq!(receipt.fields["skill_edit_proposal"], proposal.to_hex());
    assert_eq!(receipt.fields["skill_edit_cycle"], "run:wake-1");

    // The typed read model serves the same two numbers as numbers.
    let read = skill_edit_verdict(&vault, &proposal)?.expect("a standing verdict");
    assert_eq!(read.before, verdict.before);
    assert_eq!(read.after, verdict.after);
    assert!(read.improvement() > 0.0);
    Ok(())
}

#[test]
fn a_regression_and_an_exact_tie_are_both_rejected_and_both_receipted() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let (regressing, regressing_proposal) =
        losing_skill_with_proposal(&vault, "oneiron.skill.regressing");
    let (tied, tied_proposal) = losing_skill_with_proposal(&vault, "oneiron.skill.tied");
    let regressing_before = stored(&vault, &regressing);
    let tied_before = stored(&vault, &tied);

    let worse = StubScorer::new(0.60, 0.55);
    let regression = score_gate_skill_edit_in_cycle(
        &vault,
        &regressing_proposal,
        &worse,
        wake(&vault, "wake-1", 10),
        900,
    )?;
    assert!(!regression.accepted);
    assert_eq!(regression.disposition, SkillEditDisposition::Rejected);

    // Exactly equal. There is no epsilon, so a tie is not an improvement.
    let level = StubScorer::new(0.60, 0.60);
    let tie = score_gate_skill_edit_in_cycle(
        &vault,
        &tied_proposal,
        &level,
        wake(&vault, "wake-1", 10),
        901,
    )?;
    assert!(!tie.accepted);
    assert_eq!(tie.disposition, SkillEditDisposition::Rejected);
    assert_eq!(tie.before, tie.after);

    // Neither active record moved, and neither proposal became eligible.
    assert_eq!(stored(&vault, &regressing), regressing_before);
    assert_eq!(stored(&vault, &tied), tied_before);
    for proposal in [regressing_proposal, tied_proposal] {
        assert_eq!(
            stored(&vault, &proposal).lifecycle_status,
            SkillLifecycle::Candidate
        );
        assert_eq!(
            admit_optimized_skill_revision(&vault, &proposal, t(400), 401)
                .expect_err("a rejected proposal is not admissible")
                .kind(),
            ErrorKind::InvalidSkillBody
        );
    }

    // Both rejections are durable, queryable and carry their score pair.
    for (verdict, before, after) in [(&regression, 0.60_f32, 0.55_f32), (&tie, 0.60, 0.60)] {
        let receipt = verdict_receipt(&vault, verdict);
        assert_eq!(receipt.outcome, "rejected");
        assert_eq!(
            receipt.fields["skill_edit_score_before"],
            format!("{before:.6}")
        );
        assert_eq!(
            receipt.fields["skill_edit_score_after"],
            format!("{after:.6}")
        );
    }
    Ok(())
}

#[test]
fn a_score_the_comparison_cannot_mean_anything_over_is_refused() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let (_, proposal) = losing_skill_with_proposal(&vault, "oneiron.skill.losing");

    // NaN is the case that matters: `NaN > x` is false, so an unvalidated NaN
    // would read as a quiet rejection rather than the broken scorer it is.
    let nonsense = StubScorer::new(f32::NAN, 0.9);
    assert_eq!(
        score_gate_skill_edit_in_cycle(
            &vault,
            &proposal,
            &nonsense,
            wake(&vault, "wake-1", 10),
            900
        )
        .expect_err("an unusable scalar is not a verdict")
        .kind(),
        ErrorKind::InvalidSkillBody
    );
    let out_of_range = StubScorer::new(0.5, 1.5);
    assert_eq!(
        score_gate_skill_edit_in_cycle(
            &vault,
            &proposal,
            &out_of_range,
            wake(&vault, "wake-1", 10),
            901
        )
        .expect_err("a score outside the comparable range is not a verdict")
        .kind(),
        ErrorKind::InvalidSkillBody
    );
    assert!(skill_edit_verdicts_for_proposal(&vault, &proposal)?.is_empty());
    Ok(())
}

// ─── ONE-1449: the per-cycle accept cap ─────────────────────────────────

#[test]
fn the_cycle_cap_bounds_accepts_and_the_overflow_waits_for_the_next_cycle() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    assert_eq!(
        skill_edit_cycle_cap(&vault)?,
        DEFAULT_SKILL_EDIT_CYCLE_CAP,
        "the dial has a small default"
    );
    assert_eq!(
        set_skill_edit_cycle_cap(&vault, 0)
            .expect_err("a zero cap disables the loop by accident")
            .kind(),
        ErrorKind::InvalidSkillBody
    );
    // K = 1, so two passing proposals is one over.
    set_skill_edit_cycle_cap(&vault, 1)?;

    let (_, first) = losing_skill_with_proposal(&vault, "oneiron.skill.first");
    let (_, second) = losing_skill_with_proposal(&vault, "oneiron.skill.second");
    let scorer = StubScorer::improving();
    let wake_one = wake(&vault, "wake-1", 10);

    let accepted = score_gate_skill_edit_in_cycle(&vault, &first, &scorer, wake_one, 900)?;
    assert_eq!(accepted.disposition, SkillEditDisposition::Accepted);

    let deferred = score_gate_skill_edit_in_cycle(&vault, &second, &scorer, wake_one, 901)?;
    assert_eq!(deferred.disposition, SkillEditDisposition::DeferredCycleCap);
    assert!(
        deferred.after > deferred.before,
        "the cap defers a PASSING proposal — it caps accepts, not proposals"
    );
    assert!(!deferred.accepted);
    assert!(deferred.disposition.leaves_proposal_open());
    assert_eq!(
        verdict_receipt(&vault, &deferred).outcome,
        "deferred_cycle_cap"
    );

    // Open, not answered: still a proposed candidate, and not yet admissible.
    let waiting = stored(&vault, &second);
    assert_eq!(waiting.lifecycle_status, SkillLifecycle::Candidate);
    assert_eq!(waiting.approval_status, ClaimApprovalStatus::Proposed);
    assert_eq!(
        admit_optimized_skill_revision(&vault, &second, t(400), 401)
            .expect_err("a deferred proposal is not eligible")
            .kind(),
        ErrorKind::InvalidSkillBody
    );

    // The NEXT cycle has its own budget and picks the deferral up.
    let promoted =
        score_gate_skill_edit_in_cycle(&vault, &second, &scorer, wake(&vault, "wake-2", 20), 902)?;
    assert_eq!(promoted.disposition, SkillEditDisposition::Accepted);
    admit_optimized_skill_revision(&vault, &second, t(402), 403)?;
    assert_eq!(
        stored(&vault, &second).lifecycle_status,
        SkillLifecycle::Active
    );

    // Both rulings on that proposal are history, in order.
    let history = skill_edit_verdicts_for_proposal(&vault, &second)?;
    assert_eq!(history.len(), 2);
    assert_eq!(
        history[0].disposition,
        SkillEditDisposition::DeferredCycleCap
    );
    assert_eq!(history[1].disposition, SkillEditDisposition::Accepted);
    assert_eq!(history[0].cycle, "run:wake-1");
    assert_eq!(history[1].cycle, "run:wake-2");
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
    vault
        .put_entity(
            id,
            crate::registry::ENTITY_TYPE_MESSAGE,
            t(1),
            1,
            b"cited words",
        )
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
    assert!(vault.delete_entity(&doomed)?);
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
fn a_skill_with_no_reserved_evidence_has_nothing_to_score_on() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let (skill, _) = put_standard_active(&vault, "oneiron.skill.losing");
    attribute_defects_across_split(&vault, &skill, "oneiron.skill.losing");
    let proposal = run(&vault, &StubAuthor::editing())?
        .proposal
        .expect("a proposal");

    // A DIFFERENT skill, with a proposal against it but no attributed
    // outcomes at all: there is no reserved evidence, so there is no honest
    // comparison to make and the gate says so rather than passing on nothing.
    let (bare, _) = put_standard_active(&vault, "oneiron.skill.bare");
    let bare_proposal = optimizer_proposal_citing(&vault, &bare, Value::Array(Vec::new()));
    assert!(held_out_receipts(&vault, &bare)?.is_empty());
    assert_eq!(
        score_gate_skill_edit_in_cycle(
            &vault,
            &bare_proposal,
            &UnreachableScorer,
            wake(&vault, "wake-1", 10),
            900
        )
        .expect_err("no reserved evidence, no verdict")
        .kind(),
        ErrorKind::InvalidSkillBody
    );
    assert_eq!(
        skill_edit_verdict(&vault, &bare_proposal)?
            .expect("a durable refusal")
            .disposition,
        SkillEditDisposition::RefusedNoHeldOutEvidence
    );
    assert_eq!(
        stored(&vault, &bare_proposal).approval_status,
        ClaimApprovalStatus::Rejected,
        "the row and the closure commit in one transaction on this arm too"
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
fn reserve_one_more_held_out_receipt(
    vault: &Vault,
    skill: &EntityId,
    skill_id: &str,
    at: u64,
) -> String {
    for index in 0..40 {
        let now = at + index * 10;
        let receipt = stamped_receipt(vault, skill_id, now);
        if !receipt_is_held_out(skill, &receipt) {
            continue;
        }
        record_skill_contributing_win(vault, skill, &receipt, now + 5).expect("credit win");
        return receipt;
    }
    panic!("one receipt in five is reserved, so forty draws is not a near miss");
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
}

/// The host's judge, registered process-globally: no interior state, because a
/// `&'static` in a `OnceLock` has to be `Send + Sync`.
struct HostScorer;

impl HeldOutReplayScorer for HostScorer {
    fn score(&self, case: &HeldOutReplayCase<'_>) -> Result<f32> {
        Ok(if case.instructions == TARGET_DESC {
            0.25
        } else {
            0.80
        })
    }
}

static HOST_SCORER: HostScorer = HostScorer;

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
        SkillEditDisposition::RefusedNoHeldOutEvidence,
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
    let (_tmp, vault) = temp_vault();
    // Leaked so the race hook — a `'static` thread-local, because the gate that
    // fires it holds no test state — can reach this exact vault. The temp dir
    // still drops with the test; only the handle outlives it.
    let vault: &'static Vault = Box::leak(Box::new(vault));
    let (skill, _) = put_standard_active(vault, "oneiron.skill.bare");
    let proposal = optimizer_proposal_citing(vault, &skill, Value::Array(Vec::new()));
    assert!(
        held_out_receipts(vault, &skill)?.is_empty(),
        "nothing is reserved yet, so the pre-read reads a terminal no-evidence"
    );

    // The window the repair closed: the reason was read BEFORE the transaction
    // that would have written it, and evidence landed in between. The old shape
    // wrote a `refused_no_held_out_evidence` row anyway — a terminal answer
    // about a world that no longer existed, which also closed the proposal.
    gate::set_pre_score_race_hook(Box::new(move || {
        reserve_one_more_held_out_receipt(vault, &skill, "oneiron.skill.bare", 6_000);
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

// ─── ONE-1449 M4: an answer closes the question ─────────────────────────

#[test]
fn a_terminal_answer_closes_the_proposal_and_the_next_wake_may_ask_again() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let (skill, proposal) = losing_skill_with_proposal(&vault, "oneiron.skill.losing");
    assert!(
        optimize_candidates(&vault)?.is_empty(),
        "an OPEN question suppresses the skill"
    );

    // A tie. There is no epsilon, so this is an answer, not a deferral.
    let level = StubScorer::new(0.60, 0.60);
    let tie =
        score_gate_skill_edit_in_cycle(&vault, &proposal, &level, wake(&vault, "wake-1", 10), 900)?;
    assert_eq!(tie.disposition, SkillEditDisposition::Rejected);
    assert!(tie.disposition.closes_proposal());

    // Closed on the APPROVAL axis: the text, the provenance and the lifecycle
    // all survive, so the ruling is readable history rather than a deletion.
    let answered = stored(&vault, &proposal);
    assert_eq!(answered.lifecycle_status, SkillLifecycle::Candidate);
    assert_eq!(answered.approval_status, ClaimApprovalStatus::Rejected);
    assert_eq!(answered.desc, DRAFTED_DESC);
    assert_eq!(
        provenance_entry(&answered, PROVENANCE_BIRTH_KEY).as_deref(),
        Some(SKILL_OPTIMIZE_BIRTH_PATH)
    );

    // The skill is back in the loop and the optimizer may ask a NEW question.
    assert_eq!(
        optimize_candidates(&vault)?
            .first()
            .map(|entry| entry.skill),
        Some(skill),
        "a denied proposal must not wedge the skill it denied"
    );
    let again = run(&vault, &StubAuthor::editing())?;
    assert_eq!(again.skill, Some(skill));
    let next = again.proposal.expect("a fresh question");
    assert_ne!(next, proposal);

    // The answered one stays answered: no gate, and no door.
    assert_eq!(
        score_gate_skill_edit_in_cycle(
            &vault,
            &proposal,
            &UnreachableScorer,
            wake(&vault, "wake-2", 20),
            901
        )
        .expect_err("an answered proposal is not an open candidate")
        .kind(),
        ErrorKind::InvalidSkillBody
    );
    assert_eq!(
        admit_optimized_skill_revision(&vault, &proposal, t(400), 401)
            .expect_err("an answered proposal is never admitted")
            .kind(),
        ErrorKind::InvalidSkillBody
    );
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
fn a_repeated_gate_call_preserves_the_acceptance_and_spends_no_second_slot() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    set_skill_edit_cycle_cap(&vault, 1)?;
    let (_, first) = losing_skill_with_proposal(&vault, "oneiron.skill.first");
    let (_, second) = losing_skill_with_proposal(&vault, "oneiron.skill.second");
    let scorer = StubScorer::improving();
    let wake_one = wake(&vault, "wake-1", 10);

    let accepted = score_gate_skill_edit_in_cycle(&vault, &first, &scorer, wake_one, 900)?;
    assert_eq!(accepted.disposition, SkillEditDisposition::Accepted);

    // The retry: the same ruling, the same row, and no second replay.
    let retried = score_gate_skill_edit_in_cycle(&vault, &first, &scorer, wake_one, 901)?;
    assert_eq!(retried, accepted);
    assert_eq!(skill_edit_verdicts_for_proposal(&vault, &first)?.len(), 1);
    assert_eq!(
        scorer.evidence().len(),
        2,
        "one delivery is one pair of replays, however often it is delivered"
    );

    // A duplicate arriving under ANOTHER label cannot revoke it either.
    let elsewhere =
        score_gate_skill_edit_in_cycle(&vault, &first, &scorer, wake(&vault, "wake-2", 20), 902)?;
    assert_eq!(elsewhere, accepted);
    assert_eq!(
        elsewhere.cycle, "run:wake-1",
        "an acceptance keeps the cycle it was ruled in"
    );

    // The cap counts PROPOSALS, so the retry ate nothing: the one slot this
    // wake has is still spent by exactly one edit.
    let deferred = score_gate_skill_edit_in_cycle(&vault, &second, &scorer, wake_one, 903)?;
    assert_eq!(deferred.disposition, SkillEditDisposition::DeferredCycleCap);

    // And the standing acceptance still admits, after all of it.
    admit_optimized_skill_revision(&vault, &first, t(400), 401)?;
    assert_eq!(
        stored(&vault, &first).lifecycle_status,
        SkillLifecycle::Active
    );
    Ok(())
}

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
    reserve_one_more_held_out_receipt(&vault, &skill, "oneiron.skill.losing", 5_000);
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

// ─── ONE-1449 M8: the whole basis, or none of it ────────────────────────

#[test]
fn a_verdict_carries_the_whole_evidence_basis_not_only_a_display_list() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let (skill, proposal) = losing_skill_with_proposal(&vault, "oneiron.skill.losing");
    let reserved = held_out_receipts(&vault, &skill)?;
    let scorer = StubScorer::improving();
    let verdict = score_gate_skill_edit_in_cycle(
        &vault,
        &proposal,
        &scorer,
        wake(&vault, "wake-1", 10),
        900,
    )?;

    assert_eq!(
        usize::try_from(verdict.held_out_count).expect("count"),
        reserved.len()
    );
    assert_eq!(
        verdict.held_out_digest,
        held_out_receipt_set_digest(&reserved)
    );
    assert!(
        !verdict.held_out_truncated,
        "this fixture sits well under the display bound"
    );
    assert_eq!(
        verdict.held_out_receipts, reserved,
        "…so here the display list IS the whole basis, and says so"
    );

    // The digest is a binding, not a decoration: one more reserved receipt and
    // the recomputed identity no longer matches the one the ruling recorded.
    reserve_one_more_held_out_receipt(&vault, &skill, "oneiron.skill.losing", 5_000);
    assert_ne!(
        verdict.held_out_digest,
        held_out_receipt_set_digest(&held_out_receipts(&vault, &skill)?)
    );

    // The projection carries the same basis, and the typed read model is the
    // row itself rather than a lossy view of it.
    let receipt = verdict_receipt(&vault, &verdict);
    assert_eq!(
        receipt.fields["skill_edit_held_out_count"],
        reserved.len().to_string()
    );
    assert_eq!(
        receipt.fields["skill_edit_held_out_digest"],
        verdict.held_out_digest
    );
    assert_eq!(
        receipt.fields["skill_edit_proposal_digest"],
        verdict.proposal_digest
    );
    assert_eq!(
        receipt.fields["skill_edit_target_digest"],
        verdict.target_digest
    );
    assert!(
        !receipt.fields.contains_key("skill_edit_held_out_truncated"),
        "the marker is present exactly when the list is a window"
    );
    assert_eq!(
        skill_edit_verdict(&vault, &proposal)?.expect("a standing verdict"),
        verdict
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

// ─── ONE-1449 M10: the two-argument entry point ─────────────────────────

#[test]
fn the_two_argument_gate_rules_through_the_host_registered_judge() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let (_, proposal) = losing_skill_with_proposal(&vault, "oneiron.skill.losing");

    // Registration is once per process. A second call in the same test binary
    // is the already-registered case, which is this door working, not failing.
    let _ = register_held_out_replay_scorer(&HOST_SCORER);
    assert!(HELD_OUT_REPLAY_SCORER.get().is_some());

    let verdict = score_gate_skill_edit(&vault, &proposal)?;
    assert_eq!(verdict.disposition, SkillEditDisposition::Accepted);
    assert_eq!((verdict.before, verdict.after), (0.25, 0.80));
    // The cycle came from the proposal's own birth stamp, not from the caller.
    assert_eq!(
        verdict.cycle,
        SkillEditCycle::of_proposal(&vault, &proposal)?.as_str()
    );
    assert!(
        verdict.cycle.starts_with("attempt:"),
        "this fixture's wake names no run, and the attempt is the honest label"
    );

    // The injectable variant is still injectable, and still idempotent.
    let injected = score_gate_skill_edit_with_scorer(&vault, &proposal, &StubScorer::improving())?;
    assert_eq!(
        injected, verdict,
        "a standing acceptance is returned, not re-judged by whoever asks next"
    );
    admit_optimized_skill_revision(&vault, &proposal, t(400), 401)?;
    assert_eq!(
        stored(&vault, &proposal).lifecycle_status,
        SkillLifecycle::Active
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
    assert!(vault.delete_entity(&proposal)?);
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

#[test]
fn the_birth_marker_leaves_ordinary_and_replicated_writes_alone() -> Result<()> {
    let (_tmp, vault) = temp_vault();

    // The owner's own skill: created, activated and rewritten exactly as
    // before, and never marked by any of it.
    let owned = EntityId::now();
    let active = put_active(
        &vault,
        &owned,
        &record(
            "oneiron.skill.owned",
            Some(SkillGovernanceTier::Standard),
            None,
        ),
    );
    assert!(!origin_marked(&vault, &owned));
    let mut edited = active;
    edited.desc = "The owner rewrote this by hand.".to_owned();
    edited.version = "2.0.0".to_owned();
    vault.update_skill_record(&owned, &edited, t(500), 501)?;
    assert_eq!(
        stored(&vault, &owned).desc,
        "The owner rewrote this by hand."
    );
    assert!(!origin_marked(&vault, &owned));

    // And sync rematerialization of an optimizer-born row is not blocked: a
    // peer's row carries settled remote state, which is never re-decided here.
    let (_, proposal) = losing_skill_with_proposal(&vault, "oneiron.skill.losing");
    let born = stored(&vault, &proposal);
    let remote = crate::skill::encode_skill_record(&born)?;
    assert!(vault.delete_entity(&proposal)?);
    vault
        .batch()
        .put_replicated(&proposal, ENTITY_TYPE_SKILL, t(400), 401, &remote)
        .commit()?;
    assert_eq!(stored(&vault, &proposal), born);
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

#[test]
fn a_verdict_row_is_schema_v3_and_every_older_row_fails_closed() -> Result<()> {
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
        "a v3 row round-trips, bound proposal tier included"
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

    // …and so is the retired disposition, whatever schema claims to carry it.
    rewrite_verdict_row(&vault, |entries: &mut [(Value, Value)]| {
        set_row_field(entries, "v", &Value::from(3u64));
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
    assert!(vault.delete_entity(&skill)?);
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
    assert!(vault.delete_entity(&purged)?);
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
    assert!(vault.delete_entity(&shelled)?);
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
