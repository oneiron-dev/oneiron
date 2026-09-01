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

/// Attributes `count` SK-04 skill DEFECTS to the skill and projects the
/// posterior, so the fixture's losing reading rests on real routed evidence.
fn attribute_defects(vault: &Vault, skill: &EntityId, skill_id: &str, count: u32) -> Vec<String> {
    let actor = EntityId::now();
    put_actor(vault, &actor);
    let mut receipts = Vec::new();
    for index in 0..count {
        let at = 100 + u64::from(index) * 10;
        let receipt = stamped_receipt(vault, skill_id, at);
        record_attribution_evidence(
            vault,
            &OutcomeEvidence::new(&receipt, actor, AttemptOutcome::Failed, at + 5)
                .with_skill(*skill)
                .with_routing_facts(true, true),
        )
        .expect("record evidence");
        receipts.push(receipt);
    }
    let cursor = read_attribution_cursor(vault).expect("cursor");
    let judgments = run_attribution_projector(vault, cursor).expect("attribution pass");
    project_skill_reliability(vault, &judgments).expect("reliability pass");
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

fn run(vault: &Vault, author: &dyn SkillOptimizeAuthor) -> Result<SkillOptimizeOutcome> {
    run_skill_optimize(vault, AttemptId::now(), author, t(300), 301)
}

/// The record as it stands right now.
///
/// The baseline for "the job touched nothing" has to be read AFTER the
/// reliability pass: projecting the posterior refreshes the record's demoted
/// `confidence` CACHE (ONE-1738), which is truth moving, not this job.
fn stored(vault: &Vault, id: &EntityId) -> SkillRecord {
    vault.get_skill_record(id).expect("read").expect("stored")
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
    assert_eq!(brief.defect_receipts, receipts);
    assert_eq!(brief.cited_receipts.len(), receipts.len());

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
    let (skill, _) = put_standard_active(&vault, "oneiron.skill.losing");
    attribute_defects(&vault, &skill, "oneiron.skill.losing", 5);
    let before = stored(&vault, &skill);
    let proposal_id = run(&vault, &StubAuthor::editing())?
        .proposal
        .expect("a proposal");

    // The human admission act: approve, then admit. Nothing the job wrote
    // could do either — it can only stamp `proposed`.
    let mut admitted = vault.get_skill_record(&proposal_id)?.expect("proposal");
    admitted.approval_status = ClaimApprovalStatus::Approved;
    admitted.lifecycle_status = SkillLifecycle::Active;
    vault.update_skill_record(&proposal_id, &admitted, t(400), 401)?;

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
