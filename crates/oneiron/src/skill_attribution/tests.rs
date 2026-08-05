use super::*;
use crate::attempt_queue::{
    AttemptQueue, ClaimAttempt, ClaimOutcome, CompleteAttempt, EnqueueAttempt, EnqueueOutcome,
    ManifestEntry, ManifestKind,
};
use crate::claim::{ClaimApprovalStatus, ClaimSource};
use crate::receipt::attempt_pack_receipt_id;
use crate::registry::ENTITY_TYPE_PERSON;
use crate::skill::{SkillLifecycle, SkillRecord};
use crate::temporal::TimeRange;
use crate::test_util::{embedding_test_config, entity, open_test_vault_with};

const FIXTURE_SKILL_ID: &str = "attribution.fixture.skill";

fn at(ts: u64) -> TimeRange {
    TimeRange { start: ts, end: ts }
}

/// The vault-resident actor an evidence row names. Evidence about an actor the
/// vault has never seen is a fabrication, so every test grounds one.
fn put_actor(vault: &Vault, id: EntityId) -> Result<EntityId> {
    vault.put_entity(&id, ENTITY_TYPE_PERSON, at(1), 1, b"attribution fixture")?;
    Ok(id)
}

/// The vault-resident SKILL an evidence row names, under `skill_id` so the
/// receipt manifest's `reference@version` rows can be matched against it.
fn put_skill(vault: &Vault, id: EntityId, skill_id: &str) -> Result<EntityId> {
    let record = SkillRecord::new(
        skill_id,
        "attribution fixture skill",
        "1.0.0",
        ClaimApprovalStatus::Approved,
        SkillLifecycle::Candidate,
        ClaimSource::Imported,
        0.9,
        false,
        true,
        Vec::new(),
        Value::Map(vec![(
            Value::from("source"),
            Value::from("attribution-fixture"),
        )]),
    );
    vault.put_skill_record(&id, &record, at(10), 11)?;
    Ok(id)
}

/// Runs one attempt whose pack loaded `skill_id` to its terminal door and
/// returns the receipt id that close STAMPED. Evidence cites these, never a
/// hand-written string: the ledger is the authority.
fn stamped_receipt(vault: &Vault, skill_id: &str) -> Result<String> {
    let queue = AttemptQueue::new(vault);
    let EnqueueOutcome::Enqueued(attempt) = queue.enqueue(EnqueueAttempt {
        kind: "attribution.fixture".to_owned(),
        payload: Vec::new(),
        dedupe_key: None,
        run_id: None,
        now: 10,
    })?
    else {
        panic!("a fresh dedupe-free enqueue is never Existing");
    };
    queue.append_manifest_entry(
        attempt.id,
        ManifestEntry::new(ManifestKind::Skill, skill_id, "1.0.0", 11),
    )?;
    let ClaimOutcome::Claimed(leased) = queue.claim(ClaimAttempt {
        lease_owner: "fixture-worker".to_owned(),
        now: 12,
    })?
    else {
        panic!("the enqueued attempt is claimable");
    };
    assert_eq!(leased.id, attempt.id, "one attempt in flight per fixture");
    queue.complete(CompleteAttempt {
        id: attempt.id,
        lease_owner: "fixture-worker".to_owned(),
        attempt_count: leased.attempt_count,
        now: 13,
    })?;
    Ok(attempt_pack_receipt_id(&attempt.id))
}

/// One grounded stage: an actor, a skill, and a receipt whose manifest names
/// that skill — the shape every admitted evidence row has.
struct Grounded {
    actor: EntityId,
    skill: EntityId,
}

fn ground(vault: &Vault, actor_seed: u8, skill_seed: u8) -> Result<Grounded> {
    Ok(Grounded {
        actor: put_actor(vault, entity(actor_seed))?,
        skill: put_skill(vault, entity(skill_seed), FIXTURE_SKILL_ID)?,
    })
}

fn evidence(
    receipt: &str,
    actor: EntityId,
    skill: EntityId,
    outcome: AttemptOutcome,
    followed_skill: bool,
    skill_covered_step: bool,
) -> OutcomeEvidence {
    OutcomeEvidence::new(receipt, actor, outcome, 100)
        .with_skill(skill)
        .with_routing_facts(followed_skill, skill_covered_step)
}

/// ARCH-0053 §4: the projector classifies BEFORE writing. A failed attempt
/// where the actor followed a skill that covered the step is the SKILL's
/// defect; the same failure where the actor departed from the skill is the
/// ACTOR's lapse. The subject IS the routing decision.
#[test]
fn defect_routes_to_the_skill_and_lapse_routes_to_the_actor() -> Result<()> {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let Grounded { actor, skill } = ground(&vault, 0x21, 0x22)?;
    let defect_receipt = stamped_receipt(&vault, FIXTURE_SKILL_ID)?;
    let lapse_receipt = stamped_receipt(&vault, FIXTURE_SKILL_ID)?;

    record_attribution_evidence(
        &vault,
        &evidence(
            &defect_receipt,
            actor,
            skill,
            AttemptOutcome::Failed,
            true,
            true,
        ),
    )?;
    record_attribution_evidence(
        &vault,
        &evidence(
            &lapse_receipt,
            actor,
            skill,
            AttemptOutcome::Failed,
            false,
            true,
        ),
    )?;

    let judgments = run_attribution_projector(&vault, 0)?;

    assert_eq!(judgments.len(), 2, "both failures routed");
    assert_eq!(judgments[0].verdict, AttributionVerdict::SkillDefect);
    assert_eq!(
        judgments[0].subject, skill,
        "a skill defect is judged against the SKILL entity"
    );
    assert_eq!(judgments[1].verdict, AttributionVerdict::ExecutionLapse);
    assert_eq!(
        judgments[1].subject, actor,
        "an execution lapse is judged against the ACTOR entity"
    );
    assert_eq!(
        judgments
            .iter()
            .filter(|judgment| judgment.subject == actor)
            .count(),
        1,
        "the defect contributed nothing to the actor"
    );
    assert_eq!(
        judgments
            .iter()
            .filter(|judgment| judgment.subject == skill)
            .count(),
        1,
        "the lapse contributed nothing to the skill (§5)"
    );
    Ok(())
}

/// ARCH-0053 §4: DISCOVERY (the skill was missing content the attempt needed)
/// is not a claim at all — it becomes a skill EDIT PROPOSAL.
#[test]
fn discovery_routes_to_an_edit_proposal_not_a_claim() -> Result<()> {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let Grounded { actor, skill } = ground(&vault, 0x23, 0x24)?;
    let receipt = stamped_receipt(&vault, FIXTURE_SKILL_ID)?;

    record_attribution_evidence(
        &vault,
        &evidence(&receipt, actor, skill, AttemptOutcome::Failed, true, false),
    )?;
    let judgments = run_attribution_projector(&vault, 0)?;

    assert_eq!(judgments.len(), 1);
    assert_eq!(judgments[0].verdict, AttributionVerdict::Discovery);
    assert!(
        judgments[0].verdict.mints_edit_proposal(),
        "discovery mints a proposal, never a claim"
    );
    assert_eq!(pending_edit_proposals(&vault)?.len(), 1);
    assert_eq!(
        vault.claims_for_subject(&skill)?.len(),
        0,
        "1737 routes; it writes no claims on the skill"
    );
    assert_eq!(
        vault.claims_for_subject(&actor)?.len(),
        0,
        "1737 routes; it writes no claims on the actor"
    );
    Ok(())
}

/// Every judgment cites the receipt it rests on: a verdict with no trace is
/// not a verdict.
#[test]
fn every_judgment_cites_its_receipt() -> Result<()> {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let Grounded { actor, skill } = ground(&vault, 0x25, 0x26)?;
    let receipt = stamped_receipt(&vault, FIXTURE_SKILL_ID)?;
    record_attribution_evidence(
        &vault,
        &evidence(&receipt, actor, skill, AttemptOutcome::Failed, true, true),
    )?;

    let judgments = run_attribution_projector(&vault, 0)?;

    assert_eq!(judgments[0].evidence_receipts, vec![receipt.clone()]);
    assert!(
        crate::receipt::attempt_pack_receipt(&vault, &receipt)?.is_some(),
        "the cited receipt resolves on the ledger: the citation is not a string"
    );
    Ok(())
}

/// The pass is idempotent and resumable: re-running from the persisted cursor
/// routes nothing already routed, and the judgment store does not grow.
#[test]
fn a_second_pass_from_the_cursor_routes_nothing_new() -> Result<()> {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let Grounded { actor, skill } = ground(&vault, 0x27, 0x28)?;
    let receipt = stamped_receipt(&vault, FIXTURE_SKILL_ID)?;
    record_attribution_evidence(
        &vault,
        &evidence(&receipt, actor, skill, AttemptOutcome::Failed, true, true),
    )?;

    assert_eq!(run_attribution_projector(&vault, 0)?.len(), 1);
    let cursor = read_attribution_cursor(&vault)?;
    assert_eq!(cursor, 1, "the cursor advanced past the routed evidence");
    assert_eq!(
        run_attribution_projector(&vault, cursor)?.len(),
        0,
        "nothing new to route"
    );
    assert_eq!(
        attribution_judgments(&vault)?.len(),
        1,
        "the judgment store did not grow"
    );
    Ok(())
}

/// Abstention completes a routing decision; it must not re-enter every pass.
#[test]
fn abstained_evidence_still_advances_the_cursor() -> Result<()> {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let Grounded { actor, skill } = ground(&vault, 0x29, 0x2A)?;
    let receipt = stamped_receipt(&vault, FIXTURE_SKILL_ID)?;
    // A SUCCEEDED attempt abstains: this projector routes blame, and crediting
    // a win is the reliability posterior's job (ONE-1738).
    record_attribution_evidence(
        &vault,
        &evidence(
            &receipt,
            actor,
            skill,
            AttemptOutcome::Succeeded,
            true,
            true,
        ),
    )?;

    assert_eq!(run_attribution_projector(&vault, 0)?.len(), 0);
    assert_eq!(
        read_attribution_cursor(&vault)?,
        1,
        "an abstention is a completed decision, not a retryable failure"
    );
    Ok(())
}

/// Unsettled routing facts abstain rather than guess — the ambiguous case the
/// LLM tier exists for.
#[test]
fn unsettled_routing_facts_abstain() -> Result<()> {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let Grounded { actor, skill } = ground(&vault, 0x2B, 0x2C)?;
    let receipt = stamped_receipt(&vault, FIXTURE_SKILL_ID)?;
    let ambiguous =
        OutcomeEvidence::new(receipt, actor, AttemptOutcome::Failed, 5).with_skill(skill);
    record_attribution_evidence(&vault, &ambiguous)?;

    assert_eq!(run_attribution_projector(&vault, 0)?.len(), 0);
    assert_eq!(attribution_judgments(&vault)?.len(), 0);
    Ok(())
}

/// A skill-lane verdict needs a skill to route to; evidence with none abstains
/// rather than falling through to the actor's lane.
#[test]
fn skill_lane_evidence_without_a_skill_abstains() -> Result<()> {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let Grounded { actor, skill } = ground(&vault, 0x2D, 0x2E)?;
    let receipt = stamped_receipt(&vault, FIXTURE_SKILL_ID)?;
    let mut orphan = evidence(&receipt, actor, skill, AttemptOutcome::Failed, true, true);
    orphan.skill = None;
    record_attribution_evidence(&vault, &orphan)?;

    assert_eq!(
        run_attribution_projector(&vault, 0)?.len(),
        0,
        "no skill to blame, and blaming the actor would be a fabrication"
    );
    Ok(())
}

/// Persisted judgments round-trip: layers 2 and 3 read the stored rows, not
/// this pass's return value.
#[test]
fn persisted_judgments_round_trip() -> Result<()> {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let Grounded { actor, skill } = ground(&vault, 0x2F, 0x30)?;
    let receipt = stamped_receipt(&vault, FIXTURE_SKILL_ID)?;
    record_attribution_evidence(
        &vault,
        &evidence(&receipt, actor, skill, AttemptOutcome::Failed, true, true),
    )?;
    let minted = run_attribution_projector(&vault, 0)?;

    assert_eq!(attribution_judgments(&vault)?, minted);
    Ok(())
}

// ─── Evidence grounding (ONE-1737 F2) ──────────────────────────────────

/// Every reference on an evidence row is resolved at the door. A string that
/// looks like a receipt, an actor nobody minted, a skill nobody minted, and a
/// skill the attempt never loaded are all FABRICATIONS — each one is a typed
/// refusal, and none of them reaches the evidence store.
#[test]
fn fabricated_evidence_references_are_refused_at_the_door() -> Result<()> {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let Grounded { actor, skill } = ground(&vault, 0x31, 0x32)?;
    let receipt = stamped_receipt(&vault, FIXTURE_SKILL_ID)?;
    let unloaded_skill = put_skill(&vault, entity(0x33), "attribution.fixture.other")?;

    let cases: [(OutcomeEvidence, &str); 4] = [
        (
            evidence(
                "attempt:00000000000000000000000000000000",
                actor,
                skill,
                AttemptOutcome::Failed,
                true,
                true,
            ),
            "attribution evidence cites an unstamped receipt",
        ),
        (
            evidence(
                &receipt,
                entity(0x34),
                skill,
                AttemptOutcome::Failed,
                true,
                true,
            ),
            "attribution evidence names an unknown actor",
        ),
        (
            evidence(
                &receipt,
                actor,
                entity(0x35),
                AttemptOutcome::Failed,
                true,
                true,
            ),
            "attribution evidence names an unknown skill",
        ),
        (
            evidence(
                &receipt,
                actor,
                unloaded_skill,
                AttemptOutcome::Failed,
                true,
                true,
            ),
            "attribution evidence names a skill absent from the receipt manifest",
        ),
    ];

    for (fabricated, expected) in cases {
        let error = record_attribution_evidence(&vault, &fabricated)
            .expect_err("a fabricated reference is refused");
        assert!(
            matches!(error, Error::InvalidClaimBody(reason) if reason == expected),
            "expected {expected}, got {error:?}"
        );
    }
    assert_eq!(
        run_attribution_projector(&vault, 0)?.len(),
        0,
        "nothing fabricated reached the evidence store"
    );
    Ok(())
}

/// The admitting case: an actor the vault knows, a skill the vault knows, and
/// a receipt whose manifest actually names that skill.
#[test]
fn grounded_evidence_naming_a_loaded_skill_is_admitted() -> Result<()> {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let Grounded { actor, skill } = ground(&vault, 0x36, 0x37)?;
    let receipt = stamped_receipt(&vault, FIXTURE_SKILL_ID)?;

    let sequence = record_attribution_evidence(
        &vault,
        &evidence(&receipt, actor, skill, AttemptOutcome::Failed, true, true),
    )?;

    assert_eq!(sequence, 1);
    let judgments = run_attribution_projector(&vault, 0)?;
    assert_eq!(judgments.len(), 1);
    assert_eq!(judgments[0].evidence_receipts, vec![receipt]);
    Ok(())
}

/// A receipt stamped before the manifest field-set existed cannot answer
/// "was this skill loaded" — an absent fact is not a failed check, so the
/// membership rule does not manufacture a refusal from it.
#[test]
fn a_receipt_without_a_manifest_field_does_not_gate_membership() -> Result<()> {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let Grounded { actor, skill } = ground(&vault, 0x38, 0x39)?;
    let receipt_ref = stamped_receipt(&vault, FIXTURE_SKILL_ID)?;
    let mut stripped = crate::receipt::attempt_pack_receipt(&vault, &receipt_ref)?
        .expect("the terminal stamped a receipt");
    stripped.fields.clear();
    crate::receipt::overwrite_attempt_pack_receipt_for_test(&vault, &stripped)?;

    record_attribution_evidence(
        &vault,
        &evidence(
            &receipt_ref,
            actor,
            skill,
            AttemptOutcome::Failed,
            true,
            true,
        ),
    )?;

    assert_eq!(run_attribution_projector(&vault, 0)?.len(), 1);
    Ok(())
}

/// The LLM tier stamps its own call purpose so attribution calls are budgeted
/// and audited as their own class.
#[test]
fn the_llm_tier_rides_the_existing_call_purpose_surface() {
    assert_eq!(
        attribution_call_purpose(),
        CallPurpose::Other {
            name: ATTRIBUTION_CALL_PURPOSE_NAME.to_owned()
        }
    );
}

/// A judge that always answers `SkillDefect` passes the defect fixtures and
/// fails the rest — the receipted pass-rate MOVES, so a false-pass-biased
/// judge is visible in an aggregate metric.
#[test]
fn a_broken_judge_moves_the_receipted_pass_rate() -> Result<()> {
    struct AlwaysDefect;
    impl AttributionJudge for AlwaysDefect {
        fn judge(&self, _evidence: &OutcomeEvidence) -> Result<Option<AttributionVerdict>> {
            Ok(Some(AttributionVerdict::SkillDefect))
        }
    }

    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let fixtures = held_out_audit_fixtures();

    let honest = run_attribution_audit_with_judge(&vault, &fixtures, &RuleAttributionJudge, 10)?;
    let broken = run_attribution_audit_with_judge(&vault, &fixtures, &AlwaysDefect, 20)?;

    assert!(
        (honest.pass_rate() - 1.0).abs() < f32::EPSILON,
        "the deterministic tier passes its own held-out set"
    );
    assert!(
        broken.pass_rate() < honest.pass_rate(),
        "the broken judge's pass-rate is detectably lower: {} vs {}",
        broken.pass_rate(),
        honest.pass_rate()
    );
    assert_eq!(broken.passed, 1, "only the true defect fixture matched");

    let reports = attribution_audit_reports(&vault)?;
    assert_eq!(reports.len(), 2, "both audits are receipted");
    assert!(
        reports
            .iter()
            .any(|report| report.at == 20 && report.passed == 1),
        "the broken judge's poor score is on the record, not just in the return"
    );
    Ok(())
}

/// A judge that abstains on everything must not score a perfect pass-rate:
/// "nothing was checked" is not "everything was right".
#[test]
fn an_abstaining_judge_does_not_score_a_perfect_pass_rate() -> Result<()> {
    struct AlwaysAbstain;
    impl AttributionJudge for AlwaysAbstain {
        fn judge(&self, _evidence: &OutcomeEvidence) -> Result<Option<AttributionVerdict>> {
            Ok(None)
        }
    }

    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let report =
        run_attribution_audit_with_judge(&vault, &held_out_audit_fixtures(), &AlwaysAbstain, 30)?;

    assert_eq!(report.abstained, report.total);
    assert!(
        report.pass_rate() < f32::EPSILON,
        "abstention scores zero, not one"
    );
    Ok(())
}

/// The built-in audit door receipts its pass-rate.
#[test]
fn the_audit_door_receipts_its_pass_rate() -> Result<()> {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());

    let rate = run_attribution_audit(&vault)?;

    assert!((rate - 1.0).abs() < f32::EPSILON);
    assert_eq!(attribution_audit_reports(&vault)?.len(), 1);
    Ok(())
}

/// An empty fixture set scores 0.0: an unchecked judge is the worst evidence,
/// never the best.
#[test]
fn an_empty_fixture_set_scores_zero() {
    let report = AttributionAuditReport {
        total: 0,
        passed: 0,
        abstained: 0,
        at: 1,
    };
    assert!(report.pass_rate() < f32::EPSILON);
}
