use super::*;

use rmpv::Value;

use crate::claim::ClaimLifecycleStatus;
use crate::config::VaultConfig;
use crate::edit_distance::delta::{delta_from_reconstructed, put_amendment_delta_in_txn};
use crate::error::ClaimError;
use crate::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
use crate::skill::{SkillLifecycle, SkillRecord, canonical_skill_tree_hash};

// ─── fixtures ───────────────────────────────────────────────────────────

fn temp_vault() -> (tempfile::TempDir, Vault) {
    let tmp = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(tmp.path(), VaultConfig::default()).expect("open vault");
    (tmp, vault)
}

fn t(ts: u64) -> TimeRange {
    TimeRange { start: ts, end: ts }
}

fn put_actor(vault: &Vault) -> Result<EntityId> {
    let id = EntityId::now();
    vault.put_entity(&id, ENTITY_TYPE_PERSON, t(1), 1, b"ed03 actor fixture")?;
    Ok(id)
}

fn put_skill(vault: &Vault, skill_id: &str) -> Result<EntityId> {
    let id = EntityId::now();
    let tree_hash = canonical_skill_tree_hash([("SKILL.md", b"# ed03 fixture\n".as_slice())])
        .expect("fixture tree hashes");
    let candidate = SkillRecord::new(
        skill_id,
        "ed03 fixture skill",
        "1.0.0",
        ClaimApprovalStatus::Approved,
        SkillLifecycle::Candidate,
        ClaimSource::UserStated,
        0.9,
        false,
        true,
        Vec::new(),
        Value::Map(vec![(Value::from("source"), Value::from("ed03-fixture"))]),
    )
    .with_content_hash(tree_hash);
    vault.put_skill_record(&id, &candidate, t(10), 11)?;
    let mut active = candidate;
    active.lifecycle_status = SkillLifecycle::Active;
    vault.update_skill_record(&id, &active, t(12), 13)?;
    Ok(id)
}

/// Records a real ED-01 Δ against `receipt_id`, so the evidence door's
/// grounding resolves the way production's would.
fn measure_amendment(vault: &Vault, receipt_id: &str, before: &str, after: &str) -> Result<f32> {
    let delta = delta_from_reconstructed(before, after);
    let d_norm = delta.d_norm;
    vault.with_write_txn(|wtxn| {
        put_amendment_delta_in_txn(vault, wtxn, receipt_id, &delta)?;
        Ok(())
    })?;
    Ok(d_norm)
}

fn active_rows(vault: &Vault, subject: &EntityId, predicate: &str) -> Result<Vec<ClaimBody>> {
    let mut out = Vec::new();
    for id in vault.claims_for_subject(subject)? {
        let Some(body) = vault.get_claim(&id)? else {
            continue;
        };
        if body.predicate == predicate && body.lifecycle == ClaimLifecycleStatus::Active {
            out.push(body);
        }
    }
    Ok(out)
}

// ─── the evidence door ──────────────────────────────────────────────────

#[test]
fn the_evidence_door_resolves_every_reference() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = put_actor(&vault)?;
    let skill = put_skill(&vault, "ed03.grounding")?;
    measure_amendment(&vault, "receipt:grounded", "one two three", "one two four")?;

    // A receipt nobody measured is not a trace, it is a receipt id.
    let unmeasured = AmendmentEvidence::new("receipt:absent", actor, "outbound").at(5);
    assert!(record_amendment_evidence(&vault, &unmeasured).is_err());

    let unknown_actor =
        AmendmentEvidence::new("receipt:grounded", EntityId::now(), "outbound").at(5);
    assert!(record_amendment_evidence(&vault, &unknown_actor).is_err());

    let unknown_skill = AmendmentEvidence::new("receipt:grounded", actor, "outbound")
        .at(5)
        .with_skill(EntityId::now());
    assert!(record_amendment_evidence(&vault, &unknown_skill).is_err());

    let blank_scope = AmendmentEvidence::new("receipt:grounded", actor, "   ").at(5);
    assert!(record_amendment_evidence(&vault, &blank_scope).is_err());

    let good = AmendmentEvidence::new("receipt:grounded", actor, " outbound ")
        .at(5)
        .with_skill(skill)
        .with_cause(AmendmentCause::ProposalWrong)
        .with_routing_facts(true, true);
    record_amendment_evidence(&vault, &good)?;
    let read = amendment_evidence(&vault, "receipt:grounded")?.expect("the recorded facts");
    assert_eq!(
        read.scope, "outbound",
        "the scope is normalized at the door"
    );
    assert_eq!(read.actor, actor);
    assert_eq!(read.skill, Some(skill));
    assert_eq!(read.cause, Some(AmendmentCause::ProposalWrong));
    Ok(())
}

// ─── judged class → the right subject ───────────────────────────────────

/// Records + judges one amendment, returning the judgment.
fn judged(
    vault: &Vault,
    receipt: &str,
    evidence: AmendmentEvidence,
    before: &str,
    after: &str,
) -> Result<Option<AmendmentJudgment>> {
    measure_amendment(vault, receipt, before, after)?;
    record_amendment_evidence(vault, &evidence)?;
    judge_amendment(vault, receipt)
}

// ─── the write door's guards ────────────────────────────────────────────

#[test]
fn a_forged_judgment_lands_nothing() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = put_actor(&vault)?;
    let skill = put_skill(&vault, "ed03.forgery")?;
    measure_amendment(&vault, "receipt:forged", "before", "after")?;

    // Never routed by this module: a caller-built row asserting its own class.
    let forged = AmendmentJudgment {
        receipt_id: "receipt:forged".to_owned(),
        split: vec![AmendmentShare {
            class: AmendmentClass::SkillDefect,
            share: 1.0,
            subject: Some(skill),
        }],
        scope: "outbound".to_owned(),
        evidence_receipts: vec!["receipt:forged".to_owned()],
        d_norm: 1.0,
        at: 50,
    };
    assert!(project_edit_cost_claims(&vault, std::slice::from_ref(&forged))?.is_empty());
    assert!(active_rows(&vault, &skill, PREDICATE_SKILL_EDIT_COST)?.is_empty());

    // The same row, once it IS what this module routed, lands — so the refusal
    // above is the grounding check and not an unrelated failure.
    record_amendment_evidence(
        &vault,
        &AmendmentEvidence::new("receipt:forged", actor, "outbound")
            .at(50)
            .with_skill(skill)
            .with_cause(AmendmentCause::ProposalWrong)
            .with_routing_facts(true, true),
    )?;
    let routed = judge_amendment(&vault, "receipt:forged")?.expect("a settled amendment routes");
    assert!(!project_edit_cost_claims(&vault, &[routed])?.is_empty());
    Ok(())
}

#[test]
fn the_evidence_door_refuses_a_subject_that_cannot_act() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    measure_amendment(&vault, "receipt:turn", "one two", "one three")?;
    let turn = EntityId::now();
    vault.put_entity(&turn, ENTITY_TYPE_TURN, t(1), 1, b"")?;

    let evidence = AmendmentEvidence::new("receipt:turn", turn, "outbound")
        .at(160)
        .with_cause(AmendmentCause::ProposalWrong)
        .with_routing_facts(false, true);
    assert!(
        record_amendment_evidence(&vault, &evidence).is_err(),
        "a TURN cannot be charged an actor.edit_cost, so the door refuses it \
         here rather than wedging the projector two passes later"
    );
    Ok(())
}

// ─── reserved namespace ─────────────────────────────────────────────────

#[test]
fn public_writes_of_both_cost_predicates_are_reserved() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = put_actor(&vault)?;

    for predicate in [PREDICATE_ACTOR_EDIT_COST, PREDICATE_SKILL_EDIT_COST] {
        let mut body = ClaimBody::new(
            predicate,
            ClaimSubject::Entity(actor),
            Value::F32(0.0),
            1.0,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        )?;
        body.evidence = Some(Value::from("forged"));
        body.source = Some(ClaimSource::Observed);
        let error = vault
            .put_claim(&EntityId::now(), &body, t(80), 80)
            .expect_err("the generic claim API must refuse a reserved predicate");
        assert!(
            matches!(error, Error::Claim(ClaimError::ReservedPredicate { .. })),
            "typed reserved-namespace rejection, got {error:?}"
        );
    }
    Ok(())
}

// ─── the Blind Curator audit ────────────────────────────────────────────

#[test]
fn archived_amendment_costs_are_inert_and_not_projector_history() -> Result<()> {
    let (_source_dir, source) = temp_vault();
    let (_target_dir, target) = temp_vault();
    let actor = put_actor(&source)?;
    let skill = put_skill(&source, "archive.amendment.cost")?;
    let mut judgments = Vec::new();
    for (receipt, followed) in [("archive:defect", true), ("archive:lapse", false)] {
        judgments.push(
            judged(
                &source,
                receipt,
                AmendmentEvidence::new(receipt, actor, "outbound")
                    .at(50)
                    .with_skill(skill)
                    .with_cause(AmendmentCause::ProposalWrong)
                    .with_routing_facts(followed, true),
                "old wording",
                "better wording",
            )?
            .unwrap(),
        );
    }
    let ids = project_edit_cost_claims(&source, &judgments)?;
    assert_eq!(ids.len(), 2);
    let archive = source.export_whole_vault(crate::context_pack::PackFormat::Json)?;
    target.import_whole_vault_json(archive.bytes())?;
    assert_eq!(
        target
            .import_whole_vault_json(archive.bytes())?
            .inserted_entities,
        0
    );
    let mut preserved = Vec::new();
    for id in &ids {
        let body = target.get_claim(id)?.unwrap();
        let before = source.get_claim(id)?.unwrap();
        assert_eq!(body.value, before.value);
        assert_eq!(body.evidence, before.evidence);
        assert_eq!(body.source, Some(ClaimSource::Imported));
        assert_eq!(body.approval, ClaimApprovalStatus::Proposed);
        for approval in [ClaimApprovalStatus::Auto, ClaimApprovalStatus::Approved] {
            let mut forged = body.clone();
            forged.approval = approval;
            let bytes = crate::claim::encode_claim_body(&forged)?;
            assert!(
                target
                    .batch()
                    .put_replicated(
                        &EntityId::now(),
                        crate::registry::ENTITY_TYPE_CLAIM,
                        t(70),
                        70,
                        &bytes
                    )
                    .commit()
                    .is_err()
            );
        }
        preserved.push(body);
    }
    assert_eq!(edit_cost_for(&target, &actor, "outbound")?, None);
    assert_eq!(edit_cost_for(&target, &skill, "outbound")?, None);
    assert!(project_edit_cost_claims(&target, &judgments)?.is_empty());
    let local = judged(
        &target,
        "local:defect",
        AmendmentEvidence::new("local:defect", actor, "outbound")
            .at(80)
            .with_skill(skill)
            .with_cause(AmendmentCause::ProposalWrong)
            .with_routing_facts(true, true),
        "one two",
        "one three",
    )?
    .unwrap();
    let fresh = project_edit_cost_claims(&target, &[local])?;
    assert_eq!(fresh.len(), 1);
    assert!(!ids.contains(&fresh[0]));
    assert!(edit_cost_for(&target, &skill, "outbound")?.is_some());
    for (id, before) in ids.iter().zip(preserved) {
        assert_eq!(target.get_claim(id)?, Some(before));
    }
    Ok(())
}

// ─── split verdicts and unclear (ARCH-0056 §5, owner 2026-10-08) ──────────

/// Labels the first hunk the skill's defect and the second the executor's
/// lapse, both above the floor.
struct DefectThenLapse;

impl AttributionJudge for DefectThenLapse {
    fn judge(&self, _evidence: &OutcomeEvidence) -> Result<Option<AttributionVerdict>> {
        Ok(None)
    }

    fn judge_hunks(&self, request: &JudgeRequest<'_>) -> Result<Option<Vec<HunkVerdict>>> {
        assert_eq!(request.hunks.len(), 2, "the judge sees every changed hunk");
        Ok(Some(vec![
            HunkVerdict::with_confidence(AttributionVerdict::SkillDefect, 0.9),
            HunkVerdict::with_confidence(AttributionVerdict::ExecutionLapse, 0.8),
        ]))
    }
}

/// A verdict is a label + % split by hunk, and each route takes only its
/// share. One amendment whose first hunk is the skill's defect and whose
/// second is the executor's lapse charges the skill and the actor each their
/// hunk's share of the edit — weighted by the hunk's own measured edit mass —
/// and the two charges together are the whole edit.
#[test]
fn a_two_hunk_edit_charges_each_route_only_its_share() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = put_actor(&vault)?;
    let skill = put_skill(&vault, "ed03.split")?;
    let receipt = "receipt:split";
    let hunks = [
        EditHunk {
            before: "Dear team,",
            after: "Hello team,",
        },
        EditHunk {
            before: "the launch moves to Friday.",
            after: "the launch moves to Monday.\nThe review comes first.\nBring the numbers.",
        },
    ];
    let d_norm = measure_amendment(
        &vault,
        receipt,
        "Dear team,\nthe launch moves to Friday.\nRegards",
        "Hello team,\nthe launch moves to Monday.\nThe review comes first.\nBring the numbers.\nRegards",
    )?;
    record_amendment_evidence(
        &vault,
        &AmendmentEvidence::new(receipt, actor, "outbound")
            .at(70)
            .with_skill(skill)
            .with_cause(AmendmentCause::ProposalWrong)
            .with_routing_facts(true, true),
    )?;

    let judgment = judge_amendment_hunks(&vault, receipt, &DefectThenLapse, &hunks)?
        .expect("a split amendment routes");
    // Each hunk weighs what the pinned ED metric measures for it.
    let mass = |hunk: &EditHunk<'_>| {
        delta_from_reconstructed(hunk.before, hunk.after)
            .ops_summary
            .edit_mass()
    };
    let defect_share = mass(&hunks[0]) / (mass(&hunks[0]) + mass(&hunks[1]));
    assert!(
        defect_share > 0.0 && defect_share < 0.5,
        "the bigger hunk carries the bigger share"
    );
    assert!(
        (f64::from(judgment.share_of(AmendmentClass::SkillDefect)) - defect_share).abs() < 1e-6
    );
    assert!(
        (f64::from(judgment.share_of(AmendmentClass::ExecutionLapse)) - (1.0 - defect_share)).abs()
            < 1e-6
    );

    project_edit_cost_claims(&vault, std::slice::from_ref(&judgment))?;
    let skill_cost = f64::from(
        edit_cost_for(&vault, &skill, "outbound")?.expect("the skill is charged its share"),
    );
    let actor_cost = f64::from(
        edit_cost_for(&vault, &actor, "outbound")?.expect("the actor is charged its share"),
    );
    let d_norm = f64::from(d_norm);
    assert!((skill_cost - defect_share * d_norm).abs() < 1e-5);
    assert!((actor_cost - (1.0 - defect_share) * d_norm).abs() < 1e-5);
    assert!(
        (skill_cost + actor_cost - d_norm).abs() < 1e-5,
        "the shares together are the whole edit, charged once"
    );
    Ok(())
}

/// An `unclear` hunk holds: it charges nobody, and its note lands in the
/// unclear ledger. The clear hunk beside it is charged its own share alone,
/// and a re-judgment that clears the doubt withdraws the note.
#[test]
fn an_unclear_hunk_charges_nobody_and_files_its_note() -> Result<()> {
    struct DefectThenUnsure;
    impl AttributionJudge for DefectThenUnsure {
        fn judge(&self, _evidence: &OutcomeEvidence) -> Result<Option<AttributionVerdict>> {
            Ok(None)
        }
        fn judge_hunks(&self, _request: &JudgeRequest<'_>) -> Result<Option<Vec<HunkVerdict>>> {
            Ok(Some(vec![
                HunkVerdict::with_confidence(AttributionVerdict::SkillDefect, 0.9),
                HunkVerdict::with_confidence(AttributionVerdict::Unclear, 0.7)
                    .with_note("a new date with no stated reason"),
            ]))
        }
    }

    let (_tmp, vault) = temp_vault();
    let actor = put_actor(&vault)?;
    let skill = put_skill(&vault, "ed03.unclear")?;
    let receipt = "receipt:unclear";
    let hunks = [
        EditHunk {
            before: "alpha",
            after: "omega",
        },
        EditHunk {
            before: "beta",
            after: "gamma",
        },
    ];
    let d_norm = measure_amendment(&vault, receipt, "alpha\nbeta\n", "omega\ngamma\n")?;
    record_amendment_evidence(
        &vault,
        &AmendmentEvidence::new(receipt, actor, "outbound")
            .at(80)
            .with_skill(skill)
            .with_cause(AmendmentCause::ProposalWrong)
            .with_routing_facts(true, true),
    )?;

    let judgment = judge_amendment_hunks(&vault, receipt, &DefectThenUnsure, &hunks)?
        .expect("a partly clear amendment routes");
    let unclear_share = judgment.share_of(AmendmentClass::Unclear);
    assert!(unclear_share > 0.0 && unclear_share < 1.0);
    project_edit_cost_claims(&vault, std::slice::from_ref(&judgment))?;
    let skill_cost = edit_cost_for(&vault, &skill, "outbound")?.expect("the clear hunk charges");
    assert!(
        (f64::from(skill_cost) - f64::from(1.0 - unclear_share) * f64::from(d_norm)).abs() < 1e-5,
        "the skill carries the clear hunk's share alone"
    );
    assert!(
        active_rows(&vault, &actor, PREDICATE_ACTOR_EDIT_COST)?.is_empty(),
        "the unclear hunk charges nobody"
    );

    let filed = crate::skill_attribution::unclear_attributions(&vault)?;
    assert_eq!(filed.len(), 1);
    assert_eq!(filed[0].reference, receipt);
    assert_eq!(
        filed[0].notes[0].note.as_deref(),
        Some("a new date with no stated reason")
    );
    assert!((filed[0].share() - unclear_share).abs() < 1e-6);

    // Re-judged as one region by the rule tier: nothing is unclear any more,
    // so the note it no longer stands behind is withdrawn.
    judge_amendment(&vault, receipt)?.expect("the rule tier routes it");
    assert!(crate::skill_attribution::unclear_attributions(&vault)?.is_empty());
    Ok(())
}

/// Sol review, 10-08: a confidence that is not a number held a verdict only
/// while the floor was above zero, and a doubted hunk with no note reached the
/// ledger. A doubt holds at any floor, and must say why: one that does not is
/// refused rather than filed (ARCH-0056 §5: the judge always adds a note).
#[test]
fn a_doubt_holds_at_any_floor_and_must_say_why() -> Result<()> {
    struct Answers(HunkVerdict);
    impl AttributionJudge for Answers {
        fn judge(&self, _evidence: &OutcomeEvidence) -> Result<Option<AttributionVerdict>> {
            Ok(None)
        }
        fn judge_hunks(&self, _request: &JudgeRequest<'_>) -> Result<Option<Vec<HunkVerdict>>> {
            Ok(Some(vec![self.0.clone()]))
        }
    }
    let evidence = AmendmentEvidence::new("r:1", EntityId::now(), "outbound")
        .at(5)
        .with_skill(EntityId::now())
        .with_cause(AmendmentCause::ProposalWrong)
        .with_routing_facts(true, true);

    let unmeasured = Answers(
        HunkVerdict::with_confidence(AttributionVerdict::SkillDefect, f32::NAN)
            .with_note("the score came back empty"),
    );
    let split = classify_amendment(&evidence, &unmeasured, &[], 0.0)?.expect("an answer");
    assert_eq!(split.sole(), Some(AttributionVerdict::Unclear));
    assert_eq!(
        split.unclear[0].reason,
        crate::skill_attribution::UnclearReason::BelowFloor
    );

    for silent in [
        HunkVerdict::certain(AttributionVerdict::Unclear).with_note("  "),
        HunkVerdict::with_confidence(AttributionVerdict::SkillDefect, 0.2),
    ] {
        assert!(matches!(
            classify_amendment(&evidence, &Answers(silent), &[], 0.6),
            Err(Error::InvalidClaimBody(_))
        ));
    }
    Ok(())
}
