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

// ─── every share lands where §5 says (surfacing events 1–3, 10-08) ────────

/// The executor stamp every attempt fixture below runs under.
const MODEL: &str = "fixture/model@1";

/// A terminal attempt by `actor` whose pack loaded `skill_id`@1.0.0, returning
/// its stamped pack receipt — the receipt an amendment joins to.
fn terminal_attempt(vault: &Vault, actor: EntityId, skill_id: &str, failed: bool) -> Result<String> {
    use crate::attempt_queue::{
        AttemptQueue, ClaimAttempt, ClaimOutcome, CompleteAttempt, EnqueueAttempt,
        EnqueueOutcome, FailAttempt, ManifestEntry, ManifestKind,
    };
    let queue = AttemptQueue::new(vault);
    let EnqueueOutcome::Enqueued(row) = queue.enqueue(EnqueueAttempt {
        kind: "ed03.amended".to_owned(),
        payload: Vec::new(),
        dedupe_key: None,
        run_id: None,
        now: 10,
    })?
    else {
        panic!("a fresh attempt enqueues")
    };
    vault.bind_actor_attempt(row.id, &actor)?;
    queue.append_manifest_entry(
        row.id,
        ManifestEntry::new(ManifestKind::Skill, skill_id, "1.0.0", 11),
    )?;
    let ClaimOutcome::Claimed(leased) = queue.claim_kind(
        "ed03.amended",
        ClaimAttempt {
            lease_owner: "host".to_owned(),
            now: 12,
        },
    )?
    else {
        panic!("the attempt leases")
    };
    queue.set_executor_model(row.id, "host", leased.attempt_count, MODEL)?;
    if failed {
        queue.fail(FailAttempt {
            id: row.id,
            lease_owner: "host".to_owned(),
            attempt_count: leased.attempt_count,
            reason: "failed check".to_owned(),
            now: 13,
        })?;
    } else {
        queue.complete(CompleteAttempt {
            id: row.id,
            lease_owner: "host".to_owned(),
            attempt_count: leased.attempt_count,
            now: 13,
        })?;
    }
    Ok(crate::receipt::attempt_pack_receipt_id(&row.id))
}

/// The attempt arm's reliability posterior as `(alpha, beta)`.
fn arm_posterior(vault: &Vault, skill: &EntityId) -> Result<(f32, f32)> {
    use crate::skill_reliability::skill_reliability_posterior_for_executor;
    let read = skill_reliability_posterior_for_executor(vault, skill, MODEL)?
        .expect("the attempt's arm has a posterior");
    Ok((read.alpha, read.beta))
}

/// Packet check (canon §5, `skill_defect` → `learning.reliability`): one
/// amended attempt moves reliability once, by the defect share, and the
/// attempt's earlier win is replaced, not added to. A second amendment of the
/// same attempt replaces the first, and an amendment judged again without a
/// defect share hands the attempt back its own win.
#[test]
fn an_amended_attempt_counts_once_as_its_defect_share() -> Result<()> {
    use crate::skill_reliability::{
        project_skill_reliability_for_executor, record_skill_contributing_win,
        skill_reliability_prior,
    };
    let (_tmp, vault) = temp_vault();
    let actor = put_actor(&vault)?;
    let skill = put_skill(&vault, "ed03.reliability")?;
    let attempt = terminal_attempt(&vault, actor, "ed03.reliability", false)?;
    let prior = skill_reliability_prior(&vault, &skill)?;
    let posterior = |vault: &Vault| arm_posterior(vault, &skill);

    // The attempt lane's record: the completed attempt is a contributing win.
    record_skill_contributing_win(&vault, &skill, &attempt, 20)?;
    project_skill_reliability_for_executor(&vault, &skill, MODEL, 20)?;
    assert_eq!(posterior(&vault)?, (prior.alpha + 1.0, prior.beta));

    // The decider approves the attempt's proposal with an edit, and the judge
    // splits it between the skill and the executor.
    let receipt = "receipt:amended-attempt";
    let hunks = [
        EditHunk {
            before: "Dear team,",
            after: "Hello team,",
        },
        EditHunk {
            before: "the launch moves to Friday.",
            after: "the launch moves to Monday.\nThe review comes first.",
        },
    ];
    measure_amendment(
        &vault,
        receipt,
        "Dear team,\nthe launch moves to Friday.\n",
        "Hello team,\nthe launch moves to Monday.\nThe review comes first.\n",
    )?;
    let evidence = AmendmentEvidence::new(receipt, actor, "outbound")
        .at(70)
        .with_skill(skill)
        .with_attempt(attempt.clone())
        .with_cause(AmendmentCause::ProposalWrong)
        .with_routing_facts(true, true);
    record_amendment_evidence(&vault, &evidence)?;
    let judgment = judge_amendment_hunks(&vault, receipt, &DefectThenLapse, &hunks)?
        .expect("a split amendment routes");
    let defect_share = judgment.share_of(AmendmentClass::SkillDefect);
    assert!(defect_share > 0.0 && defect_share < 1.0);

    assert_eq!(project_amendment_reliability(&vault)?, vec![skill]);
    let (alpha, beta) = posterior(&vault)?;
    assert_eq!(alpha, prior.alpha, "the earlier win is replaced");
    assert!(
        (beta - (prior.beta + defect_share)).abs() < 1e-6,
        "the attempt counts once, as a loss of the defect share"
    );

    // Replays move nothing: neither the amendment pass again, nor the attempt
    // lane crediting the same win again.
    assert!(project_amendment_reliability(&vault)?.is_empty());
    record_skill_contributing_win(&vault, &skill, &attempt, 20)?;
    project_skill_reliability_for_executor(&vault, &skill, MODEL, 20)?;
    assert_eq!(posterior(&vault)?, (alpha, beta));

    // A later amendment of the same attempt is the later verdict: it replaces
    // the first one's share rather than adding its own.
    let again = "receipt:amended-again";
    measure_amendment(&vault, again, "Regards", "Best regards")?;
    record_amendment_evidence(
        &vault,
        &AmendmentEvidence::new(again, actor, "outbound")
            .at(80)
            .with_skill(skill)
            .with_attempt(attempt.clone())
            .with_cause(AmendmentCause::ProposalWrong)
            .with_routing_facts(true, true),
    )?;
    judge_amendment(&vault, again)?.expect("a followed, covered step is the skill's defect");
    assert_eq!(project_amendment_reliability(&vault)?, vec![skill]);
    assert_eq!(posterior(&vault)?, (prior.alpha, prior.beta + 1.0));

    // Judged again as the decider's taste, the later amendment charges the
    // skill nothing, and the attempt is its own win once more.
    record_amendment_evidence(
        &vault,
        &AmendmentEvidence::new(again, actor, "outbound")
            .at(80)
            .with_skill(skill)
            .with_attempt(attempt)
            .with_cause(AmendmentCause::DeciderPreference),
    )?;
    judge_amendment(&vault, again)?.expect("a preference routes");
    assert_eq!(project_amendment_reliability(&vault)?, vec![skill]);
    assert_eq!(posterior(&vault)?, (prior.alpha + 1.0, prior.beta));
    Ok(())
}

/// Sol review, 10-10: withdrawing the amendment of an attempt the attempt lane
/// never recorded left its loss behind as imported history, and correcting the
/// evidence to another attempt moved the old verdict there before any judge had
/// seen the correction. A verdict stays on the attempt it was judged against,
/// and its withdrawal leaves the prior exactly.
#[test]
fn a_withdrawn_or_rejoined_amendment_leaves_no_stale_loss() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = put_actor(&vault)?;
    let skill = put_skill(&vault, "ed03.withdrawn")?;
    let first = terminal_attempt(&vault, actor, "ed03.withdrawn", false)?;
    let second = terminal_attempt(&vault, actor, "ed03.withdrawn", false)?;
    let prior = crate::skill_reliability::skill_reliability_prior(&vault, &skill)?;
    let receipt = "receipt:withdrawn";
    measure_amendment(&vault, receipt, "Ship it Friday.", "Ship it Monday.")?;
    let defect = |attempt: &str| {
        AmendmentEvidence::new(receipt, actor, "outbound")
            .at(70)
            .with_skill(skill)
            .with_attempt(attempt)
            .with_cause(AmendmentCause::ProposalWrong)
            .with_routing_facts(true, true)
    };
    record_amendment_evidence(&vault, &defect(&first))?;
    judge_amendment(&vault, receipt)?.expect("a followed, covered step is the skill's defect");
    assert_eq!(project_amendment_reliability(&vault)?, vec![skill]);
    assert_eq!(arm_posterior(&vault, &skill)?, (prior.alpha, prior.beta + 1.0));

    record_amendment_evidence(&vault, &defect(&second))?;
    assert!(
        project_amendment_reliability(&vault)?.is_empty(),
        "evidence alone does not move a judged verdict"
    );

    record_amendment_evidence(
        &vault,
        &defect(&second).with_cause(AmendmentCause::DeciderPreference),
    )?;
    judge_amendment(&vault, receipt)?.expect("a preference routes");
    assert_eq!(project_amendment_reliability(&vault)?, vec![skill]);
    assert_eq!(
        arm_posterior(&vault, &skill)?,
        (prior.alpha, prior.beta),
        "the withdrawn loss is gone, not kept as imported history"
    );
    Ok(())
}

/// The join is grounded at the door by the attempt lane's own check: an
/// attempt nobody stamped, or one another actor ran, is refused.
#[test]
fn the_attempt_join_is_grounded_at_the_door() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = put_actor(&vault)?;
    let stranger = put_actor(&vault)?;
    let skill = put_skill(&vault, "ed03.join")?;
    let attempt = terminal_attempt(&vault, actor, "ed03.join", false)?;
    measure_amendment(&vault, "receipt:join", "a", "b")?;
    let evidence = |actor: EntityId, attempt: &str| {
        AmendmentEvidence::new("receipt:join", actor, "outbound")
            .at(70)
            .with_skill(skill)
            .with_attempt(attempt)
    };
    assert!(record_amendment_evidence(&vault, &evidence(actor, "attempt:00")).is_err());
    assert!(record_amendment_evidence(&vault, &evidence(stranger, &attempt)).is_err());
    record_amendment_evidence(&vault, &evidence(actor, &attempt))?;
    assert_eq!(
        amendment_evidence(&vault, "receipt:join")?.and_then(|row| row.attempt_receipt),
        Some(attempt)
    );
    Ok(())
}

/// Packet check (canon §5, `discovery` mints a skill edit proposal): a
/// discovery share creates exactly one edit proposal, with the same shape as
/// the attempt lane's, through the same door. Judging again keeps it one, and
/// a re-judgment without the discovery withdraws it.
#[test]
fn a_discovery_share_mints_one_edit_proposal_shaped_like_the_attempt_lanes() -> Result<()> {
    use crate::skill_attribution::{
        AttemptOutcome, SkillEditProposal, pending_edit_proposals, record_attribution_evidence,
        run_attribution_projector,
    };
    let (_tmp, vault) = temp_vault();
    let actor = put_actor(&vault)?;
    let skill = put_skill(&vault, "ed03.discovery")?;

    // The attempt lane's own discovery: a failed attempt whose skill lacked the step.
    let attempt = terminal_attempt(&vault, actor, "ed03.discovery", true)?;
    let failed = OutcomeEvidence::new(attempt.as_str(), actor, AttemptOutcome::Failed, 50)
        .with_skill(skill)
        .with_routing_facts(true, false);
    record_attribution_evidence(&vault, &failed)?;
    run_attribution_projector(&vault, 0)?;
    let attempt_lane = pending_edit_proposals(&vault)?;
    assert_eq!(attempt_lane.len(), 1);

    let receipt = "receipt:discovery";
    measure_amendment(&vault, receipt, "Send the deck.", "Send the deck and the notes.")?;
    let discovered = AmendmentEvidence::new(receipt, actor, "outbound")
        .at(70)
        .with_skill(skill)
        .with_cause(AmendmentCause::ProposalWrong)
        .with_routing_facts(true, false);
    record_amendment_evidence(&vault, &discovered)?;
    let judgment = judge_amendment(&vault, receipt)?.expect("a missing step is a discovery");
    assert_eq!(judgment.sole_class(), Some(AmendmentClass::Discovery));

    let minted = |vault: &Vault| -> Result<Vec<SkillEditProposal>> {
        Ok(pending_edit_proposals(vault)?
            .into_iter()
            .filter(|proposal| proposal.evidence_receipts == [receipt])
            .collect())
    };
    let proposals = minted(&vault)?;
    assert_eq!(proposals.len(), 1, "one discovery share, one proposal");
    let proposal = &proposals[0];
    assert_eq!(
        *proposal,
        SkillEditProposal {
            judgment_sequence: proposal.judgment_sequence,
            skill,
            evidence_receipts: vec![receipt.to_owned()],
            at: 70,
        }
    );
    assert_ne!(
        proposal.judgment_sequence, attempt_lane[0].judgment_sequence,
        "both lanes mint into one keyspace without colliding"
    );
    assert_eq!(attempt_lane[0].skill, proposal.skill);

    judge_amendment(&vault, receipt)?.expect("judged again");
    assert_eq!(minted(&vault)?, proposals, "judging again keeps it one");

    record_amendment_evidence(&vault, &discovered.with_routing_facts(true, true))?;
    judge_amendment(&vault, receipt)?.expect("now the skill's defect");
    assert!(minted(&vault)?.is_empty(), "the proposal leaves with its discovery");
    assert_eq!(pending_edit_proposals(&vault)?, attempt_lane);
    Ok(())
}

/// Packet check (canon §5, `execution_lapse` → the actor lesson): an execution
/// lapse adds one actor lesson that cites its amendment receipt. A replay adds
/// nothing, a second lapse is a second entry, and a re-judgment that clears the
/// actor retracts the lesson.
#[test]
fn an_execution_lapse_adds_one_actor_lesson_citing_its_amendment() -> Result<()> {
    use crate::actor_claims::{ActorClaimEvidence, PREDICATE_ACTOR_LESSON};
    let (_tmp, vault) = temp_vault();
    let actor = put_actor(&vault)?;
    let skill = put_skill(&vault, "ed03.lapse")?;
    let lapse = |receipt: &str, at: u64| {
        AmendmentEvidence::new(receipt, actor, "outbound")
            .at(at)
            .with_skill(skill)
            .with_cause(AmendmentCause::ProposalWrong)
            .with_routing_facts(false, true)
    };

    let receipt = "receipt:lapse";
    measure_amendment(&vault, receipt, "Ship it Friday.", "Ship it Monday.")?;
    record_amendment_evidence(&vault, &lapse(receipt, 70))?;
    let judgment = judge_amendment(&vault, receipt)?.expect("an ignored skill is a lapse");
    assert_eq!(judgment.sole_class(), Some(AmendmentClass::ExecutionLapse));

    let landed = project_amendment_lessons(&vault, std::slice::from_ref(&judgment))?;
    assert_eq!(landed.len(), 1);
    let lessons = active_rows(&vault, &actor, PREDICATE_ACTOR_LESSON)?;
    assert_eq!(lessons.len(), 1, "one lapse, one lesson");
    assert_eq!(
        lessons[0].evidence,
        Some(ActorClaimEvidence::amendment(vec![receipt.to_owned()], 70)?.to_value()),
        "the lesson cites its amendment receipt"
    );
    assert_eq!(
        lessons[0].value.as_str(),
        Some("execution_lapse:receipt:lapse")
    );
    assert_eq!(
        project_amendment_lessons(&vault, std::slice::from_ref(&judgment))?,
        landed,
        "a replay re-returns the standing lesson"
    );

    let second = "receipt:lapse-again";
    measure_amendment(&vault, second, "Call them.", "Email them.")?;
    record_amendment_evidence(&vault, &lapse(second, 80))?;
    let again = judge_amendment(&vault, second)?.expect("a second lapse");
    project_amendment_lessons(&vault, &[again])?;
    assert_eq!(active_rows(&vault, &actor, PREDICATE_ACTOR_LESSON)?.len(), 2);

    record_amendment_evidence(
        &vault,
        &lapse(receipt, 70).with_cause(AmendmentCause::DeciderPreference),
    )?;
    judge_amendment(&vault, receipt)?.expect("a preference routes");
    project_amendment_lessons(&vault, &[])?;
    let standing = active_rows(&vault, &actor, PREDICATE_ACTOR_LESSON)?;
    assert_eq!(standing.len(), 1, "the cleared lapse's lesson is retracted");
    assert_eq!(
        standing[0].value.as_str(),
        Some("execution_lapse:receipt:lapse-again")
    );
    Ok(())
}
