use super::*;

use rmpv::Value;

use crate::claim::ClaimLifecycleStatus;
use crate::config::VaultConfig;
use crate::edit_distance::delta::{delta_from_reconstructed, put_amendment_delta_in_txn};
use crate::registry::ENTITY_TYPE_PERSON;
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
        ClaimSource::Imported,
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

fn superseded_count(vault: &Vault, subject: &EntityId, predicate: &str) -> Result<usize> {
    let mut count = 0;
    for id in vault.claims_for_subject(subject)? {
        let Some(body) = vault.get_claim(&id)? else {
            continue;
        };
        if body.predicate == predicate && body.lifecycle == ClaimLifecycleStatus::Superseded {
            count += 1;
        }
    }
    Ok(count)
}

/// The receipts a cost row cites, out of either evidence shape: the `skill.*`
/// row carries the citation array itself, the `actor.*` row carries the lane
/// envelope its own ledger builds.
fn cited(body: &ClaimBody) -> Vec<String> {
    let receipts = match body.evidence.as_ref() {
        Some(Value::Array(rows)) => rows.clone(),
        Some(Value::Map(entries)) => entries
            .iter()
            .find(|(key, _)| key.as_str() == Some("receipts"))
            .and_then(|(_, value)| value.as_array().cloned())
            .unwrap_or_default(),
        _ => Vec::new(),
    };
    receipts
        .iter()
        .filter_map(|row| row.as_str().map(str::to_owned))
        .collect()
}

/// A judge that names one class no matter what it is shown — the defect the
/// Blind Curator audit exists to make visible.
struct AlwaysDefectJudge;

impl AttributionJudge for AlwaysDefectJudge {
    fn judge(&self, _evidence: &OutcomeEvidence) -> Result<Option<AttributionVerdict>> {
        Ok(Some(AttributionVerdict::SkillDefect))
    }
}

// ─── classification ─────────────────────────────────────────────────────

#[test]
fn the_two_amendment_causes_short_circuit_the_ladder() -> Result<()> {
    let actor = EntityId::now();
    let skill = EntityId::now();
    let base = AmendmentEvidence::new("r:1", actor, "outbound")
        .at(5)
        .with_skill(skill)
        // Facts that WOULD route a skill defect, so the assertion is that the
        // cause pre-empts the ladder rather than agreeing with it.
        .with_routing_facts(true, true);

    assert_eq!(
        classify_amendment(
            &base.clone().with_cause(AmendmentCause::ExternalChange),
            &RuleAttributionJudge
        )?,
        Some(AmendmentClass::Environment)
    );
    assert_eq!(
        classify_amendment(
            &base.clone().with_cause(AmendmentCause::DeciderPreference),
            &RuleAttributionJudge
        )?,
        Some(AmendmentClass::PreferenceShift)
    );
    assert_eq!(
        classify_amendment(
            &base.clone().with_cause(AmendmentCause::ProposalWrong),
            &RuleAttributionJudge
        )?,
        Some(AmendmentClass::SkillDefect)
    );
    // No cause settled: the honest answer is silence, not the nearest class.
    assert_eq!(classify_amendment(&base, &RuleAttributionJudge)?, None);
    Ok(())
}

#[test]
fn the_wrong_proposal_arm_is_sk04s_table_verbatim() -> Result<()> {
    let actor = EntityId::now();
    let skill = EntityId::now();
    let wrong = |followed, covered| {
        AmendmentEvidence::new("r:1", actor, "outbound")
            .at(5)
            .with_skill(skill)
            .with_cause(AmendmentCause::ProposalWrong)
            .with_routing_facts(followed, covered)
    };
    assert_eq!(
        classify_amendment(&wrong(false, true), &RuleAttributionJudge)?,
        Some(AmendmentClass::ExecutionLapse)
    );
    assert_eq!(
        classify_amendment(&wrong(true, false), &RuleAttributionJudge)?,
        Some(AmendmentClass::Discovery)
    );
    // A skill-routed verdict with no skill in the evidence abstains rather than
    // falling through onto the actor.
    let skill_less = AmendmentEvidence::new("r:1", actor, "outbound")
        .at(5)
        .with_cause(AmendmentCause::ProposalWrong)
        .with_routing_facts(true, true);
    assert_eq!(
        classify_amendment(&skill_less, &RuleAttributionJudge)?,
        None
    );
    Ok(())
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

#[test]
fn a_skill_defect_charges_the_skill_and_a_lapse_charges_the_actor() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = put_actor(&vault)?;
    let skill = put_skill(&vault, "ed03.routing")?;

    let defect = judged(
        &vault,
        "receipt:defect",
        AmendmentEvidence::new("receipt:defect", actor, "outbound")
            .at(20)
            .with_skill(skill)
            .with_cause(AmendmentCause::ProposalWrong)
            .with_routing_facts(true, true),
        "the skill said do it this way",
        "the skill was wrong so do it that way",
    )?
    .expect("a settled amendment routes");
    assert_eq!(defect.class, AmendmentClass::SkillDefect);
    assert_eq!(defect.subject, Some(skill));

    let lapse = judged(
        &vault,
        "receipt:lapse",
        AmendmentEvidence::new("receipt:lapse", actor, "outbound")
            .at(21)
            .with_skill(skill)
            .with_cause(AmendmentCause::ProposalWrong)
            .with_routing_facts(false, true),
        "the skill said do it this way",
        "so do it this way",
    )?
    .expect("a settled amendment routes");
    assert_eq!(lapse.class, AmendmentClass::ExecutionLapse);
    assert_eq!(lapse.subject, Some(actor));

    let landed = project_edit_cost_claims(&vault, &[defect, lapse])?;
    assert_eq!(landed.len(), 2, "one row per charged subject");

    let skill_rows = active_rows(&vault, &skill, PREDICATE_SKILL_EDIT_COST)?;
    assert_eq!(skill_rows.len(), 1);
    let actor_rows = active_rows(&vault, &actor, PREDICATE_ACTOR_EDIT_COST)?;
    assert_eq!(actor_rows.len(), 1);
    // Each row cites the receipt its own class was judged from, and only that.
    assert_eq!(cited(&skill_rows[0]), vec!["receipt:defect".to_owned()]);
    assert_eq!(cited(&actor_rows[0]), vec!["receipt:lapse".to_owned()]);
    assert!(
        edit_cost_for(&vault, &skill, "outbound")?.is_some()
            && edit_cost_for(&vault, &actor, "outbound")?.is_some()
    );
    Ok(())
}

#[test]
fn environment_charges_nobody_and_preference_mints_a_proposal() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = put_actor(&vault)?;
    let skill = put_skill(&vault, "ed03.noclaim")?;

    let environment = judged(
        &vault,
        "receipt:environment",
        AmendmentEvidence::new("receipt:environment", actor, "calendar")
            .at(30)
            .with_skill(skill)
            .with_cause(AmendmentCause::ExternalChange),
        "meet at four",
        "meet at five",
    )?
    .expect("an external change is a class, not an abstention");
    assert_eq!(environment.class, AmendmentClass::Environment);
    assert_eq!(environment.subject, None, "there is nobody to blame");

    let preference = judged(
        &vault,
        "receipt:preference",
        AmendmentEvidence::new("receipt:preference", actor, "calendar")
            .at(31)
            .with_skill(skill)
            .with_cause(AmendmentCause::DeciderPreference),
        "warm regards",
        "best",
    )?
    .expect("a preference is a class, not an abstention");
    assert_eq!(preference.class, AmendmentClass::PreferenceShift);

    assert!(
        project_edit_cost_claims(&vault, &[environment, preference])?.is_empty(),
        "neither class earns an edit_cost row"
    );
    assert!(active_rows(&vault, &actor, PREDICATE_ACTOR_EDIT_COST)?.is_empty());
    assert!(active_rows(&vault, &skill, PREDICATE_SKILL_EDIT_COST)?.is_empty());

    let proposals = pending_preference_proposals(&vault)?;
    assert_eq!(proposals.len(), 1, "only the preference shift proposes");
    assert_eq!(proposals[0].receipt_id, "receipt:preference");
    assert_eq!(proposals[0].scope, "calendar");
    Ok(())
}

#[test]
fn a_discovery_earns_no_cost_row() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = put_actor(&vault)?;
    let skill = put_skill(&vault, "ed03.discovery")?;

    let discovery = judged(
        &vault,
        "receipt:discovery",
        AmendmentEvidence::new("receipt:discovery", actor, "outbound")
            .at(40)
            .with_skill(skill)
            .with_cause(AmendmentCause::ProposalWrong)
            .with_routing_facts(true, false),
        "nothing here covered the case",
        "nothing here covered the case, so add this",
    )?
    .expect("a settled amendment routes");
    assert_eq!(discovery.class, AmendmentClass::Discovery);
    assert_eq!(discovery.subject, Some(skill), "the gap is the skill's");
    assert!(
        project_edit_cost_claims(&vault, &[discovery])?.is_empty(),
        "missing content is SK-04's edit proposal, not a cost"
    );
    assert!(active_rows(&vault, &skill, PREDICATE_SKILL_EDIT_COST)?.is_empty());
    Ok(())
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
        class: AmendmentClass::SkillDefect,
        subject: Some(skill),
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
fn the_cost_row_supersedes_and_averages_its_judgments() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = put_actor(&vault)?;
    let skill = put_skill(&vault, "ed03.aggregate")?;

    let mut judgments = Vec::new();
    let mut deltas = Vec::new();
    for (index, (before, after)) in [("a\nb\nc\n", "a\nb\nc\n"), ("a\nb\nc\n", "x\ny\nz\n")]
        .into_iter()
        .enumerate()
    {
        let receipt = format!("receipt:agg:{index}");
        deltas.push(measure_amendment(&vault, &receipt, before, after)?);
        record_amendment_evidence(
            &vault,
            &AmendmentEvidence::new(&receipt, actor, "outbound")
                .at(60 + index as u64)
                .with_skill(skill)
                .with_cause(AmendmentCause::ProposalWrong)
                .with_routing_facts(false, true),
        )?;
        judgments.push(judge_amendment(&vault, &receipt)?.expect("a settled amendment routes"));
    }

    project_edit_cost_claims(&vault, &judgments[..1])?;
    project_edit_cost_claims(&vault, &judgments)?;

    let rows = active_rows(&vault, &actor, PREDICATE_ACTOR_EDIT_COST)?;
    assert_eq!(rows.len(), 1, "the pair holds exactly one live estimate");
    assert_eq!(
        superseded_count(&vault, &actor, PREDICATE_ACTOR_EDIT_COST)?,
        1,
        "the first estimate is closed, not left live beside the second"
    );
    let expected = (deltas[0] + deltas[1]) / 2.0;
    let cost = edit_cost_for(&vault, &actor, "outbound")?.expect("a live estimate");
    assert!(
        (cost - expected).abs() < 1e-6,
        "the row is the mean of its judgments: {cost} vs {expected}"
    );
    let citations = cited(&rows[0]);
    assert_eq!(citations.len(), 2, "both receipts are cited: {citations:?}");

    // A second pass over the same judgments re-derives the same number rather
    // than folding them in twice.
    project_edit_cost_claims(&vault, &judgments)?;
    let again = edit_cost_for(&vault, &actor, "outbound")?.expect("a live estimate");
    assert!((again - expected).abs() < 1e-6, "re-running is idempotent");
    Ok(())
}

#[test]
fn one_scope_is_not_another() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = put_actor(&vault)?;
    let skill = put_skill(&vault, "ed03.scopes")?;

    let mut judgments = Vec::new();
    for (index, scope) in ["outbound", "calendar"].into_iter().enumerate() {
        let receipt = format!("receipt:scope:{index}");
        measure_amendment(&vault, &receipt, "a\nb\n", "a\nc\n")?;
        record_amendment_evidence(
            &vault,
            &AmendmentEvidence::new(&receipt, actor, scope)
                .at(70 + index as u64)
                .with_skill(skill)
                .with_cause(AmendmentCause::ProposalWrong)
                .with_routing_facts(false, true),
        )?;
        judgments.push(judge_amendment(&vault, &receipt)?.expect("a settled amendment routes"));
    }
    project_edit_cost_claims(&vault, &judgments)?;

    assert_eq!(
        active_rows(&vault, &actor, PREDICATE_ACTOR_EDIT_COST)?.len(),
        2,
        "two scopes are two live rows, not one row that keeps moving"
    );
    assert!(edit_cost_for(&vault, &actor, "outbound")?.is_some());
    assert!(edit_cost_for(&vault, &actor, "calendar")?.is_some());
    assert!(edit_cost_for(&vault, &actor, "inbox")?.is_none());
    Ok(())
}

#[test]
fn re_judging_withdraws_the_proposal_it_no_longer_stands_behind() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = put_actor(&vault)?;
    let skill = put_skill(&vault, "ed03.rejudge")?;
    measure_amendment(&vault, "receipt:rejudge", "one", "two")?;

    record_amendment_evidence(
        &vault,
        &AmendmentEvidence::new("receipt:rejudge", actor, "outbound")
            .at(80)
            .with_skill(skill)
            .with_cause(AmendmentCause::DeciderPreference),
    )?;
    judge_amendment(&vault, "receipt:rejudge")?;
    assert_eq!(pending_preference_proposals(&vault)?.len(), 1);

    // The door re-read the amendment and settled a different cause.
    record_amendment_evidence(
        &vault,
        &AmendmentEvidence::new("receipt:rejudge", actor, "outbound")
            .at(80)
            .with_skill(skill)
            .with_cause(AmendmentCause::ProposalWrong)
            .with_routing_facts(true, true),
    )?;
    let rejudged = judge_amendment(&vault, "receipt:rejudge")?.expect("a settled amendment routes");
    assert_eq!(rejudged.class, AmendmentClass::SkillDefect);
    assert!(
        pending_preference_proposals(&vault)?.is_empty(),
        "the stale proposal is withdrawn with the verdict that minted it"
    );
    assert_eq!(
        amendment_judgments(&vault)?.len(),
        1,
        "a re-judgment replaces the receipt's row rather than adding one"
    );
    Ok(())
}

#[test]
fn an_unmeasured_amendment_is_never_judged() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = put_actor(&vault)?;
    measure_amendment(&vault, "receipt:vanishing", "one", "two")?;
    record_amendment_evidence(
        &vault,
        &AmendmentEvidence::new("receipt:vanishing", actor, "outbound")
            .at(90)
            .with_cause(AmendmentCause::ProposalWrong)
            .with_routing_facts(false, true),
    )?;
    assert!(judge_amendment(&vault, "receipt:vanishing")?.is_some());
    // A receipt with no recorded facts at all is silence, not a class.
    assert!(judge_amendment(&vault, "receipt:never-seen")?.is_none());
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
        );
        body.evidence = Some(Value::from("forged"));
        body.source = Some(ClaimSource::Observed);
        let error = vault
            .put_claim(&EntityId::now(), &body, t(80), 80)
            .expect_err("the generic claim API must refuse a reserved predicate");
        assert!(
            matches!(error, Error::ReservedPredicate { .. }),
            "typed reserved-namespace rejection, got {error:?}"
        );
    }
    Ok(())
}

// ─── the Blind Curator audit ────────────────────────────────────────────

#[test]
fn the_held_out_audit_scores_the_rule_tier_and_exposes_a_broken_one() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let fixtures = held_out_amendment_fixtures();

    let honest = run_judge_audit(&vault)?;
    assert!(
        (honest - 1.0).abs() < f32::EPSILON,
        "the deterministic tier answers its own held-out set: {honest}"
    );

    let broken = run_judge_audit_with_judge(&vault, &fixtures, &AlwaysDefectJudge, 100)?;
    assert!(
        broken.pass_rate() < honest,
        "a judge that never abstains must score visibly worse: {} vs {honest}",
        broken.pass_rate()
    );
    assert_eq!(
        broken.abstained, 1,
        "its only silence is the pre-filter's, on the fixture whose cause is \
         unsettled — the tier itself never abstains"
    );

    let reports = judge_audit_reports(&vault)?;
    assert_eq!(reports.len(), 2, "both passes are on the record");
    assert!(
        reports.iter().any(|report| report.at == 100),
        "the injected pass is queryable by ops"
    );
    Ok(())
}

#[test]
fn the_audit_fixtures_leak_no_answer_key() {
    for fixture in held_out_amendment_fixtures() {
        let case = fixture.evidence.receipt_id.as_str();
        for class in [
            AmendmentClass::SkillDefect,
            AmendmentClass::ExecutionLapse,
            AmendmentClass::Discovery,
            AmendmentClass::Environment,
            AmendmentClass::PreferenceShift,
        ] {
            assert!(
                !case.contains(class.as_str()),
                "fixture {case} names its own answer"
            );
        }
    }
}

#[test]
fn an_always_abstaining_tier_cannot_score_full_marks() -> Result<()> {
    struct SilentJudge;
    impl AttributionJudge for SilentJudge {
        fn judge(&self, _evidence: &OutcomeEvidence) -> Result<Option<AttributionVerdict>> {
            Ok(None)
        }
    }
    let (_tmp, vault) = temp_vault();
    let fixtures = held_out_amendment_fixtures();
    let report = run_judge_audit_with_judge(&vault, &fixtures, &SilentJudge, 110)?;
    assert!(
        report.pass_rate() < 1.0,
        "abstaining on everything earns only the abstention fixtures"
    );
    Ok(())
}
