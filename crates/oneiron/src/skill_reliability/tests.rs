use super::*;

use crate::attempt_queue::{
    AttemptQueue, ClaimAttempt, ClaimOutcome, CompleteAttempt, CompleteOutcome, EnqueueAttempt,
    EnqueueOutcome, ManifestEntry, ManifestKind,
};
use crate::config::VaultConfig;
use crate::receipt::attempt_pack_receipt_id;
use crate::registry::ENTITY_TYPE_PERSON;
use crate::skill::SkillLifecycle;
use crate::skill_attribution::{
    AttemptOutcome, OutcomeEvidence, read_attribution_cursor, record_attribution_evidence,
    run_attribution_projector,
};

// ─── fixtures ───────────────────────────────────────────────────────────

fn temp_vault() -> (tempfile::TempDir, Vault) {
    let tmp = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(tmp.path(), VaultConfig::default()).expect("open vault");
    (tmp, vault)
}

fn t(ts: u64) -> TimeRange {
    TimeRange { start: ts, end: ts }
}

fn provenance() -> Value {
    Value::Map(vec![(Value::from("source"), Value::from("sk05-fixture"))])
}

fn record(skill_id: &str, source: ClaimSource, generated: bool) -> SkillRecord {
    SkillRecord::new(
        skill_id,
        "SK-05 reliability fixture",
        "1.0.0",
        ClaimApprovalStatus::Approved,
        SkillLifecycle::Candidate,
        source,
        0.5,
        generated,
        !generated,
        Vec::new(),
        provenance(),
    )
}

/// Puts a skill and walks it `candidate → active`.
fn put_active(vault: &Vault, id: &EntityId, record: SkillRecord) -> SkillRecord {
    vault.put_skill_record(id, &record, t(10), 11).expect("put");
    let mut active = record;
    active.lifecycle_status = SkillLifecycle::Active;
    vault
        .update_skill_record(id, &active, t(12), 13)
        .expect("activate");
    active
}

fn put_active_import(vault: &Vault, id: &EntityId, skill_id: &str) -> SkillRecord {
    put_active(vault, id, record(skill_id, ClaimSource::Imported, false))
}

fn put_actor(vault: &Vault, id: &EntityId) {
    vault
        .put_entity(id, ENTITY_TYPE_PERSON, t(1), 1, b"sk05 actor")
        .expect("put actor");
}

/// Runs one attempt whose pack loaded `skill_id` to its terminal door and
/// returns the receipt id its close STAMPED.
fn stamped_receipt(vault: &Vault, skill_id: &str) -> String {
    let queue = AttemptQueue::new(vault);
    let EnqueueOutcome::Enqueued(attempt) = queue
        .enqueue(EnqueueAttempt {
            kind: "sk05.attempt".to_owned(),
            payload: Vec::new(),
            dedupe_key: None,
            run_id: None,
            now: 10,
        })
        .expect("enqueue")
    else {
        panic!("a fresh dedupe-free enqueue is never Existing");
    };
    queue
        .append_manifest_entry(
            attempt.id,
            ManifestEntry::new(ManifestKind::Skill, skill_id, "1.0.0", 11),
        )
        .expect("manifest append");
    let ClaimOutcome::Claimed(leased) = queue
        .claim(ClaimAttempt {
            lease_owner: "sk05-worker".to_owned(),
            now: 12,
        })
        .expect("claim")
    else {
        panic!("the enqueued attempt is claimable");
    };
    let CompleteOutcome::Completed(_) = queue
        .complete(CompleteAttempt {
            id: attempt.id,
            lease_owner: "sk05-worker".to_owned(),
            attempt_count: leased.attempt_count,
            now: 13,
        })
        .expect("complete")
    else {
        panic!("a leased attempt completes exactly once");
    };
    attempt_pack_receipt_id(&attempt.id)
}

/// Records one routed outcome and returns the judgments the pass minted.
fn route(
    vault: &Vault,
    skill: &EntityId,
    actor: &EntityId,
    skill_id: &str,
    followed: bool,
    covered: bool,
    at: u64,
) -> (String, Vec<AttributionJudgment>) {
    let receipt = stamped_receipt(vault, skill_id);
    record_attribution_evidence(
        vault,
        &OutcomeEvidence::new(&receipt, *actor, AttemptOutcome::Failed, at)
            .with_skill(*skill)
            .with_routing_facts(followed, covered),
    )
    .expect("record evidence");
    let cursor = read_attribution_cursor(vault).expect("cursor");
    let judgments = run_attribution_projector(vault, cursor).expect("project attribution");
    (receipt, judgments)
}

fn active_reliability(vault: &Vault, skill: &EntityId) -> Vec<ClaimBody> {
    claims(
        vault,
        skill,
        PREDICATE_SKILL_RELIABILITY,
        ClaimLifecycleStatus::Active,
    )
}

fn claims(
    vault: &Vault,
    subject: &EntityId,
    predicate: &str,
    lifecycle: ClaimLifecycleStatus,
) -> Vec<ClaimBody> {
    vault
        .claims_for_subject(subject)
        .expect("claims for subject")
        .into_iter()
        .filter_map(|id| vault.get_claim(&id).expect("claim body"))
        .filter(|body| body.predicate == predicate && body.lifecycle == lifecycle)
        .collect()
}

// ─── posterior arithmetic ───────────────────────────────────────────────

#[test]
fn provenance_priors_order_vetted_above_generated() {
    let vetted =
        SkillReliabilityPosterior::seeded_from_provenance(ProvenanceTrustClass::VettedImport);
    let human =
        SkillReliabilityPosterior::seeded_from_provenance(ProvenanceTrustClass::HumanAuthored);
    let unvetted =
        SkillReliabilityPosterior::seeded_from_provenance(ProvenanceTrustClass::UnvettedImport);
    let generated =
        SkillReliabilityPosterior::seeded_from_provenance(ProvenanceTrustClass::Generated);

    // The documented values, not just their ordering: a table that silently
    // drifts to all-uniform would still pass an ordering-only assert.
    assert!((vetted.mean() - 0.75).abs() < 1e-6);
    assert!((human.mean() - 2.0 / 3.0).abs() < 1e-6);
    assert!((unvetted.mean() - 0.5).abs() < 1e-6);
    assert!((generated.mean() - 1.0 / 3.0).abs() < 1e-6);
    assert!(vetted.mean() > human.mean());
    assert!(human.mean() > unvetted.mean());
    assert!(unvetted.mean() > generated.mean());
}

#[test]
fn lower_bound_holds_its_pinned_anchors() {
    // Beta(3, 1) — two wins on a uniform prior.
    let two_of_two = SkillReliabilityPosterior {
        alpha: 3.0,
        beta: 1.0,
    };
    // Beta(91, 11) — 90/100 on a uniform prior.
    let ninety_of_hundred = SkillReliabilityPosterior {
        alpha: 91.0,
        beta: 11.0,
    };
    assert!((two_of_two.lower_bound() - 0.43).abs() < 0.01);
    assert!((ninety_of_hundred.lower_bound() - 0.84).abs() < 0.01);
    // The uncertainty law: two lucky pulls never outrank a hundred observed
    // ones on the conservative ranking, and 2/2's MEAN sits under 90/100's
    // lower bound.
    assert!(two_of_two.lower_bound() < ninety_of_hundred.lower_bound());
    assert!(two_of_two.mean() < ninety_of_hundred.lower_bound());
    // …and not on the selection score either, at the pinned exploration weight.
    let total = 106;
    assert!(two_of_two.ucb(total) < ninety_of_hundred.ucb(total));
}

#[test]
fn selection_bonus_lifts_the_uncertain_arm_at_equal_means() {
    // Anti-shadowing (OF-184): equal-ish means, wildly different evidence —
    // the barely-pulled arm must still be worth trying.
    let fresh = SkillReliabilityPosterior {
        alpha: 2.0,
        beta: 1.0,
    };
    let seasoned = SkillReliabilityPosterior {
        alpha: 21.0,
        beta: 11.0,
    };
    assert!(fresh.mean() > seasoned.mean());
    assert!(fresh.ucb(35) > seasoned.ucb(35));
    // The bonus DECAYS with evidence: the same arm, once observed, stops
    // riding exploration.
    let matured = SkillReliabilityPosterior {
        alpha: 21.0,
        beta: 10.0,
    };
    assert!(fresh.ucb(35) - fresh.mean() > matured.ucb(35) - matured.mean());
}

#[test]
fn lower_bound_clamps_into_the_unit_interval() {
    let hopeless = SkillReliabilityPosterior {
        alpha: 1.0,
        beta: 2.0,
    };
    assert!(hopeless.lower_bound() >= 0.0);
    let flawless = SkillReliabilityPosterior {
        alpha: 500.0,
        beta: 1.0,
    };
    assert!(flawless.lower_bound() <= 1.0);
}

// ─── projection ─────────────────────────────────────────────────────────

#[test]
fn defect_judgments_lower_the_posterior_and_lapses_leave_it_alone() {
    let (_tmp, vault) = temp_vault();
    let skill = EntityId::now();
    let actor = EntityId::now();
    put_active_import(&vault, &skill, "sk05.skill.defect");
    put_actor(&vault, &actor);

    let (_, defect) = route(&vault, &skill, &actor, "sk05.skill.defect", true, true, 30);
    project_skill_reliability(&vault, &defect).expect("project defect");
    let after_defect = skill_reliability_posterior(&vault, &skill)
        .expect("read")
        .expect("projected");
    assert!(
        (after_defect.beta - 2.0).abs() < 1e-6,
        "unvetted prior β=1 + one loss"
    );
    assert!((after_defect.alpha - 1.0).abs() < 1e-6);

    // An execution lapse routes to the ACTOR. It must move nothing here.
    let (_, lapse) = route(&vault, &skill, &actor, "sk05.skill.defect", false, true, 31);
    assert_eq!(lapse.len(), 1);
    assert_eq!(lapse[0].verdict, AttributionVerdict::ExecutionLapse);
    assert_eq!(lapse[0].subject, actor);
    let touched = project_skill_reliability(&vault, &lapse).expect("project lapse");
    assert!(touched.is_empty(), "a lapse projects no skill posterior");
    let after_lapse = skill_reliability_posterior(&vault, &skill)
        .expect("read")
        .expect("projected");
    assert_eq!(after_lapse, after_defect, "the lapse left α, β untouched");
}

#[test]
fn re_running_the_projector_over_the_same_judgments_is_a_no_op() {
    let (_tmp, vault) = temp_vault();
    let skill = EntityId::now();
    let actor = EntityId::now();
    put_active_import(&vault, &skill, "sk05.skill.idempotent");
    put_actor(&vault, &actor);

    let (_, judgments) = route(
        &vault,
        &skill,
        &actor,
        "sk05.skill.idempotent",
        true,
        true,
        30,
    );
    project_skill_reliability(&vault, &judgments).expect("first pass");
    let first = skill_reliability_posterior(&vault, &skill)
        .expect("read")
        .expect("projected");

    // Crash-replay: the same judgment batch arrives again.
    project_skill_reliability(&vault, &judgments).expect("replay");
    project_skill_reliability(&vault, &judgments).expect("replay again");
    let replayed = skill_reliability_posterior(&vault, &skill)
        .expect("read")
        .expect("projected");

    assert_eq!(replayed, first, "the citation keyspace deduped the replay");
    assert_eq!(
        active_reliability(&vault, &skill).len(),
        1,
        "one active row per skill"
    );
    assert_eq!(
        claims(
            &vault,
            &skill,
            PREDICATE_SKILL_RELIABILITY,
            ClaimLifecycleStatus::Superseded
        )
        .len(),
        0,
        "an unchanged posterior supersedes nothing"
    );
}

#[test]
fn contributing_wins_raise_the_posterior_and_are_grounded_at_the_door() {
    let (_tmp, vault) = temp_vault();
    let skill = EntityId::now();
    let other = EntityId::now();
    put_active_import(&vault, &skill, "sk05.skill.win");
    put_active_import(&vault, &other, "sk05.skill.other");

    let receipt = stamped_receipt(&vault, "sk05.skill.win");
    record_skill_contributing_win(&vault, &skill, &receipt, 20).expect("credit win");
    let posterior = project_skill_reliability_for(&vault, &skill, 21).expect("project");
    assert!(
        (posterior.alpha - 2.0).abs() < 1e-6,
        "unvetted prior α=1 + one win"
    );
    assert!((posterior.beta - 1.0).abs() < 1e-6);

    // Same receipt twice = one win.
    record_skill_contributing_win(&vault, &skill, &receipt, 22).expect("re-credit");
    let replayed = project_skill_reliability_for(&vault, &skill, 23).expect("re-project");
    assert_eq!(replayed, posterior);

    // A skill the pack never loaded cannot claim the win.
    record_skill_contributing_win(&vault, &other, &receipt, 24)
        .expect_err("the manifest does not name this skill");
    // Neither can a receipt nobody stamped.
    record_skill_contributing_win(&vault, &skill, "attempt-receipt:deadbeef", 25)
        .expect_err("unstamped receipt");
}

#[test]
fn projection_supersedes_rather_than_forking_the_active_row() {
    let (_tmp, vault) = temp_vault();
    let skill = EntityId::now();
    let actor = EntityId::now();
    put_active_import(&vault, &skill, "sk05.skill.supersede");
    put_actor(&vault, &actor);

    for (index, at) in [30_u64, 31].into_iter().enumerate() {
        let (_, judgments) = route(
            &vault,
            &skill,
            &actor,
            "sk05.skill.supersede",
            true,
            true,
            at,
        );
        project_skill_reliability(&vault, &judgments).expect("project");
        assert_eq!(
            active_reliability(&vault, &skill).len(),
            1,
            "exactly one active row after pass {index}"
        );
    }
    assert_eq!(
        claims(
            &vault,
            &skill,
            PREDICATE_SKILL_RELIABILITY,
            ClaimLifecycleStatus::Superseded
        )
        .len(),
        1,
        "the first posterior was superseded, not deleted"
    );
}

// ─── cache demotion ─────────────────────────────────────────────────────

#[test]
fn cache_rebuilds_from_the_claim_and_the_record_never_writes_back() {
    let (_tmp, vault) = temp_vault();
    let skill = EntityId::now();
    let actor = EntityId::now();
    put_active_import(&vault, &skill, "sk05.skill.cache");
    put_actor(&vault, &actor);

    let (_, judgments) = route(&vault, &skill, &actor, "sk05.skill.cache", true, true, 30);
    project_skill_reliability(&vault, &judgments).expect("project");
    let mean = skill_reliability_posterior(&vault, &skill)
        .expect("read")
        .expect("projected")
        .mean();
    let cached = vault
        .get_skill_record(&skill)
        .expect("read record")
        .expect("record")
        .confidence;
    assert!(
        (cached - mean).abs() < 1e-6,
        "the projector refreshed the cache in the same pass"
    );

    // Clobber the cache through the ordinary update door — no version bump,
    // and the imported-content fork law is not tripped, because the field is
    // not content.
    let mut clobbered = vault
        .get_skill_record(&skill)
        .expect("read record")
        .expect("record");
    let version_before = clobbered.version.clone();
    clobbered.confidence = 0.01;
    vault
        .update_skill_record(&skill, &clobbered, t(40), 41)
        .expect("cache writes need no revision");

    // Truth is untouched by the clobber (the direction proof).
    let claim_mean = skill_reliability_posterior(&vault, &skill)
        .expect("read")
        .expect("projected")
        .mean();
    assert!((claim_mean - mean).abs() < 1e-6);
    assert_eq!(active_reliability(&vault, &skill).len(), 1);

    let rebuilt = rebuild_skill_confidence_cache(&vault, &skill, 42).expect("rebuild");
    assert!((rebuilt - mean).abs() < 1e-6);
    let stored = vault
        .get_skill_record(&skill)
        .expect("read record")
        .expect("record");
    assert!((stored.confidence - mean).abs() < 1e-6);
    assert_eq!(
        stored.version, version_before,
        "a cache rebuild mints no revision"
    );
}

#[test]
fn cache_rebuild_without_a_claim_falls_back_to_the_provenance_prior() {
    let (_tmp, vault) = temp_vault();
    let skill = EntityId::now();
    put_active(
        &vault,
        &skill,
        record("sk05.skill.unprojected", ClaimSource::Generated, true),
    );
    let rebuilt = rebuild_skill_confidence_cache(&vault, &skill, 20).expect("rebuild");
    assert!(
        (rebuilt - 1.0 / 3.0).abs() < 1e-6,
        "a generated skill's cache rebuilds to its weak prior"
    );
}

#[test]
fn selection_reads_the_claim_not_the_clobbered_cache() {
    let (_tmp, vault) = temp_vault();
    let skill = EntityId::now();
    put_active_import(&vault, &skill, "sk05.skill.selection");

    let receipt = stamped_receipt(&vault, "sk05.skill.selection");
    record_skill_contributing_win(&vault, &skill, &receipt, 20).expect("credit win");
    let posterior = project_skill_reliability_for(&vault, &skill, 21).expect("project");

    let mut clobbered = vault
        .get_skill_record(&skill)
        .expect("read record")
        .expect("record");
    clobbered.confidence = 0.0;
    vault
        .update_skill_record(&skill, &clobbered, t(30), 31)
        .expect("clobber cache");

    let score = skill_selection_score(&vault, &skill, 8).expect("score");
    assert!(
        (score - posterior.ucb(8)).abs() < 1e-6,
        "the score came off the claim, not the zeroed cache"
    );
    assert!(score > 0.0);
}

// ─── floor crossing ─────────────────────────────────────────────────────

#[test]
fn floor_never_fires_on_a_bare_prior() {
    let (_tmp, vault) = temp_vault();
    let skill = EntityId::now();
    put_active(
        &vault,
        &skill,
        record("sk05.skill.newborn", ClaimSource::Generated, true),
    );
    // Beta(1, 2)'s lower bound is 0 — under any floor. Without the
    // minimum-outcomes guard this newborn would be proposed for quarantine
    // before it ever ran.
    let prior = skill_reliability_prior(&vault, &skill).expect("prior");
    assert!(prior.lower_bound() < DEFAULT_SKILL_RELIABILITY_FLOOR);
    assert_eq!(
        check_reliability_floor(&vault, &skill, 20).expect("floor check"),
        None,
        "ignorance is not unreliability"
    );
    assert!(
        claims(
            &vault,
            &skill,
            PREDICATE_SKILL_QUARANTINE_PROPOSAL,
            ClaimLifecycleStatus::Active
        )
        .is_empty()
    );
}

#[test]
fn floor_crossing_proposes_once_and_never_retires() {
    let (_tmp, vault) = temp_vault();
    let skill = EntityId::now();
    let actor = EntityId::now();
    put_active_import(&vault, &skill, "sk05.skill.floor");
    put_actor(&vault, &actor);

    let mut proposal = None;
    for at in 30..30 + u64::from(SKILL_RELIABILITY_FLOOR_MIN_OUTCOMES) + 2 {
        let (_, judgments) = route(&vault, &skill, &actor, "sk05.skill.floor", true, true, at);
        project_skill_reliability(&vault, &judgments).expect("project");
        let open = claims(
            &vault,
            &skill,
            PREDICATE_SKILL_QUARANTINE_PROPOSAL,
            ClaimLifecycleStatus::Active,
        );
        if let Some(row) = open.first() {
            proposal = Some(row.clone());
        }
    }

    let proposal = proposal.expect("sustained losses cross the floor");
    assert_eq!(
        proposal.approval,
        ClaimApprovalStatus::Proposed,
        "quarantine is PROPOSED, never auto"
    );
    assert_eq!(
        claims(
            &vault,
            &skill,
            PREDICATE_SKILL_QUARANTINE_PROPOSAL,
            ClaimLifecycleStatus::Active
        )
        .len(),
        1,
        "further crossings while the proposal is open mint no duplicate"
    );
    assert_eq!(
        vault
            .get_skill_record(&skill)
            .expect("read record")
            .expect("record")
            .lifecycle_status,
        SkillLifecycle::Active,
        "the record stays active until a human rules"
    );
}

#[test]
fn the_floor_dial_is_settings_backed() {
    let (_tmp, vault) = temp_vault();
    assert!(
        (skill_reliability_floor(&vault).expect("default floor") - DEFAULT_SKILL_RELIABILITY_FLOOR)
            .abs()
            < 1e-6
    );
    set_skill_reliability_floor(&vault, 0.6).expect("set floor");
    assert!((skill_reliability_floor(&vault).expect("floor") - 0.6).abs() < 1e-6);
    set_skill_reliability_floor(&vault, 1.5).expect_err("floor is a probability");
    set_skill_reliability_floor(&vault, f32::NAN).expect_err("floor must be finite");
}

#[test]
fn the_reliability_claim_carries_exactly_the_posterior_and_cites_its_receipts() {
    let (_tmp, vault) = temp_vault();
    let skill = EntityId::now();
    let actor = EntityId::now();
    put_active_import(&vault, &skill, "sk05.skill.wire");
    put_actor(&vault, &actor);

    let (receipt, judgments) = route(&vault, &skill, &actor, "sk05.skill.wire", true, true, 30);
    project_skill_reliability(&vault, &judgments).expect("project");

    let rows = active_reliability(&vault, &skill);
    assert_eq!(rows.len(), 1);
    let body = &rows[0];
    assert_eq!(
        body.approval,
        ClaimApprovalStatus::Auto,
        "projector-written"
    );
    assert_eq!(body.subject, ClaimSubject::Entity(skill));
    let posterior = body.value.as_map().expect("posterior map");
    assert_eq!(
        posterior.len(),
        2,
        "the value is {{alpha, beta}} and nothing else"
    );
    for key in [KEY_ALPHA, KEY_BETA] {
        assert_eq!(
            posterior
                .iter()
                .filter(|(k, _)| k.as_str() == Some(key))
                .count(),
            1
        );
    }
    let cited = body
        .evidence
        .as_ref()
        .expect("reliability cites its receipts")
        .as_array()
        .expect("evidence is an array")
        .clone();
    assert_eq!(cited, vec![Value::from(receipt.as_str())]);
}
