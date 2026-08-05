use super::*;

use crate::attempt_queue::{
    AttemptQueue, ClaimAttempt, ClaimOutcome, CompleteAttempt, CompleteOutcome, EnqueueAttempt,
    EnqueueOutcome, ManifestEntry, ManifestKind,
};
use crate::config::VaultConfig;
use crate::receipt::attempt_pack_receipt_id;
use crate::registry::ENTITY_TYPE_PERSON;
use crate::skill::{SkillLifecycle, canonical_skill_tree_hash};
use crate::skill_attribution::{
    AttemptOutcome, OutcomeEvidence, read_attribution_cursor, record_attribution_evidence,
    run_attribution_projector,
};
use crate::skill_hub::{
    HubFile, HubPackage, HubPin, HubRef, ScanCompleteness, ScanRiskLevel, ScanVerdict,
    SkillCapabilitySurface, SkillGovernance, SkillScanReceipt,
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
    versioned_record(skill_id, "1.0.0", source, generated)
}

fn versioned_record(
    skill_id: &str,
    version: &str,
    source: ClaimSource,
    generated: bool,
) -> SkillRecord {
    SkillRecord::new(
        skill_id,
        "SK-05 reliability fixture",
        version,
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

/// Runs one attempt whose pack loaded `skill_id@1.0.0` to its terminal door and
/// returns the receipt id its close STAMPED.
fn stamped_receipt(vault: &Vault, skill_id: &str) -> String {
    stamped_receipt_for_revision(vault, skill_id, "1.0.0")
}

/// [`stamped_receipt`] with the manifest revision named explicitly.
fn stamped_receipt_for_revision(vault: &Vault, skill_id: &str, version: &str) -> String {
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
            ManifestEntry::new(ManifestKind::Skill, skill_id, version, 11),
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

/// Plants the claim a SYNC would have delivered: an active `skill.reliability`
/// row on this skill citing receipts this vault has no outcome rows for.
///
/// `vault_meta` never travels, so this is exactly what device B sees after
/// device A projects — the posterior arrives, the ledger under it does not.
fn plant_synced_claim(
    vault: &Vault,
    skill: &EntityId,
    posterior: SkillReliabilityPosterior,
    cited: &[&str],
    at: u64,
) -> EntityId {
    let claim_id = EntityId::now();
    let mut body = ClaimBody::new(
        PREDICATE_SKILL_RELIABILITY,
        ClaimSubject::Entity(*skill),
        posterior.to_value(),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    body.evidence = Some(Value::Array(
        cited.iter().map(|id| Value::from(*id)).collect(),
    ));
    body.source = Some(ClaimSource::Observed);
    vault
        .with_write_txn(|wtxn| vault.put_reserved_claim_in_txn(wtxn, &claim_id, &body, t(at), at))
        .expect("plant synced claim");
    claim_id
}

/// Imports a skill through the REAL hub door, so it carries a
/// `skill.hub_provenance` alias for its canonical bytes.
fn import_from_hub(vault: &Vault, skill_id: &str) -> (EntityId, SkillContentHash) {
    let files = vec![HubFile::new("SKILL.md", b"# vetted fixture\n".to_vec())];
    let package = HubPackage::new(
        record(skill_id, ClaimSource::Imported, false),
        files,
        SkillCapabilitySurface::default(),
    );
    let content_hash = package.content_hash().expect("package hashes");
    let hub_ref = HubRef::new(EntityId::now(), "sk05/vetted", HubPin::None).expect("hub ref");
    let entity = vault
        .import_skill_from_hub(&hub_ref, &package, t(10), 11)
        .expect("hub import");
    (entity, content_hash)
}

fn ingest_verdict(
    vault: &Vault,
    skill: &EntityId,
    hash: SkillContentHash,
    provider: &str,
    verdict: ScanVerdict,
    governance: SkillGovernance,
    at: u64,
) {
    let receipt = SkillScanReceipt::new(
        provider,
        at,
        verdict,
        ScanRiskLevel::None,
        ScanCompleteness::Complete,
        governance,
    )
    .expect("scan receipt");
    vault
        .ingest_skill_scan_verdict(skill, hash, &receipt, t(at), at + 1)
        .expect("ingest verdict");
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
fn a_clean_scan_verdict_on_hub_carried_bytes_promotes_an_import_to_vetted() {
    // The vetted branch reads the scan-verdict claim's `verdict` wire string,
    // which this module spells out rather than importing (ScanVerdict::as_str is
    // private to skill_hub). Without a vault-level test that spelling could rot
    // silently and every vetted import would quietly seed as unvetted.
    let (_tmp, vault) = temp_vault();
    let (skill, tree) = import_from_hub(&vault, "sk05.skill.vetted");

    assert_eq!(
        skill_provenance_trust_class(&vault, &skill).expect("class"),
        ProvenanceTrustClass::UnvettedImport,
        "an import nobody scanned is not vetted"
    );

    // A scanner that did NOT clear the bytes must not promote it either.
    for (provider, verdict, at) in [
        ("provider-suspicious", ScanVerdict::Suspicious, 20),
        ("provider-unknown", ScanVerdict::Unknown, 21),
    ] {
        ingest_verdict(
            &vault,
            &skill,
            tree,
            provider,
            verdict,
            SkillGovernance::Recommended,
            at,
        );
    }
    assert_eq!(
        skill_provenance_trust_class(&vault, &skill).expect("class"),
        ProvenanceTrustClass::UnvettedImport,
        "suspicious and unknown are not a clearance"
    );

    ingest_verdict(
        &vault,
        &skill,
        tree,
        "provider-clean",
        ScanVerdict::Clean,
        SkillGovernance::Recommended,
        30,
    );

    assert_eq!(
        skill_provenance_trust_class(&vault, &skill).expect("class"),
        ProvenanceTrustClass::VettedImport
    );
    let prior = skill_reliability_prior(&vault, &skill).expect("prior");
    assert!(
        (prior.mean() - 0.75).abs() < 1e-6,
        "the vetted prior seeded"
    );

    // …and the done-means ordering, end to end through the vault: a vetted
    // import outranks a conversation-authored skill before either has run.
    let generated = EntityId::now();
    put_active(
        &vault,
        &generated,
        record("sk05.skill.converted", ClaimSource::Generated, true),
    );
    let generated_prior = skill_reliability_prior(&vault, &generated).expect("prior");
    assert!(prior.mean() > generated_prior.mean());
}

#[test]
fn a_clean_scan_on_governance_prohibited_bytes_clears_nothing() {
    // `governance` is a POLICY axis carried on the same row, and the scan-ingest
    // door validates only the provider text — so `clean` + `prohibited` is a
    // storable receipt. Seeding the MOST optimistic prior off bytes governance
    // forbids inverts the whole table.
    let (_tmp, vault) = temp_vault();
    let (skill, tree) = import_from_hub(&vault, "sk05.skill.prohibited");
    ingest_verdict(
        &vault,
        &skill,
        tree,
        "provider-clean-but-banned",
        ScanVerdict::Clean,
        SkillGovernance::Prohibited,
        20,
    );

    assert_eq!(
        skill_provenance_trust_class(&vault, &skill).expect("class"),
        ProvenanceTrustClass::UnvettedImport,
        "a prohibited row clears nothing, however clean the scanner found it"
    );

    // A second provider that clears the same bytes WITHOUT the prohibition does
    // promote them: the guard reads the row, it does not blanket-reject.
    ingest_verdict(
        &vault,
        &skill,
        tree,
        "provider-clean",
        ScanVerdict::Clean,
        SkillGovernance::Recommended,
        21,
    );
    assert_eq!(
        skill_provenance_trust_class(&vault, &skill).expect("class"),
        ProvenanceTrustClass::VettedImport
    );
}

#[test]
fn a_clean_scan_without_a_hub_alias_is_still_an_unvetted_import() {
    // `VettedImport` is the VETTED-HUB import (blueprint §5: "hub trust tier —
    // scan-verdict + hub provenance rows"). Scan verdicts hang off the
    // content-global anchor, so a clean verdict alone says a scanner looked at
    // some bytes; the provenance row is what says a HUB carried them here.
    let (_tmp, vault) = temp_vault();
    let tree = canonical_skill_tree_hash([("SKILL.md", b"# direct fixture\n".as_slice())])
        .expect("tree hashes");
    let skill = EntityId::now();
    put_active(
        &vault,
        &skill,
        record("sk05.skill.direct", ClaimSource::Imported, false).with_content_hash(tree),
    );
    ingest_verdict(
        &vault,
        &skill,
        tree,
        "provider-clean",
        ScanVerdict::Clean,
        SkillGovernance::Recommended,
        20,
    );

    assert_eq!(
        skill_provenance_trust_class(&vault, &skill).expect("class"),
        ProvenanceTrustClass::UnvettedImport,
        "no hub vouches for these bytes"
    );
    let prior = skill_reliability_prior(&vault, &skill).expect("prior");
    assert!((prior.mean() - 0.5).abs() < 1e-6);
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
fn a_routed_defect_outranks_the_default_win_credit_in_either_order() {
    // A blamed attempt still reaches its terminal door COMPLETED, so the same
    // receipt can be offered as a contributing win AND routed to a defect. The
    // posterior must not depend on which call the host makes first.
    let posterior_for = |credit_first: bool| {
        let (_tmp, vault) = temp_vault();
        let skill = EntityId::now();
        let actor = EntityId::now();
        put_active_import(&vault, &skill, "sk05.skill.order");
        put_actor(&vault, &actor);

        let receipt = stamped_receipt(&vault, "sk05.skill.order");
        let blame = |vault: &Vault| {
            record_attribution_evidence(
                vault,
                &OutcomeEvidence::new(&receipt, actor, AttemptOutcome::Failed, 30)
                    .with_skill(skill)
                    .with_routing_facts(true, true),
            )
            .expect("record evidence");
            let cursor = read_attribution_cursor(vault).expect("cursor");
            let judgments = run_attribution_projector(vault, cursor).expect("route");
            project_skill_reliability(vault, &judgments).expect("project");
        };
        if credit_first {
            record_skill_contributing_win(&vault, &skill, &receipt, 20).expect("credit");
            blame(&vault);
        } else {
            blame(&vault);
            record_skill_contributing_win(&vault, &skill, &receipt, 20).expect("credit");
            project_skill_reliability_for(&vault, &skill, 40).expect("re-project");
        }
        skill_reliability_posterior(&vault, &skill)
            .expect("read")
            .expect("projected")
    };

    let credited_first = posterior_for(true);
    let blamed_first = posterior_for(false);
    assert_eq!(credited_first, blamed_first, "order-independent");
    assert!(
        (blamed_first.beta - 2.0).abs() < 1e-6 && (blamed_first.alpha - 1.0).abs() < 1e-6,
        "one receipt, one outcome, and the routed verdict is the one that counts"
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

// ─── reserved-door authorization ────────────────────────────────────────

#[test]
fn a_forged_judgment_writes_no_reserved_claim() {
    // `AttributionJudgment` is a public type with public fields, and this door
    // authors reserved `skill.*` truth. A row that was never routed is an
    // assertion however well-formed it looks.
    let (_tmp, vault) = temp_vault();
    let skill = EntityId::now();
    let actor = EntityId::now();
    put_active_import(&vault, &skill, "sk05.skill.forged");
    put_actor(&vault, &actor);

    let fabricated = AttributionJudgment {
        sequence: 1,
        verdict: AttributionVerdict::SkillDefect,
        subject: skill,
        evidence_receipts: vec!["attempt-receipt:deadbeef".to_owned()],
        at: 30,
    };
    assert!(
        project_skill_reliability(&vault, std::slice::from_ref(&fabricated))
            .expect("project")
            .is_empty(),
        "a citation naming no stamped receipt grounds nothing"
    );
    assert!(active_reliability(&vault, &skill).is_empty());
    assert_eq!(
        skill_reliability_posterior(&vault, &skill).expect("read"),
        None
    );

    // …and a judgment whose GROUNDING is real — a stamped receipt whose
    // manifest names this skill — but whose sequence names no routed row.
    // Grounding is not authorization.
    let (_, routed) = route(&vault, &skill, &actor, "sk05.skill.forged", true, true, 31);
    let mut relabelled = routed[0].clone();
    relabelled.sequence = relabelled.sequence.saturating_add(1_000);
    assert!(
        project_skill_reliability(&vault, &[relabelled])
            .expect("project")
            .is_empty()
    );
    assert!(active_reliability(&vault, &skill).is_empty());

    // The routed row itself still projects: the gate refuses forgeries, not work.
    assert_eq!(
        project_skill_reliability(&vault, &routed).expect("project"),
        vec![skill]
    );
    assert_eq!(active_reliability(&vault, &skill).len(), 1);
}

#[test]
fn a_win_receipt_must_name_the_revision_it_credits() {
    // A revision is its own SKILL entity with its own posterior, so a `skill@1`
    // receipt crediting the `skill@2` entity moves a claim about bytes that
    // attempt never ran.
    let (_tmp, vault) = temp_vault();
    let v2 = EntityId::now();
    put_active(
        &vault,
        &v2,
        versioned_record("sk05.skill.rev", "2.0.0", ClaimSource::Imported, false),
    );

    let v1_receipt = stamped_receipt_for_revision(&vault, "sk05.skill.rev", "1.0.0");
    record_skill_contributing_win(&vault, &v2, &v1_receipt, 20)
        .expect_err("a v1 receipt does not credit the v2 entity");

    let v2_receipt = stamped_receipt_for_revision(&vault, "sk05.skill.rev", "2.0.0");
    record_skill_contributing_win(&vault, &v2, &v2_receipt, 21).expect("the revision matches");
    let posterior = project_skill_reliability_for(&vault, &v2, 22).expect("project");
    assert!((posterior.alpha - 2.0).abs() < 1e-6);
}

// ─── replica convergence ────────────────────────────────────────────────

#[test]
fn a_synced_posterior_is_the_base_a_local_loss_folds_onto() {
    // Sync carries entities and edges; `vault_meta` outcome rows stay
    // node-local. Recomputing `prior + local tally` and superseding the synced
    // claim destroys the other replica's history with one local loss.
    let (_tmp, vault) = temp_vault();
    let skill = EntityId::now();
    let actor = EntityId::now();
    put_active_import(&vault, &skill, "sk05.skill.replica");
    put_actor(&vault, &actor);

    plant_synced_claim(
        &vault,
        &skill,
        SkillReliabilityPosterior {
            alpha: 50.0,
            beta: 10.0,
        },
        &["attempt-receipt:remote-a"],
        20,
    );

    let (_, judgments) = route(&vault, &skill, &actor, "sk05.skill.replica", true, true, 30);
    project_skill_reliability(&vault, &judgments).expect("project");
    let after = skill_reliability_posterior(&vault, &skill)
        .expect("read")
        .expect("projected");
    assert!(
        (after.alpha - 50.0).abs() < 1e-6,
        "the other replica's wins survived"
    );
    assert!(
        (after.beta - 11.0).abs() < 1e-6,
        "the local loss folded onto them, it did not replace them"
    );

    // Re-projecting must not fold the imported base a second time…
    let replayed = project_skill_reliability_for(&vault, &skill, 31).expect("re-project");
    assert_eq!(replayed, after, "the base is imported once, not per pass");

    // …and a second local loss still moves β by exactly one.
    let (_, more) = route(&vault, &skill, &actor, "sk05.skill.replica", true, true, 32);
    project_skill_reliability(&vault, &more).expect("project");
    let after_second = skill_reliability_posterior(&vault, &skill)
        .expect("read")
        .expect("projected");
    assert!((after_second.alpha - 50.0).abs() < 1e-6);
    assert!((after_second.beta - 12.0).abs() < 1e-6);
}

#[test]
fn every_active_head_is_superseded_not_just_the_first() {
    // `EntityId::now()` is per-replica unique, so two replicas that both
    // projected this skill hold two distinct claim entities. After a sync both
    // are Active on the same subject, and superseding one leaves the other
    // active forever.
    let (_tmp, vault) = temp_vault();
    let skill = EntityId::now();
    put_active_import(&vault, &skill, "sk05.skill.fork");

    plant_synced_claim(
        &vault,
        &skill,
        SkillReliabilityPosterior {
            alpha: 4.0,
            beta: 1.0,
        },
        &["attempt-receipt:remote-a"],
        20,
    );
    plant_synced_claim(
        &vault,
        &skill,
        SkillReliabilityPosterior {
            alpha: 3.0,
            beta: 1.0,
        },
        &["attempt-receipt:remote-b"],
        21,
    );
    assert_eq!(
        active_reliability(&vault, &skill).len(),
        2,
        "the fork the sync produced"
    );

    let resolved = project_skill_reliability_for(&vault, &skill, 30).expect("project");
    assert_eq!(
        active_reliability(&vault, &skill).len(),
        1,
        "the fork collapsed to one head"
    );
    assert_eq!(
        claims(
            &vault,
            &skill,
            PREDICATE_SKILL_RELIABILITY,
            ClaimLifecycleStatus::Superseded
        )
        .len(),
        2,
        "both heads were superseded, not deleted"
    );
    assert!(
        (resolved.alpha - 4.0).abs() < 1e-6,
        "the richest head is the base"
    );
}

#[test]
fn supersession_clamps_to_the_prior_rows_event_time() {
    // `supersede_reserved_claim_in_txn` re-Puts the old row over
    // `{start: old_start, end: now}`. An out-of-order event time would make
    // that range invalid and roll the whole projection back — permanently,
    // because the retry re-derives the same `at`.
    let (_tmp, vault) = temp_vault();
    let skill = EntityId::now();
    put_active_import(&vault, &skill, "sk05.skill.clock");

    plant_synced_claim(
        &vault,
        &skill,
        SkillReliabilityPosterior {
            alpha: 6.0,
            beta: 2.0,
        },
        &["attempt-receipt:remote-late"],
        900,
    );

    let posterior =
        project_skill_reliability_for(&vault, &skill, 100).expect("out-of-order projection lands");
    assert!((posterior.alpha - 6.0).abs() < 1e-6);
    assert_eq!(active_reliability(&vault, &skill).len(), 1);
    assert_eq!(
        claims(
            &vault,
            &skill,
            PREDICATE_SKILL_RELIABILITY,
            ClaimLifecycleStatus::Superseded
        )
        .len(),
        1
    );
}

#[test]
fn the_floor_reads_the_claim_not_the_local_ledger() {
    // A replica that synced a below-floor posterior holds no outcome rows
    // behind it, so recomputing from the tally exits at
    // `outcomes < MIN_OUTCOMES` and skips the quarantine proposal the evidence
    // already demands.
    let (_tmp, vault) = temp_vault();
    let skill = EntityId::now();
    put_active_import(&vault, &skill, "sk05.skill.synced-floor");

    plant_synced_claim(
        &vault,
        &skill,
        SkillReliabilityPosterior {
            alpha: 1.0,
            beta: 20.0,
        },
        &["attempt-receipt:remote-loss"],
        20,
    );

    assert!(
        check_reliability_floor(&vault, &skill, 30)
            .expect("floor check")
            .is_some(),
        "the synced evidence crossed the floor"
    );
    let open = claims(
        &vault,
        &skill,
        PREDICATE_SKILL_QUARANTINE_PROPOSAL,
        ClaimLifecycleStatus::Active,
    );
    assert_eq!(open.len(), 1);
    assert_eq!(open[0].approval, ClaimApprovalStatus::Proposed);
}

// ─── frozen revisions ───────────────────────────────────────────────────

#[test]
fn a_late_outcome_on_a_frozen_revision_keeps_its_outcome_and_claim() {
    // The lifecycle machine hard-rejects any update to a superseded revision,
    // and the cache door shares the projection's write transaction — so a v1
    // outcome arriving after v2 was admitted would roll back the OUTCOME and
    // the CLAIM alongside the cache write it could never land.
    let (_tmp, vault) = temp_vault();
    let v1 = EntityId::now();
    let v2 = EntityId::now();
    put_active(
        &vault,
        &v1,
        versioned_record("sk05.skill.frozen", "1.0.0", ClaimSource::Imported, false),
    );
    put_active(
        &vault,
        &v2,
        versioned_record("sk05.skill.frozen", "2.0.0", ClaimSource::Imported, false),
    );
    vault
        .supersede_skill_record(&v1, &v2, t(20), 21)
        .expect("admit v2");

    let receipt = stamped_receipt_for_revision(&vault, "sk05.skill.frozen", "1.0.0");
    record_skill_contributing_win(&vault, &v1, &receipt, 22).expect("credit the frozen revision");
    let posterior = project_skill_reliability_for(&vault, &v1, 23).expect("the projection lands");

    assert!((posterior.alpha - 2.0).abs() < 1e-6);
    assert_eq!(
        active_reliability(&vault, &v1).len(),
        1,
        "truth landed on the frozen revision"
    );
    assert!(
        (vault
            .get_skill_record(&v1)
            .expect("read record")
            .expect("record")
            .confidence
            - 0.5)
            .abs()
            < 1e-6,
        "the frozen revision keeps the cache it was frozen with"
    );
}

#[test]
fn a_judgment_routed_against_an_earlier_revision_no_longer_grounds() {
    // ONE-1737's evidence door checks the manifest by `skill_id` ALONE, so a
    // judgment routed while the entity carried v1 stays persisted after the
    // entity revises in place. Counting it then would move v2's posterior with
    // a defect in bytes v2 does not contain — which is why grounding is
    // re-checked at THIS door, on the record as it stands now.
    let (_tmp, vault) = temp_vault();
    let skill = EntityId::now();
    let actor = EntityId::now();
    put_active(
        &vault,
        &skill,
        record("sk05.skill.drift", ClaimSource::Generated, true),
    );
    put_actor(&vault, &actor);

    let (_, judgments) = route(&vault, &skill, &actor, "sk05.skill.drift", true, true, 30);
    assert_eq!(judgments.len(), 1, "the routing door admitted it");

    let mut revised = vault
        .get_skill_record(&skill)
        .expect("read record")
        .expect("record");
    revised.version = "2.0.0".to_owned();
    revised.desc = "SK-05 reliability fixture, revised".to_owned();
    vault
        .update_skill_record(&skill, &revised, t(31), 32)
        .expect("admit the revision");

    assert!(
        project_skill_reliability(&vault, &judgments)
            .expect("project")
            .is_empty(),
        "the receipt names v1 and this entity is v2"
    );
    assert!(active_reliability(&vault, &skill).is_empty());
}
