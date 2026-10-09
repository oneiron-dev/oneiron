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
    if record.source == ClaimSource::Imported {
        return crate::skill_hub::test_support::admitted_import(vault, id, record);
    }
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
    stamped_receipt_for_as_model(vault, skill_id, version, None, None)
}

fn stamped_receipt_for_revision_as(
    vault: &Vault,
    skill_id: &str,
    version: &str,
    actor: Option<EntityId>,
) -> String {
    stamped_receipt_for_as_model(vault, skill_id, version, actor, None)
}

fn stamped_receipt_for_as_model(
    vault: &Vault,
    skill_id: &str,
    version: &str,
    actor: Option<EntityId>,
    model: Option<&str>,
) -> String {
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
    if let Some(actor) = actor {
        vault
            .bind_actor_attempt(attempt.id, &actor)
            .expect("bind executor");
    }
    queue
        .append_manifest_entry(
            attempt.id,
            ManifestEntry::new(ManifestKind::Skill, skill_id, version, 11),
        )
        .expect("manifest append");
    let ClaimOutcome::Claimed(leased) = queue
        .claim_kind(
            "sk05.attempt",
            ClaimAttempt {
                lease_owner: "sk05-worker".to_owned(),
                now: 12,
            },
        )
        .expect("claim")
    else {
        panic!("the enqueued attempt is claimable");
    };
    queue
        .set_executor_model(
            attempt.id,
            "sk05-worker",
            leased.attempt_count,
            model.unwrap_or("fixture/model@1"),
        )
        .expect("stamp model");
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
    let receipt_id = attempt_pack_receipt_id(&attempt.id);
    if model.is_none() {
        crate::receipt::make_attempt_receipt_legacy_for_tests(vault, &receipt_id)
            .expect("emulate older receipt without executor stamp");
    }
    receipt_id
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
    let receipt = stamped_receipt_for_revision_as(vault, skill_id, "1.0.0", Some(*actor));
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
    )
    .unwrap();
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

// ─── floor crossing ─────────────────────────────────────────────────────

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

#[test]
fn archived_reliability_does_not_seed_a_posterior_cache_or_local_projection() -> crate::Result<()> {
    let (_source_dir, source) = temp_vault();
    let (_target_dir, target) = temp_vault();
    let skill = EntityId::now();
    put_active(
        &source,
        &skill,
        record("archive.reliability", ClaimSource::UserStated, false),
    );
    for at in 20..23 {
        record_skill_contributing_win(
            &source,
            &skill,
            &stamped_receipt(&source, "archive.reliability"),
            at,
        )?;
    }
    let native = project_skill_reliability_for(&source, &skill, 30)?;
    assert_eq!(skill_reliability_posterior(&source, &skill)?, Some(native));
    let id = source
        .claims_for_subject(&skill)?
        .into_iter()
        .find(|id| {
            source.get_claim(id).unwrap().is_some_and(|c| {
                c.predicate == PREDICATE_SKILL_RELIABILITY
                    && c.lifecycle == ClaimLifecycleStatus::Active
            })
        })
        .unwrap();
    let original = source.get_claim(&id)?.unwrap();
    let export = source.export_whole_vault(crate::context_pack::PackFormat::Json)?;
    target.import_whole_vault_json(export.bytes())?;
    let imported = target.get_claim(&id)?.unwrap();
    assert_eq!(imported.value, original.value);
    assert_eq!(imported.evidence, original.evidence);
    assert_eq!(imported.source, Some(ClaimSource::Imported));
    assert_eq!(imported.approval, ClaimApprovalStatus::Proposed);
    assert_eq!(skill_reliability_posterior(&target, &skill)?, None);
    let prior = skill_reliability_prior(&target, &skill)?;
    assert_ne!(prior, native);
    assert_eq!(
        rebuild_skill_confidence_cache(&target, &skill, 80)?,
        prior.mean()
    );
    let projected = project_skill_reliability_for(&target, &skill, 81)?;
    assert_eq!(projected, prior);
    assert_eq!(target.get_claim(&id)?, Some(imported.clone()));
    assert_eq!(skill_reliability_posterior(&target, &skill)?, Some(prior));
    for approval in [ClaimApprovalStatus::Auto, ClaimApprovalStatus::Approved] {
        let mut forged = imported.clone();
        forged.approval = approval;
        let bytes = crate::claim::encode_claim_body(&forged)?;
        assert!(
            target
                .batch()
                .put_replicated(
                    &EntityId::now(),
                    crate::registry::ENTITY_TYPE_CLAIM,
                    t(90),
                    90,
                    &bytes
                )
                .commit()
                .is_err()
        );
    }
    Ok(())
}

#[test]
fn swapping_executor_forks_statistics_without_retiring_skill() -> crate::error::Result<()> {
    let (_tmp, vault) = temp_vault();
    let skill = EntityId::now();
    let actor = EntityId::now();
    put_active_import(&vault, &skill, "sk05.pair.swap");
    put_actor(&vault, &actor);
    let prior = skill_reliability_prior(&vault, &skill)?;
    let old = stamped_receipt_for_as_model(
        &vault,
        "sk05.pair.swap",
        "1.0.0",
        Some(actor),
        Some("old@1"),
    );
    record_skill_contributing_win(&vault, &skill, &old, 20)?;
    project_skill_reliability_for_executor(&vault, &skill, "old@1", 21)?;
    let old_posterior = skill_reliability_posterior_for_executor(&vault, &skill, "old@1")?.unwrap();
    assert_eq!(old_posterior.alpha, prior.alpha + 1.0);
    assert_eq!(
        skill_executor_reliability(&vault, &skill, "new@2")?.posterior,
        prior
    );
    assert_eq!(skill_executor_reliability(&vault, &skill, "new@2")?.runs, 0);
    assert!(skill_executor_reliability(&vault, &skill, "new@2")?.new_model);
    assert_eq!(
        skill_reliability_posterior_for_executor(&vault, &skill, "new@2")?,
        None
    );
    assert_eq!(skill_reliability_posterior(&vault, &skill)?, None);
    assert_eq!(
        vault.get_skill_record(&skill)?.unwrap().lifecycle_status,
        SkillLifecycle::Active
    );

    // An A/B slice credits only the new model. A held-out rerun has the same
    // receipt-stamped door; neither can borrow the incumbent's observations.
    for _ in 0..2 {
        let new_receipt = stamped_receipt_for_as_model(
            &vault,
            "sk05.pair.swap",
            "1.0.0",
            Some(actor),
            Some("new@2"),
        );
        record_skill_contributing_win(&vault, &skill, &new_receipt, 22)?;
        project_skill_reliability_for_executor(&vault, &skill, "new@2", 23)?;
    }
    let new = skill_executor_reliability(&vault, &skill, "new@2")?;
    assert_eq!(new.runs, 2);
    assert!(!new.new_model);
    assert_eq!(new.posterior.alpha, prior.alpha + 2.0);
    assert_eq!(
        skill_reliability_posterior_for_executor(&vault, &skill, "old@1")?,
        Some(old_posterior)
    );
    assert_eq!(
        skill_reliability_posterior_for_executor(&vault, &skill, "new@3")?,
        None
    );
    assert_eq!(
        skill_selection_score_for_executor(&vault, &skill, "new@3", 8)?,
        prior.ucb(8)
    );

    let failed = stamped_receipt_for_as_model(
        &vault,
        "sk05.pair.swap",
        "1.0.0",
        Some(actor),
        Some("new@2"),
    );
    record_attribution_evidence(
        &vault,
        &OutcomeEvidence::new(&failed, actor, AttemptOutcome::Failed, 24)
            .with_skill(skill)
            .with_routing_facts(true, true),
    )?;
    let judgments = run_attribution_projector(&vault, read_attribution_cursor(&vault)?)?;
    project_skill_reliability(&vault, &judgments)?;
    assert_eq!(
        skill_reliability_posterior_for_executor(&vault, &skill, "new@2")?
            .unwrap()
            .beta,
        prior.beta + 1.0
    );
    assert_eq!(
        skill_reliability_posterior_for_executor(&vault, &skill, "old@1")?,
        Some(old_posterior)
    );
    Ok(())
}

#[test]
fn executor_stamp_is_write_once_and_survives_terminal_receipt() -> crate::error::Result<()> {
    let (_tmp, vault) = temp_vault();
    let queue = AttemptQueue::new(&vault);
    let EnqueueOutcome::Enqueued(row) = queue.enqueue(EnqueueAttempt {
        kind: "sk05.stamp".to_owned(),
        payload: vec![],
        dedupe_key: None,
        run_id: None,
        now: 10,
    })?
    else {
        panic!("fresh attempt")
    };
    queue.append_manifest_entry(
        row.id,
        ManifestEntry::new(ManifestKind::Skill, "skill-stamp", "1", 11),
    )?;
    assert!(
        queue
            .set_executor_model(row.id, "worker", 1, "provider/model@1")
            .is_err()
    );
    let ClaimOutcome::Claimed(leased) = queue.claim(ClaimAttempt {
        lease_owner: "worker".to_owned(),
        now: 12,
    })?
    else {
        panic!("leased")
    };
    assert!(
        queue
            .set_executor_model(row.id, "other", leased.attempt_count, "provider/model@1")
            .is_err()
    );
    queue.set_executor_model(row.id, "worker", leased.attempt_count, "provider/model@1")?;
    assert!(
        queue
            .set_executor_model(row.id, "worker", leased.attempt_count, "provider/model@2")
            .is_err()
    );
    assert!(
        queue
            .set_executor_model(row.id, "worker", leased.attempt_count, "")
            .is_err()
    );
    queue.complete(CompleteAttempt {
        id: row.id,
        lease_owner: "worker".to_owned(),
        attempt_count: leased.attempt_count,
        now: 13,
    })?;
    assert_eq!(
        queue
            .set_executor_model(row.id, "worker", leased.attempt_count, "provider/model@1")?
            .executor_model
            .as_deref(),
        Some("provider/model@1")
    );
    assert!(
        queue
            .set_executor_model(row.id, "worker", leased.attempt_count, "provider/model@2")
            .is_err()
    );
    let receipt =
        crate::receipt::attempt_pack_receipt(&vault, &attempt_pack_receipt_id(&row.id))?.unwrap();
    assert_eq!(
        receipt.fields.get("model").map(String::as_str),
        Some("provider/model@1")
    );
    Ok(())
}

#[test]
fn displaced_judge_marks_receipt_and_supersedes_weight_without_erasing() -> crate::error::Result<()>
{
    let (_tmp, vault) = temp_vault();
    let skill = EntityId::now();
    let actor = EntityId::now();
    put_active_import(&vault, &skill, "sk05.displaced");
    put_actor(&vault, &actor);
    let receipt = stamped_receipt_for_as_model(
        &vault,
        "sk05.displaced",
        "1.0.0",
        Some(actor),
        Some("executor@1"),
    );
    record_attribution_evidence(
        &vault,
        &OutcomeEvidence::new(&receipt, actor, AttemptOutcome::Failed, 30)
            .with_skill(skill)
            .with_routing_facts(true, true),
    )?;
    let judgments = run_attribution_projector(&vault, read_attribution_cursor(&vault)?)?;
    project_skill_reliability(&vault, &judgments)?;
    assert_eq!(
        skill_executor_reliability(&vault, &skill, "executor@1")?.runs,
        1
    );
    let marked = crate::skill_attribution::supersede_displaced_judge_receipts(
        &vault,
        "rule-attribution@1",
        "replacement@2",
        32,
    )?;
    assert_eq!(marked.len(), 1);
    assert_eq!(marked[0].receipt_ref, receipt);
    assert_eq!(
        skill_executor_reliability(&vault, &skill, "executor@1")?.runs,
        0
    );
    assert_eq!(
        crate::skill_attribution::attribution_judgments(&vault)?,
        judgments
    );
    assert!(crate::receipt::attempt_pack_receipt(&vault, &receipt)?.is_some());
    assert_eq!(
        crate::skill_attribution::supersede_displaced_judge_receipts(
            &vault,
            "rule-attribution@1",
            "replacement@2",
            33
        )?
        .len(),
        1
    );
    project_skill_reliability(&vault, &judgments)?;
    assert_eq!(
        skill_executor_reliability(&vault, &skill, "executor@1")?.runs,
        0
    );
    Ok(())
}

#[test]
fn replay_cannot_reassign_an_unknown_judgment_to_a_new_judge() -> crate::error::Result<()> {
    use crate::skill_attribution::{
        AttributionJudge, RuleAttributionJudge, run_attribution_projector_with_judge,
    };
    struct Unknown;
    impl AttributionJudge for Unknown {
        fn judge(
            &self,
            evidence: &OutcomeEvidence,
        ) -> crate::error::Result<Option<AttributionVerdict>> {
            RuleAttributionJudge.judge(evidence)
        }
    }
    let (_tmp, vault) = temp_vault();
    let skill = EntityId::now();
    let actor = EntityId::now();
    put_active_import(&vault, &skill, "sk05.unknown-judge");
    put_actor(&vault, &actor);
    let receipt = stamped_receipt_for_as_model(
        &vault,
        "sk05.unknown-judge",
        "1.0.0",
        Some(actor),
        Some("model@1"),
    );
    record_attribution_evidence(
        &vault,
        &OutcomeEvidence::new(&receipt, actor, AttemptOutcome::Failed, 30)
            .with_skill(skill)
            .with_routing_facts(true, true),
    )?;
    let rows = run_attribution_projector_with_judge(&vault, 0, &Unknown)?;
    project_skill_reliability(&vault, &rows)?;
    run_attribution_projector_with_judge(&vault, 0, &RuleAttributionJudge)?;
    assert!(
        crate::skill_attribution::supersede_displaced_judge_receipts(
            &vault,
            "rule-attribution@1",
            "rule-attribution@2",
            40
        )?
        .is_empty()
    );
    assert_eq!(
        skill_executor_reliability(&vault, &skill, "model@1")?.runs,
        1
    );
    Ok(())
}

#[test]
fn displacement_between_batch_read_and_writer_cannot_restore_loss() -> crate::error::Result<()> {
    let (_tmp, vault) = temp_vault();
    let skill = EntityId::now();
    let actor = EntityId::now();
    put_active_import(&vault, &skill, "sk05.race");
    put_actor(&vault, &actor);
    let receipt =
        stamped_receipt_for_as_model(&vault, "sk05.race", "1.0.0", Some(actor), Some("model@1"));
    record_attribution_evidence(
        &vault,
        &OutcomeEvidence::new(&receipt, actor, AttemptOutcome::Failed, 30)
            .with_skill(skill)
            .with_routing_facts(true, true),
    )?;
    let rows = run_attribution_projector(&vault, read_attribution_cursor(&vault)?)?;
    std::thread::scope(|scope| -> crate::error::Result<()> {
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(0);
        let (resume_tx, resume_rx) = std::sync::mpsc::sync_channel(0);
        let projector = scope.spawn(|| {
            super::projector::set_pre_write_hook(Box::new(move || {
                ready_tx.send(()).expect("notify before writer");
                resume_rx.recv().expect("wait for judge displacement");
            }));
            project_skill_reliability(&vault, &rows)
        });
        ready_rx.recv().expect("projector completed its pre-read");
        crate::skill_attribution::supersede_displaced_judge_receipts(
            &vault,
            "rule-attribution@1",
            "replacement@2",
            31,
        )?;
        resume_tx.send(()).expect("release projector");
        projector.join().expect("projector thread")?;
        Ok(())
    })?;
    assert_eq!(
        skill_executor_reliability(&vault, &skill, "model@1")?.runs,
        0
    );
    assert_eq!(
        crate::skill_attribution::displaced_judge_receipts(&vault)?.len(),
        1
    );
    Ok(())
}

#[test]
fn displaced_attribution_judge_cannot_commit_a_new_inflight_verdict() -> crate::error::Result<()> {
    use crate::skill_attribution::{
        AttributionJudge, RuleAttributionJudge, run_attribution_projector_with_judge,
    };
    struct SlowOld<'a> {
        vault: &'a Vault,
        displaced: std::cell::Cell<bool>,
    }
    impl AttributionJudge for SlowOld<'_> {
        fn judge_revision(&self) -> Option<&str> {
            Some("old-attribution@1")
        }
        fn judge(
            &self,
            evidence: &OutcomeEvidence,
        ) -> crate::error::Result<Option<AttributionVerdict>> {
            if !self.displaced.replace(true) {
                crate::skill_attribution::supersede_displaced_judge_receipts(
                    self.vault,
                    "old-attribution@1",
                    "new-attribution@2",
                    30,
                )?;
            }
            RuleAttributionJudge.judge(evidence)
        }
    }
    let (_tmp, vault) = temp_vault();
    let skill = EntityId::now();
    let actor = EntityId::now();
    put_active_import(&vault, &skill, "sk05.inflight-judge");
    put_actor(&vault, &actor);
    let receipt = stamped_receipt_for_as_model(
        &vault,
        "sk05.inflight-judge",
        "1.0.0",
        Some(actor),
        Some("model@1"),
    );
    record_attribution_evidence(
        &vault,
        &OutcomeEvidence::new(&receipt, actor, AttemptOutcome::Failed, 29)
            .with_skill(skill)
            .with_routing_facts(true, true),
    )?;
    let old = SlowOld {
        vault: &vault,
        displaced: std::cell::Cell::new(false),
    };
    assert!(run_attribution_projector_with_judge(&vault, 0, &old).is_err());
    assert!(crate::skill_attribution::attribution_judgments(&vault)?.is_empty());
    assert!(
        project_skill_reliability_for_executor(&vault, &skill, "model@1", 31)?.observations()
            == skill_reliability_prior(&vault, &skill)?.observations()
    );
    Ok(())
}

#[test]
fn displacement_scan_cannot_miss_a_judgment_committed_before_its_writer() -> crate::error::Result<()>
{
    let (_tmp, vault) = temp_vault();
    let skill = EntityId::now();
    let actor = EntityId::now();
    put_active_import(&vault, &skill, "sk05.replacement-scan");
    put_actor(&vault, &actor);
    let receipt = stamped_receipt_for_as_model(
        &vault,
        "sk05.replacement-scan",
        "1.0.0",
        Some(actor),
        Some("model@1"),
    );
    std::thread::scope(|scope| -> crate::error::Result<()> {
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(0);
        let (resume_tx, resume_rx) = std::sync::mpsc::sync_channel(0);
        let replacement = scope.spawn(|| {
            crate::skill_attribution::set_pre_writer_hook(Box::new(move || {
                ready_tx.send(()).expect("replacement about to take writer");
                resume_rx.recv().expect("wait for new J1 judgment");
            }));
            crate::skill_attribution::supersede_displaced_judge_receipts(
                &vault,
                "rule-attribution@1",
                "new-judge@2",
                40,
            )
        });
        ready_rx.recv().expect("replacement prepared");
        record_attribution_evidence(
            &vault,
            &OutcomeEvidence::new(&receipt, actor, AttemptOutcome::Failed, 30)
                .with_skill(skill)
                .with_routing_facts(true, true),
        )?;
        let rows = run_attribution_projector(&vault, read_attribution_cursor(&vault)?)?;
        assert_eq!(rows.len(), 1);
        resume_tx.send(()).expect("release replacement");
        let displaced = replacement.join().expect("replacement thread")?;
        assert_eq!(displaced.len(), 1);
        project_skill_reliability(&vault, &rows)?;
        Ok(())
    })?;
    assert_eq!(
        skill_executor_reliability(&vault, &skill, "model@1")?.runs,
        0
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
    Ok(())
}

mod resident;
