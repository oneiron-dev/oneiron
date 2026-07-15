use rmpv::Value as Mp;

use crate::claim::{ClaimSubject, claim_consolidatable};
use crate::config::VaultConfig;
use crate::dreamer_runner::{
    DreamerRunnerStore, EnqueueDreamerAttempt, EnqueueDreamerAttemptOutcome,
};
use crate::edge::{EdgeActorClass, EdgeKind};
use crate::gate::GateOutcome;
use crate::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_SESSION, ENTITY_TYPE_TURN};
use crate::temporal::TimeRange;
use crate::write_envelope::ClaimCandidate;
use crate::{EntityId, Vault};

use super::*;

fn open_vault() -> (tempfile::TempDir, Vault) {
    crate::test_util::open_test_vault_with(VaultConfig::device())
}

/// A vault that KEEPS the default policy manifest, so gate evaluations
/// record decision receipts (the shared helper clears it for legacy tests).
fn open_gated_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("open vault");
    (dir, vault)
}

fn occurred(at: u64) -> TimeRange {
    TimeRange { start: at, end: at }
}

struct PromotionFixture {
    run: DreamerRunContext,
    subject: EntityId,
    turn: EntityId,
}

fn fixture(vault: &Vault) -> Result<PromotionFixture> {
    let actor = EntityId::now();
    let subject = EntityId::now();
    let conversation = EntityId::now();
    let turn = EntityId::now();
    vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred(1), 1, b"agent")?;
    vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred(1), 1, b"subject")?;
    vault.put_entity(
        &conversation,
        ENTITY_TYPE_SESSION,
        occurred(1),
        1,
        b"session",
    )?;
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &Mp::Map(vec![
            (Mp::from("txt"), Mp::from("my name is Oleksii")),
            (Mp::from("spkr"), Mp::from("user")),
        ]),
    )
    .expect("turn body");
    vault
        .batch()
        .put(&turn, ENTITY_TYPE_TURN, occurred(5), 5, &body)
        .edge(&turn, EdgeKind::ChildOf, &conversation, 1.0)
        .commit()?;

    let runner = DreamerRunnerStore::new(vault);
    let status = match runner.enqueue(EnqueueDreamerAttempt {
        attempt_type: "promotion-test".to_owned(),
        input: Mp::from("input"),
        parent_attempt: None,
        dedupe_key: None,
        run_id: Some("run-promo".to_owned()),
        now: 6,
    })? {
        EnqueueDreamerAttemptOutcome::Enqueued(status)
        | EnqueueDreamerAttemptOutcome::Existing(status) => status,
    };

    Ok(PromotionFixture {
        run: DreamerRunContext {
            run_id: "run-promo".to_owned(),
            attempt_id: status.attempt.id,
            agent_actor: WriteActor::new(actor, EdgeActorClass::Agent),
            now_ms: 10_000,
        },
        subject,
        turn,
    })
}

fn candidate(
    fixture: &PromotionFixture,
    predicate: &str,
    value: &str,
    evidence: Vec<EntityId>,
) -> PromotionCandidate {
    PromotionCandidate {
        claim_id: EntityId::now(),
        candidate: ClaimCandidate::new(
            predicate,
            ClaimSubject::Entity(fixture.subject),
            Mp::from(value),
            0.7,
        ),
        evidence_turn_refs: evidence,
        supersedes: None,
        evidence_meet: ClaimSource::Generated,
        occurred: occurred(9_000),
        learned_at: 9_000,
    }
}

fn user_stated_head(
    vault: &Vault,
    fixture: &PromotionFixture,
    predicate: &str,
) -> Result<EntityId> {
    let human = EntityId::now();
    vault.put_entity(&human, ENTITY_TYPE_PERSON, occurred(1), 1, b"human")?;
    let claim_id = EntityId::now();
    let envelope = WriteEnvelope::new(
        WriteActor::new(human, EdgeActorClass::Human),
        ClaimSource::UserStated,
        WriteProvenance::new(Mp::from("promotion-test"))?,
        ClaimApprovalStatus::Approved,
    );
    vault
        .batch()
        .claim_candidate(
            &claim_id,
            ClaimCandidate::new(
                predicate,
                ClaimSubject::Entity(fixture.subject),
                Mp::from("owner truth"),
                0.9,
            ),
            &envelope,
            occurred(2_000),
            2_000,
        )
        .commit()?;
    Ok(claim_id)
}

fn gate_decision_count(vault: &Vault) -> usize {
    vault
        .store
        .gate_decisions(1_000)
        .expect("gate decisions")
        .len()
}

#[test]
fn promotion_lands_as_generated_proposed_through_gate() -> Result<()> {
    let (_dir, vault) = open_gated_vault();
    let fixture = fixture(&vault)?;
    let promoted = candidate(&fixture, "profile.name", "Oleksii", vec![fixture.turn]);
    let claim_id = promoted.claim_id;

    let outcome = promote_consolidated_claims(&vault, &fixture.run, vec![promoted])?;
    assert_eq!(outcome.pended, vec![claim_id], "Proposed lane");
    assert!(outcome.landed.is_empty());
    assert!(outcome.rejected.is_empty());

    let body = vault.get_claim(&claim_id)?.expect("landed claim");
    assert_eq!(body.source, Some(ClaimSource::Generated));
    assert_eq!(body.approval, ClaimApprovalStatus::Proposed);

    // Envelope-stamped evidence map: actor/class/provenance keys plus the
    // writer-supplied candidate_evidence carrying the surviving turn refs.
    let Some(Mp::Map(evidence)) = &body.evidence else {
        panic!("expected envelope evidence map");
    };
    let keys: Vec<&str> = evidence
        .iter()
        .filter_map(|(key, _)| key.as_str())
        .collect();
    assert!(keys.contains(&"actor_entity_ref"));
    assert!(keys.contains(&"actor_class"));
    assert!(keys.contains(&"provenance"));
    assert!(keys.contains(&"candidate_evidence"));
    let candidate_evidence = evidence
        .iter()
        .find(|(key, _)| key.as_str() == Some("candidate_evidence"))
        .map(|(_, value)| value)
        .expect("candidate_evidence entry");
    let Mp::Array(refs) = candidate_evidence else {
        panic!("candidate_evidence must be an array");
    };
    assert_eq!(refs.len(), 1);
    assert_eq!(
        refs[0],
        Mp::Binary(fixture.turn.as_bytes().to_vec()),
        "the surviving turn ref is stamped"
    );

    let claim_decisions: Vec<_> = vault
        .store
        .gate_decisions(1_000)?
        .into_iter()
        .filter(|decision| decision.claim_id == Some(*claim_id.as_bytes()))
        .collect();
    assert_eq!(
        claim_decisions.len(),
        1,
        "one promotion must append exactly one gate decision"
    );
    assert_eq!(
        claim_decisions[0].outcome,
        GateOutcome::Pending.as_str(),
        "the gate outcome stays Pending while the claim is stamped Proposed"
    );
    Ok(())
}

#[test]
fn promotion_cannot_supersede_user_stated() -> Result<()> {
    let (_dir, vault) = open_gated_vault();
    let fixture = fixture(&vault)?;
    let head = user_stated_head(&vault, &fixture, "profile.name")?;

    let mut superseding = candidate(&fixture, "profile.name", "Wrong", vec![fixture.turn]);
    superseding.supersedes = Some(head);
    let superseding_id = superseding.claim_id;
    let clean = candidate(&fixture, "profile.tone", "warm", vec![fixture.turn]);
    let clean_id = clean.claim_id;

    let outcome = promote_consolidated_claims(&vault, &fixture.run, vec![superseding, clean])?;

    // GATE-007 surfaced per-candidate; nothing written for the rejected one
    // (the one-wtxn contract rolled the claim back with the supersession).
    assert_eq!(outcome.rejected.len(), 1);
    assert_eq!(outcome.rejected[0].0, superseding_id);
    assert!(vault.get_claim(&superseding_id)?.is_none(), "rolled back");
    let superseding_receipts = vault
        .store
        .gate_decisions(1_000)?
        .into_iter()
        .filter(|decision| decision.claim_id == Some(*superseding_id.as_bytes()))
        .count();
    assert_eq!(
        superseding_receipts, 0,
        "failed supersession must roll back its same-transaction gate decision"
    );
    let superseding_consents = vault
        .store
        .pending_gate_consents(1_000)?
        .into_iter()
        .filter(|consent| consent.claim_id == *superseding_id.as_bytes())
        .count();
    assert_eq!(
        superseding_consents, 0,
        "failed supersession must roll back its same-transaction pending consent"
    );

    // The UserStated head is untouched and the other candidate landed.
    let head_body = vault.get_claim(&head)?.expect("head");
    assert_eq!(
        head_body.lifecycle,
        crate::claim::ClaimLifecycleStatus::Active
    );
    assert_eq!(outcome.pended, vec![clean_id]);
    Ok(())
}

#[test]
fn per_op_gating_no_bulk() -> Result<()> {
    let (_dir, vault) = open_gated_vault();
    let fixture = fixture(&vault)?;
    let candidates = vec![
        candidate(&fixture, "profile.name", "Oleksii", vec![fixture.turn]),
        candidate(&fixture, "profile.tone", "warm", vec![fixture.turn]),
        candidate(&fixture, "profile.lives_in", "Tokyo", vec![fixture.turn]),
    ];

    let decisions_before = gate_decision_count(&vault);
    let outcome = promote_consolidated_claims(&vault, &fixture.run, candidates)?;
    assert_eq!(outcome.pended.len(), 3);

    // N candidates = N separate gate evaluations (one decision receipt
    // each) — a single batched txn would record fewer.
    assert_eq!(
        gate_decision_count(&vault) - decisions_before,
        3,
        "one gate evaluation per candidate"
    );
    Ok(())
}

#[test]
fn tainted_meet_forces_proposed_and_stamps_scope() -> Result<()> {
    let (_dir, vault) = open_vault();
    let fixture = fixture(&vault)?;
    let mut tainted = candidate(&fixture, "profile.employer", "ACME", vec![fixture.turn]);
    tainted.evidence_meet = ClaimSource::ToolOutput;
    let claim_id = tainted.claim_id;

    let outcome = promote_consolidated_claims(&vault, &fixture.run, vec![tainted])?;
    assert_eq!(outcome.pended, vec![claim_id], "taint forces Proposed");

    let body = vault.get_claim(&claim_id)?.expect("landed claim");
    assert_eq!(body.approval, ClaimApprovalStatus::Proposed);
    assert_eq!(claim_evidence_taint(&body), Some(ClaimSource::ToolOutput));
    let Some(Mp::Map(scope)) = &body.scope else {
        panic!("expected scope map");
    };
    assert!(scope.iter().any(|(key, value)| {
        key.as_str() == Some("evidence_taint") && value.as_str() == Some("tool_output")
    }));

    // Tainted claims are surfaceable but not consolidatable (GATE-05/006).
    assert!(!claim_consolidatable(&body));
    Ok(())
}

#[test]
fn tainted_head_clean_candidate_folds_taint() -> Result<()> {
    let (_dir, vault) = open_vault();
    let fixture = fixture(&vault)?;

    // A tainted head: promoted earlier with a ToolOutput meet.
    let mut head = candidate(&fixture, "profile.employer", "ACME", vec![fixture.turn]);
    head.evidence_meet = ClaimSource::ToolOutput;
    let head_id = head.claim_id;
    let outcome = promote_consolidated_claims(&vault, &fixture.run, vec![head])?;
    assert_eq!(outcome.pended, vec![head_id]);

    // A CLEAN candidate (meet = Generated) supersedes the tainted head:
    // the old head's taint folds into the effective meet BEFORE stamping —
    // no laundering — and the new head stays in the Proposed lane.
    let mut clean = candidate(
        &fixture,
        "profile.employer",
        "ACME Corp",
        vec![fixture.turn],
    );
    clean.supersedes = Some(head_id);
    let clean_id = clean.claim_id;
    let outcome = promote_consolidated_claims(&vault, &fixture.run, vec![clean])?;
    assert_eq!(outcome.pended, vec![clean_id], "fail-closed Proposed lane");
    assert!(outcome.rejected.is_empty());

    let new_head = vault.get_claim(&clean_id)?.expect("new head");
    assert_eq!(
        claim_evidence_taint(&new_head),
        Some(ClaimSource::ToolOutput),
        "the folded taint rides the new head"
    );
    let old_head = vault.get_claim(&head_id)?.expect("old head");
    assert_eq!(
        old_head.lifecycle,
        crate::claim::ClaimLifecycleStatus::Superseded
    );
    Ok(())
}

#[test]
fn generated_evidence_gives_no_boost() -> Result<()> {
    let (_dir, vault) = open_vault();
    let fixture = fixture(&vault)?;

    // A Generated claim in the store (an earlier promotion).
    let generated = candidate(&fixture, "profile.tone", "warm", vec![fixture.turn]);
    let generated_id = generated.claim_id;
    promote_consolidated_claims(&vault, &fixture.run, vec![generated])?;

    // A candidate citing the Generated claim AND a turn: the claim ref is
    // dropped from corroboration; confidence is untouched by the writer.
    let citing = candidate(
        &fixture,
        "profile.name",
        "Oleksii",
        vec![generated_id, fixture.turn],
    );
    let citing_id = citing.claim_id;
    let baseline = candidate(&fixture, "profile.hobby", "climbing", vec![fixture.turn]);
    let baseline_id = baseline.claim_id;
    let outcome = promote_consolidated_claims(&vault, &fixture.run, vec![citing, baseline])?;
    assert_eq!(outcome.pended, vec![citing_id, baseline_id]);

    let citing_body = vault.get_claim(&citing_id)?.expect("citing claim");
    let Some(Mp::Map(evidence)) = &citing_body.evidence else {
        panic!("expected evidence map");
    };
    let candidate_evidence = evidence
        .iter()
        .find(|(key, _)| key.as_str() == Some("candidate_evidence"))
        .map(|(_, value)| value)
        .expect("candidate_evidence entry");
    let Mp::Array(refs) = candidate_evidence else {
        panic!("candidate_evidence must be an array");
    };
    assert_eq!(refs.len(), 1, "the Generated claim ref was dropped");
    assert_eq!(refs[0], Mp::Binary(fixture.turn.as_bytes().to_vec()));

    let baseline_body = vault.get_claim(&baseline_id)?.expect("baseline claim");
    assert_eq!(
        citing_body.confidence, baseline_body.confidence,
        "zero confidence boost from the Generated ref"
    );

    // A candidate whose ONLY evidence is the Generated claim is rejected.
    let only_generated = candidate(&fixture, "profile.age", "40", vec![generated_id]);
    let only_id = only_generated.claim_id;
    let outcome = promote_consolidated_claims(&vault, &fixture.run, vec![only_generated])?;
    assert_eq!(outcome.rejected.len(), 1);
    assert_eq!(outcome.rejected[0].0, only_id);
    assert!(vault.get_claim(&only_id)?.is_none());
    Ok(())
}

#[test]
fn landed_verification_blocks_ack() -> Result<()> {
    let (_dir, vault) = open_vault();
    let fixture = fixture(&vault)?;

    // Drive the verification leg directly: a claim that "landed" but is
    // gone at re-read time is a rejection (caller must fail the attempt).
    let promoted = candidate(&fixture, "profile.name", "Oleksii", vec![fixture.turn]);
    let claim_id = promoted.claim_id;
    promote_consolidated_claims(&vault, &fixture.run, vec![promoted])?;
    assert!(vault.get_claim(&claim_id)?.is_some());

    vault.delete_entity(&claim_id)?;
    let verdict = verify_landed(&vault, &claim_id, "profile.name");
    assert!(
        verdict.is_err(),
        "a write that cannot be re-read never verifies"
    );
    assert!(
        verdict.unwrap_err().contains("missing"),
        "typed missing-after-commit reason"
    );

    // Predicate mismatch also fails verification.
    let survivor = candidate(&fixture, "profile.tone", "warm", vec![fixture.turn]);
    let survivor_id = survivor.claim_id;
    promote_consolidated_claims(&vault, &fixture.run, vec![survivor])?;
    assert!(verify_landed(&vault, &survivor_id, "profile.other").is_err());
    Ok(())
}

#[cfg(feature = "sync")]
#[test]
fn replay_path_still_skips_source_trust_gate() -> Result<()> {
    let (_dir, vault) = open_vault();
    let fixture = fixture(&vault)?;
    let promoted = candidate(&fixture, "profile.name", "Oleksii", vec![fixture.turn]);
    let claim_id = promoted.claim_id;
    promote_consolidated_claims(&vault, &fixture.run, vec![promoted])?;

    // Replicate the promoted claim's stored bytes into a second vault via
    // the replicated-put door: it must land WITHOUT re-gating (no new gate
    // decision) — replication and replay never re-run policy checks.
    let raw = vault.get_raw(&claim_id)?.expect("stored claim");
    let body_bytes = &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..];

    let (_dir_b, vault_b) = open_vault();
    let decisions_before = gate_decision_count(&vault_b);
    vault_b
        .batch()
        .put_replicated(
            &claim_id,
            crate::registry::ENTITY_TYPE_CLAIM,
            occurred(9_000),
            9_000,
            body_bytes,
        )
        .commit()?;
    assert!(
        vault_b.get_raw(&claim_id)?.is_some(),
        "replicated replay must not re-gate promoted claims"
    );
    assert_eq!(
        gate_decision_count(&vault_b),
        decisions_before,
        "no gate decision on the replay path"
    );
    Ok(())
}

#[test]
fn writer_sink_routes_through_promotion() -> Result<()> {
    use crate::dreamer_consolidation::ConsolidationSink;

    let (_dir, vault) = open_vault();
    let promo = fixture(&vault)?;
    let promoted = candidate(&promo, "profile.name", "Oleksii", vec![promo.turn]);
    let claim_id = promoted.claim_id;

    let mut sink = PromotionWriterSink::new(&vault, promo.run);
    sink.accept(vec![promoted])?;
    assert_eq!(sink.outcome.pended, vec![claim_id]);
    assert!(sink.outcome.rejected.is_empty());
    assert!(vault.get_claim(&claim_id)?.is_some());
    Ok(())
}
