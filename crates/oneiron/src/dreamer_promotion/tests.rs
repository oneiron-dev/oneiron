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

/// A vault whose policy manifest GRANTS the Dreamer's Auto request: an
/// `agent` actor ceiling, an explicit auto permit for every provenance
/// source, and a manifest signature (the Dreamer auto-grant requires one).
///
/// ONE-1710 made `Auto` the universal promotion request — there is no
/// Proposed lane to fall into any more — so the promotion tests must state
/// the owner policy that permits the write instead of observing the queue
/// that used to absorb it. A vault WITHOUT this permit rejects the
/// candidate; `promotion_rejects_rather_than_pends_without_an_auto_permit`
/// pins exactly that.
fn open_auto_vault() -> (tempfile::TempDir, Vault) {
    let (dir, vault) = open_vault();
    let id = crate::gate::default_policy_manifest_id().expect("default policy manifest id");
    crate::test_util::put_policy_manifest_bytes(&vault, id, &auto_permitting_manifest())
        .expect("seed the auto-permitting policy manifest");
    (dir, vault)
}

fn auto_permitting_manifest() -> Vec<u8> {
    let source_row = || {
        Mp::Map(vec![
            (Mp::from("max_auto_sensitivity"), Mp::from(3_u64)),
            (Mp::from("receipted"), Mp::Boolean(true)),
            (Mp::from("warned"), Mp::Boolean(true)),
        ])
    };
    let manifest = Mp::Map(vec![
        (Mp::from("schema_version"), Mp::from("1.1")),
        (Mp::from("pack_id"), Mp::from("dreamer-promotion-test")),
        (Mp::from("pack_version"), Mp::from("v1")),
        (
            Mp::from("min_engine_version"),
            Mp::from(env!("CARGO_PKG_VERSION")),
        ),
        (
            Mp::from("defaults"),
            Mp::Map(vec![
                (Mp::from("criticality"), Mp::from("normal")),
                (Mp::from("sensitivity"), Mp::from("normal")),
            ]),
        ),
        (Mp::from("rules"), Mp::Array(Vec::new())),
        (
            Mp::from("actor_ceilings"),
            Mp::Array(
                // `first_party` carries the envelope-less supersede/retract
                // lifecycle Puts; `human` carries the owner-authored heads
                // the supersession tests seed.
                ["agent", "human", "first_party"]
                    .into_iter()
                    .map(|actor_class| {
                        Mp::Map(vec![
                            (Mp::from("actor_class"), Mp::from(actor_class)),
                            (Mp::from("ceiling"), Mp::from("auto")),
                        ])
                    })
                    .collect(),
            ),
        ),
        (
            Mp::from("source_trust"),
            Mp::Map(
                [
                    ClaimSource::UserStated,
                    ClaimSource::Observed,
                    ClaimSource::Inferred,
                    ClaimSource::Imported,
                    ClaimSource::ToolOutput,
                    ClaimSource::Generated,
                ]
                .into_iter()
                .map(|source| (Mp::from(source.as_str()), source_row()))
                .collect(),
            ),
        ),
        (
            Mp::from("signature"),
            Mp::Map(vec![
                (Mp::from("alg"), Mp::from("ed25519")),
                (Mp::from("key_id"), Mp::from("promotion-test")),
                (Mp::from("sig"), Mp::from("promotion-test-signature")),
            ]),
        ),
    ]);
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &manifest).expect("encode the policy manifest");
    out
}

/// Reads the `refs` list out of a landed claim's consolidation evidence
/// envelope (ONE-1710 replaced the bare ref array with the typed envelope).
fn evidence_refs(body: &crate::claim::ClaimBody) -> Vec<EntityId> {
    consolidation_evidence(body).refs
}

fn consolidation_evidence(
    body: &crate::claim::ClaimBody,
) -> crate::dreamer_consolidation::ConsolidationEvidenceEnvelope {
    let Some(Mp::Map(evidence)) = &body.evidence else {
        panic!("expected the envelope evidence map");
    };
    let candidate_evidence = evidence
        .iter()
        .find(|(key, _)| key.as_str() == Some("candidate_evidence"))
        .map(|(_, value)| value)
        .expect("candidate_evidence entry");
    crate::dreamer_consolidation::decode_consolidation_evidence(candidate_evidence)
        .expect("evidence envelope decodes")
        .expect("consolidation claims carry the typed evidence envelope")
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
        provenance_chain: Vec::new(),
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
fn promotion_lands_auto_with_the_computed_source_through_gate() -> Result<()> {
    let (_dir, vault) = open_auto_vault();
    let fixture = fixture(&vault)?;
    let promoted = candidate(&fixture, "profile.name", "Oleksii", vec![fixture.turn]);
    let claim_id = promoted.claim_id;

    let outcome = promote_consolidated_claims(&vault, &fixture.run, vec![promoted])?;
    assert_eq!(outcome.landed, vec![claim_id], "Auto lane");
    assert!(
        outcome.pended.is_empty(),
        "ONE-1710: consolidation mints no approval-queue entry"
    );
    assert!(outcome.rejected.is_empty());

    let body = vault.get_claim(&claim_id)?.expect("landed claim");
    // Source is COMPUTED from the evidence meet, not hardcoded: this
    // candidate's meet is Generated, so Generated is the truthful stamp.
    assert_eq!(body.source, Some(ClaimSource::Generated));
    assert_eq!(body.approval, ClaimApprovalStatus::Auto);
    assert_eq!(
        claim_evidence_taint(&body),
        Some(ClaimSource::Generated),
        "every consolidation claim carries the engine-owned taint stamp"
    );

    // Envelope-stamped evidence map: actor/class/provenance keys plus the
    // writer-supplied candidate_evidence carrying the typed envelope.
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
    let envelope = consolidation_evidence(&body);
    assert_eq!(
        envelope.refs,
        vec![fixture.turn],
        "the surviving turn ref is stamped"
    );
    assert_eq!(envelope.source_meet, ClaimSource::Generated);
    assert!(
        envelope.chain.is_empty(),
        "no external lineage on this path"
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
        GateOutcome::Allow.as_str(),
        "a permitted vault grants the Auto request outright"
    );
    assert!(
        vault.store.pending_gate_consents(1_000)?.is_empty(),
        "no pending consent record anywhere on the peer/consolidation path"
    );
    Ok(())
}

#[test]
fn promotion_rejects_rather_than_pends_without_an_auto_permit() -> Result<()> {
    // No policy manifest at all: the gate cannot grant Auto. ONE-1710 turns
    // that into a per-candidate REJECTION with nothing committed — never a
    // Proposed claim plus a pending consent row for an owner to work off.
    let (_dir, vault) = open_vault();
    let fixture = fixture(&vault)?;
    let promoted = candidate(&fixture, "profile.name", "Oleksii", vec![fixture.turn]);
    let claim_id = promoted.claim_id;

    let outcome = promote_consolidated_claims(&vault, &fixture.run, vec![promoted])?;
    assert!(outcome.landed.is_empty());
    assert!(outcome.pended.is_empty(), "no approval queue, ever");
    assert_eq!(outcome.rejected.len(), 1);
    assert_eq!(outcome.rejected[0].0, claim_id);

    assert!(
        vault.get_claim(&claim_id)?.is_none(),
        "the refused write rolled back rather than landing Proposed"
    );
    assert!(
        vault.store.pending_gate_consents(1_000)?.is_empty(),
        "a refused consolidation write mints no pending consent record"
    );
    Ok(())
}

#[test]
fn promotion_cannot_supersede_user_stated() -> Result<()> {
    let (_dir, vault) = open_auto_vault();
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
    assert_eq!(outcome.landed, vec![clean_id]);
    assert!(outcome.pended.is_empty());
    Ok(())
}

#[test]
fn per_op_gating_no_bulk() -> Result<()> {
    let (_dir, vault) = open_auto_vault();
    let fixture = fixture(&vault)?;
    let candidates = vec![
        candidate(&fixture, "profile.name", "Oleksii", vec![fixture.turn]),
        candidate(&fixture, "profile.tone", "warm", vec![fixture.turn]),
        candidate(&fixture, "profile.lives_in", "Tokyo", vec![fixture.turn]),
    ];

    let decisions_before = gate_decision_count(&vault);
    let outcome = promote_consolidated_claims(&vault, &fixture.run, candidates)?;
    assert_eq!(outcome.landed.len(), 3);
    assert!(outcome.pended.is_empty());

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
fn tainted_meet_stamps_scope_and_blocks_consolidation() -> Result<()> {
    // ONE-1710 moved the taint's teeth off the APPROVAL axis (there is no
    // Proposed lane any more) and onto the taint/consolidation-block axis:
    // the claim lands, truthfully sourced `tool_output`, and is barred from
    // laundering itself back into consolidation.
    let (_dir, vault) = open_auto_vault();
    let fixture = fixture(&vault)?;
    let mut tainted = candidate(&fixture, "profile.employer", "ACME", vec![fixture.turn]);
    tainted.evidence_meet = ClaimSource::ToolOutput;
    let claim_id = tainted.claim_id;

    let outcome = promote_consolidated_claims(&vault, &fixture.run, vec![tainted])?;
    assert_eq!(outcome.landed, vec![claim_id], "storage is never gated");
    assert!(outcome.pended.is_empty());

    let body = vault.get_claim(&claim_id)?.expect("landed claim");
    assert_eq!(body.approval, ClaimApprovalStatus::Auto);
    assert_eq!(
        body.source,
        Some(ClaimSource::ToolOutput),
        "tool-output lineage is stamped as tool_output, never generated"
    );
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
    let (_dir, vault) = open_auto_vault();
    let fixture = fixture(&vault)?;

    // A tainted head: promoted earlier with a ToolOutput meet.
    let mut head = candidate(&fixture, "profile.employer", "ACME", vec![fixture.turn]);
    head.evidence_meet = ClaimSource::ToolOutput;
    let head_id = head.claim_id;
    let outcome = promote_consolidated_claims(&vault, &fixture.run, vec![head])?;
    assert_eq!(outcome.landed, vec![head_id]);

    // A CLEAN candidate (meet = Generated) supersedes the tainted head:
    // the old head's taint folds into the effective meet BEFORE stamping —
    // no laundering — so the SOURCE the new head stores is bounded by the
    // old head's tool-output lineage, not the candidate's own Generated.
    let mut clean = candidate(
        &fixture,
        "profile.employer",
        "ACME Corp",
        vec![fixture.turn],
    );
    clean.supersedes = Some(head_id);
    let clean_id = clean.claim_id;
    let outcome = promote_consolidated_claims(&vault, &fixture.run, vec![clean])?;
    assert_eq!(outcome.landed, vec![clean_id]);
    assert!(outcome.pended.is_empty());
    assert!(outcome.rejected.is_empty());

    let new_head = vault.get_claim(&clean_id)?.expect("new head");
    assert_eq!(
        claim_evidence_taint(&new_head),
        Some(ClaimSource::ToolOutput),
        "the folded taint rides the new head"
    );
    assert_eq!(
        new_head.source,
        Some(ClaimSource::ToolOutput),
        "an otherwise-Generated candidate stays source-bounded by the head it supersedes"
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
    let (_dir, vault) = open_auto_vault();
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
    assert_eq!(outcome.landed, vec![citing_id, baseline_id]);

    let citing_body = vault.get_claim(&citing_id)?.expect("citing claim");
    assert_eq!(
        evidence_refs(&citing_body),
        vec![fixture.turn],
        "the Generated claim ref was dropped; refs are exactly the survivors"
    );

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
    let (_dir, vault) = open_auto_vault();
    let fixture = fixture(&vault)?;

    // Drive the verification leg directly: a claim that "landed" but is
    // gone at re-read time is a rejection (caller must fail the attempt).
    let promoted = candidate(&fixture, "profile.name", "Oleksii", vec![fixture.turn]);
    let claim_id = promoted.claim_id;
    promote_consolidated_claims(&vault, &fixture.run, vec![promoted])?;
    assert!(vault.get_claim(&claim_id)?.is_some());

    vault.delete_entity(&claim_id)?;
    let verdict = verify_landed(&vault, &claim_id, "profile.name", ClaimSource::Generated);
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
    assert!(
        verify_landed(
            &vault,
            &survivor_id,
            "profile.other",
            ClaimSource::Generated
        )
        .is_err()
    );

    // ONE-1710: verification compares against the COMPUTED source, so the
    // old hardcoded `Generated` expectation is itself a mismatch for a
    // tool-output-derived head.
    let mut tainted = candidate(&fixture, "profile.employer", "ACME", vec![fixture.turn]);
    tainted.evidence_meet = ClaimSource::ToolOutput;
    let tainted_id = tainted.claim_id;
    promote_consolidated_claims(&vault, &fixture.run, vec![tainted])?;
    assert!(
        verify_landed(
            &vault,
            &tainted_id,
            "profile.employer",
            ClaimSource::Generated
        )
        .is_err(),
        "the hardcoded Generated expectation no longer verifies a tool_output head"
    );
    assert_eq!(
        verify_landed(
            &vault,
            &tainted_id,
            "profile.employer",
            ClaimSource::ToolOutput
        ),
        Ok(ClaimApprovalStatus::Auto),
        "the computed source is what verification compares"
    );
    Ok(())
}

#[cfg(feature = "sync")]
#[test]
fn replay_path_still_skips_source_trust_gate() -> Result<()> {
    let (_dir, vault) = open_auto_vault();
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

    let (_dir, vault) = open_auto_vault();
    let promo = fixture(&vault)?;
    let promoted = candidate(&promo, "profile.name", "Oleksii", vec![promo.turn]);
    let claim_id = promoted.claim_id;

    let mut sink = PromotionWriterSink::new(&vault, promo.run);
    sink.accept(vec![promoted])?;
    assert_eq!(sink.outcome.landed, vec![claim_id]);
    assert!(sink.outcome.pended.is_empty());
    assert!(sink.outcome.rejected.is_empty());
    assert!(vault.get_claim(&claim_id)?.is_some());
    Ok(())
}

/// ONE-1710 §3 unit floor: the meet is computed from evidence, and the
/// classification of a peer-answer TURN is `ToolOutput`.
#[test]
fn evidence_chain_source_classifies_the_peer_answer_turn() -> Result<()> {
    use crate::dreamer_consolidation::{
        ConsolidationProvenanceHop, ConsolidationProvenanceHopKind, evidence_chain_source,
    };

    let (_dir, vault) = open_auto_vault();
    let fixture = fixture(&vault)?;
    let chain = vec![ConsolidationProvenanceHop {
        kind: ConsolidationProvenanceHopKind::AnswerTurn,
        entity_ref: fixture.turn,
        actor_ref: None,
    }];

    // Peer answer alone → ToolOutput.
    assert_eq!(
        evidence_chain_source(&vault, &chain, &[fixture.turn])?,
        ClaimSource::ToolOutput
    );

    // ToolOutput + a plain (Generated-floor) turn → still ToolOutput.
    let plain_turn = EntityId::now();
    vault.put_entity(&plain_turn, ENTITY_TYPE_TURN, occurred(5), 5, b"plain")?;
    assert_eq!(
        evidence_chain_source(&vault, &chain, &[fixture.turn, plain_turn])?,
        ClaimSource::ToolOutput
    );

    // ToolOutput + an unresolvable ref fails closed at Imported, the bottom.
    assert_eq!(
        evidence_chain_source(&vault, &chain, &[fixture.turn, EntityId::now()])?,
        ClaimSource::Imported
    );

    // No chain and no external reads → the Dreamer's own Generated floor.
    assert_eq!(
        evidence_chain_source(&vault, &[], &[plain_turn])?,
        ClaimSource::Generated
    );
    Ok(())
}

/// ONE-1710 §2/§3: a peer-derived candidate keeps its typed chain and its
/// confidence through promotion, and the stored refs are the survivors only.
#[test]
fn peer_candidate_stores_typed_chain_and_preserves_confidence() -> Result<()> {
    use crate::dreamer_consolidation::{
        ConsolidationProvenanceHop, ConsolidationProvenanceHopKind,
    };

    let (_dir, vault) = open_auto_vault();
    let fixture = fixture(&vault)?;
    let consult_task = EntityId::now();
    vault.put_entity(
        &consult_task,
        crate::registry::ENTITY_TYPE_TASK,
        occurred(4),
        4,
        &crate::habit::task_body_for_test(crate::habit::TaskRole::Task),
    )?;

    let mut peer = candidate(
        &fixture,
        "profile.employer",
        "ACME",
        // The second ref never resolves: it must be dropped from the stored
        // envelope rather than recorded as evidence.
        vec![fixture.turn, EntityId::now()],
    );
    peer.evidence_meet = ClaimSource::ToolOutput;
    peer.provenance_chain = vec![
        ConsolidationProvenanceHop {
            kind: ConsolidationProvenanceHopKind::AnswerTurn,
            entity_ref: fixture.turn,
            actor_ref: None,
        },
        ConsolidationProvenanceHop {
            kind: ConsolidationProvenanceHopKind::ConsultTask,
            entity_ref: consult_task,
            actor_ref: None,
        },
    ];
    let claim_id = peer.claim_id;

    let outcome = promote_consolidated_claims(&vault, &fixture.run, vec![peer])?;
    assert_eq!(outcome.landed, vec![claim_id]);
    assert!(outcome.pended.is_empty());

    let body = vault.get_claim(&claim_id)?.expect("landed peer claim");
    assert_eq!(body.source, Some(ClaimSource::ToolOutput));
    assert!(
        (body.confidence - 0.7).abs() < f32::EPSILON,
        "confidence is copied unchanged"
    );

    let envelope = consolidation_evidence(&body);
    assert_eq!(envelope.refs, vec![fixture.turn], "survivors only");
    assert_eq!(envelope.source_meet, ClaimSource::ToolOutput);
    assert_eq!(envelope.chain.len(), 2);
    assert_eq!(
        envelope
            .chain
            .iter()
            .filter(|hop| hop.kind == ConsolidationProvenanceHopKind::AnswerTurn)
            .count(),
        1
    );
    assert_eq!(
        envelope
            .chain
            .iter()
            .filter(|hop| hop.kind == ConsolidationProvenanceHopKind::ConsultTask)
            .count(),
        1
    );
    assert_eq!(envelope.chain[0].entity_ref, fixture.turn);
    assert_eq!(envelope.chain[1].entity_ref, consult_task);
    Ok(())
}

/// ONE-1710 §1: the ledger is the record. Storage and promotion are
/// deliberately SEPARATE transactions, so a candidate the writer refuses can
/// never roll back or hide the answer TURN it was derived from.
#[test]
fn a_refused_candidate_never_unstores_the_answer_turn() -> Result<()> {
    let (_dir, vault) = open_auto_vault();
    let fixture = fixture(&vault)?;
    let answer_turn = fixture.turn;

    // Malformed by construction: `edge.*` is the reserved namespace no
    // consolidation write may author, so the claim write fails.
    let malformed = candidate(&fixture, "edge.forged", "ACME", vec![answer_turn]);
    let claim_id = malformed.claim_id;

    let outcome = promote_consolidated_claims(&vault, &fixture.run, vec![malformed])?;
    assert!(outcome.landed.is_empty());
    assert!(
        outcome.pended.is_empty(),
        "a refusal is a rejection, never an approval-queue row"
    );
    assert_eq!(outcome.rejected.len(), 1);
    assert_eq!(outcome.rejected[0].0, claim_id);
    assert!(
        vault.get_claim(&claim_id)?.is_none(),
        "the refused claim rolled back whole"
    );

    // The already-landed answer is untouched by the failed consolidation.
    assert!(
        vault.get(&answer_turn)?.is_some(),
        "a consolidation failure never rolls back or hides the stored answer"
    );
    Ok(())
}

/// True only for the central lineage guard's own refusal, so a coincidental
/// policy/shape rejection cannot be mistaken for coverage.
fn is_lineage_rejection(error: &Error) -> bool {
    matches!(
        error,
        Error::InvalidClaimBody("claim source widens beyond evidence lineage")
    )
}

/// ONE-1710 §5 coverage: the guard is not a door-local check. EVERY claim
/// write decodes through `validate_claim_body_and_decode`, so a widening
/// restamp is refused whichever surface carries it — and this vault's policy
/// GRANTS these writes, so the refusal can only be the guard itself.
#[test]
fn the_lineage_guard_is_reached_from_every_claim_write_door() -> Result<()> {
    let (_dir, vault) = open_auto_vault();
    let fixture = fixture(&vault)?;
    let when = occurred(9_000);

    let lineage_scope = |taint: ClaimSource| {
        Mp::Map(vec![(
            Mp::from(CLAIM_SCOPE_EVIDENCE_TAINT_KEY),
            Mp::from(taint.as_str()),
        )])
    };
    let forged_candidate = |taint: ClaimSource| {
        ClaimCandidate::new(
            "profile.name",
            ClaimSubject::Entity(fixture.subject),
            Mp::from("forged"),
            0.7,
        )
        .with_scope(lineage_scope(taint))
    };
    let door_envelope = |source: ClaimSource| {
        WriteEnvelope::new(
            fixture.run.agent_actor,
            source,
            WriteProvenance::new(Mp::from("lineage-coverage")).expect("provenance"),
            ClaimApprovalStatus::Auto,
        )
    };

    // 1. The public `Vault::put_claim` door, with a hand-built body.
    let put_id = EntityId::now();
    let mut body = crate::claim::ClaimBody::new(
        "profile.name",
        ClaimSubject::Entity(fixture.subject),
        Mp::from("forged"),
        0.7,
        ClaimApprovalStatus::Proposed,
        crate::claim::ClaimLifecycleStatus::Active,
    );
    body.source = Some(ClaimSource::Generated);
    body.scope = Some(lineage_scope(ClaimSource::ToolOutput));
    let error = vault
        .put_claim(&put_id, &body, when, 9_000)
        .expect_err("the public door refuses a widening restamp");
    assert!(is_lineage_rejection(&error), "{error}");
    assert!(vault.get_claim(&put_id)?.is_none());

    // 2. The first-party code-mode surface: the host binds `generated`, so a
    // tool-output lineage stamped beneath it is the canonical forgery.
    let code_mode_id = EntityId::now();
    let error = vault
        .batch()
        .claim_candidate(
            &code_mode_id,
            forged_candidate(ClaimSource::ToolOutput),
            &door_envelope(ClaimSource::Generated),
            when,
            9_000,
        )
        .commit()
        .expect_err("the code-mode door refuses it too");
    assert!(is_lineage_rejection(&error), "{error}");
    assert!(vault.get_claim(&code_mode_id)?.is_none());

    // 3. The MCP/tool-output surface: the host binds `tool_output`, which is
    // still no licence to outrank an `imported` lineage.
    let mcp_id = EntityId::now();
    let error = vault
        .batch()
        .claim_candidate(
            &mcp_id,
            forged_candidate(ClaimSource::Imported),
            &door_envelope(ClaimSource::ToolOutput),
            when,
            9_000,
        )
        .commit()
        .expect_err("host-bound tool_output cannot outrank imported evidence");
    assert!(is_lineage_rejection(&error), "{error}");
    assert!(vault.get_claim(&mcp_id)?.is_none());

    // 4. Sync replay admits through the SAME chokepoint with the reserved
    // door open (`sync::selector`). The guard is keyed on the PREDICATE, not
    // on that flag, so an ordinary predicate is refused there too.
    let error =
        crate::claim::validate_claim_body_bytes(&crate::claim::encode_claim_body(&body)?, true)
            .expect_err("sync replay decodes through the same guard");
    assert!(is_lineage_rejection(&error), "{error}");

    // 5. Dreamer promotion cannot reach the guard at all: it COMPUTES the
    // source from evidence, so the stamp it writes never outranks the taint
    // it stamps beside it.
    let promoted = candidate(&fixture, "profile.name", "Oleksii", vec![fixture.turn]);
    let promoted_id = promoted.claim_id;
    promote_consolidated_claims(&vault, &fixture.run, vec![promoted])?;
    let landed = vault.get_claim(&promoted_id)?.expect("landed claim");
    assert!(!claim_source_widens_beyond(
        landed.source.expect("a consolidation claim is sourced"),
        claim_evidence_taint(&landed).expect("and taint-stamped beside it"),
    ));
    Ok(())
}

/// GATE-12: the promotion writer is not the validator — a malformed
/// candidate is refused at the write chokepoint it already goes through, so
/// promotion inherits the floor rather than re-implementing it.
#[test]
fn validation_at_chokepoint() -> Result<()> {
    let (_dir, vault) = open_auto_vault();
    let fixture = fixture(&vault)?;
    // Evidence resolves and the policy grants Auto, so the ONLY thing that
    // can refuse this candidate is pre-commit validation of its value.
    let promoted = candidate(
        &fixture,
        "profile.name",
        "I will remember this next pass",
        vec![fixture.turn],
    );
    let claim_id = promoted.claim_id;

    let outcome = promote_consolidated_claims(&vault, &fixture.run, vec![promoted])?;

    assert!(outcome.landed.is_empty(), "no degenerate claim may land");
    assert!(
        outcome.pended.is_empty(),
        "a validity failure is never an owner-review row"
    );
    let (rejected_id, reason) = outcome
        .rejected
        .first()
        .expect("the malformed candidate is reported as rejected");
    assert_eq!(*rejected_id, claim_id);
    assert!(
        reason.contains("gated write rejected"),
        "the rejection must come from the gated write, got {reason}"
    );
    assert!(
        reason.contains("gate.deny.dreamer_precommit.degenerate_output"),
        "the pinned pre-commit code must survive into the reason, got {reason}"
    );

    assert!(
        vault.get_claim(&claim_id)?.is_none(),
        "nothing lands in the vault"
    );
    assert!(
        vault.get_raw(&fixture.turn)?.is_some(),
        "the already-stored answer TURN never shared the rolled-back transaction"
    );
    assert!(
        vault.pending_gate_consents(10)?.is_empty(),
        "no pending-consent row is minted behind the Dreamer's back"
    );
    Ok(())
}

/// GATE-12 authorship is the WRITE's provenance, not the candidate's
/// evidence meet.
///
/// The promotion envelope's source is the COMPUTED meet, so a truthful
/// `ToolOutput` lineage is the ordinary case — and it must not disable the
/// deny-first floor. This is `validation_at_chokepoint` with the meet as the
/// single changed axis.
#[test]
fn tool_output_meet_degenerate_candidate_is_denied_at_the_door() -> Result<()> {
    let (_dir, vault) = open_auto_vault();
    let fixture = fixture(&vault)?;
    // Resolving evidence and an Auto-granting policy, so the degenerate
    // VALUE is the only thing that can refuse this candidate.
    let mut promoted = candidate(
        &fixture,
        "profile.name",
        "I will remember this next pass",
        vec![fixture.turn],
    );
    promoted.evidence_meet = ClaimSource::ToolOutput;
    let claim_id = promoted.claim_id;

    let outcome = promote_consolidated_claims(&vault, &fixture.run, vec![promoted])?;

    assert!(
        outcome.landed.is_empty(),
        "a tool-output meet is not an exemption"
    );
    assert!(
        outcome.pended.is_empty(),
        "a validity failure is never an owner-review row"
    );
    let (rejected_id, reason) = outcome
        .rejected
        .first()
        .expect("the degenerate candidate is reported as rejected");
    assert_eq!(*rejected_id, claim_id);
    assert!(
        reason.contains("gated write rejected"),
        "the rejection must come from the gated write, got {reason}"
    );
    assert!(
        reason.contains("gate.deny.dreamer_precommit.degenerate_output"),
        "the pinned pre-commit code must survive into the reason, got {reason}"
    );

    assert!(
        vault.get_claim(&claim_id)?.is_none(),
        "nothing lands in the vault"
    );
    assert!(
        vault.get_raw(&fixture.turn)?.is_some(),
        "the already-stored answer TURN never shared the rolled-back transaction"
    );
    assert!(
        vault.pending_gate_consents(10)?.is_empty(),
        "no pending-consent row is minted behind the Dreamer's back"
    );
    Ok(())
}

/// `auto_permitting_manifest` with its `signature` entry removed, and
/// nothing else changed.
fn unsigned_auto_permitting_manifest() -> Vec<u8> {
    let signed = auto_permitting_manifest();
    let mut manifest =
        rmpv::decode::read_value(&mut &signed[..]).expect("decode the signed manifest");
    let Mp::Map(entries) = &mut manifest else {
        panic!("expected the manifest map");
    };
    entries.retain(|(key, _)| key.as_str() != Some("signature"));
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &manifest).expect("encode the unsigned manifest");
    out
}

fn open_unsigned_auto_vault() -> (tempfile::TempDir, Vault) {
    let (dir, vault) = open_vault();
    let id = crate::gate::default_policy_manifest_id().expect("default policy manifest id");
    crate::test_util::put_policy_manifest_bytes(&vault, id, &unsigned_auto_permitting_manifest())
        .expect("seed the unsigned auto-permitting policy manifest");
    (dir, vault)
}

/// INTENDED fail-closed tightening, pinned so it cannot be undone quietly.
///
/// `dreamer_auto_grant_requires_manifest_signature` keys on the detected
/// Dreamer run handle. While authorship was coupled to `Generated`, a
/// `ToolOutput`-meet promotion carried NO run handle, so the signature
/// requirement was skipped on exactly the writes it exists to cover and the
/// claim landed Auto off an unsigned manifest. Source-agnostic detection
/// closes that: the same candidate now takes the existing
/// `gate.pending.policy_manifest_authority` path, which promotion reports as
/// a gated-write rejection because it requests Auto.
///
/// The manifest is NOT signed to make this pass, the meet is NOT forced to
/// `Generated`, and the signature rule is untouched — the control is
/// `tainted_meet_stamps_scope_and_blocks_consolidation`, where the same
/// tool-output shape still lands Auto on the SIGNED manifest.
#[test]
fn tool_output_meet_promotion_no_longer_lands_auto_on_an_unsigned_manifest() -> Result<()> {
    let (_dir, vault) = open_unsigned_auto_vault();
    let fixture = fixture(&vault)?;
    // Valid, non-degenerate, resolving evidence: nothing here fails GATE-12
    // validity, so the refusal can only be the manifest-authority rule.
    let mut promoted = candidate(&fixture, "profile.employer", "ACME", vec![fixture.turn]);
    promoted.evidence_meet = ClaimSource::ToolOutput;
    let claim_id = promoted.claim_id;

    let outcome = promote_consolidated_claims(&vault, &fixture.run, vec![promoted])?;

    assert!(
        outcome.landed.is_empty(),
        "an unsigned manifest cannot grant the Dreamer's Auto request"
    );
    assert!(outcome.pended.is_empty(), "no approval queue, ever");
    let (rejected_id, reason) = outcome
        .rejected
        .first()
        .expect("the unsigned-manifest candidate is reported as rejected");
    assert_eq!(*rejected_id, claim_id);
    assert!(
        reason.contains("gated write rejected"),
        "the rejection must come from the gated write, got {reason}"
    );
    assert!(
        reason.contains("gate.pending.policy_manifest_authority"),
        "the existing signature rule is what refuses this, got {reason}"
    );
    assert!(
        !reason.contains("gate.deny.dreamer_precommit."),
        "the candidate itself is valid; only the manifest authority is missing, got {reason}"
    );

    assert!(
        vault.get_claim(&claim_id)?.is_none(),
        "the refused write rolled back rather than landing Auto"
    );
    assert!(
        vault.pending_gate_consents(10)?.is_empty(),
        "an Auto request is refused outright, never turned into a consent row"
    );
    Ok(())
}
