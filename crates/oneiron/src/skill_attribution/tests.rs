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
    put_skill_version(vault, id, skill_id, "1.0.0")
}

fn put_skill_version(
    vault: &Vault,
    id: EntityId,
    skill_id: &str,
    version: &str,
) -> Result<EntityId> {
    let record = SkillRecord::new(
        skill_id,
        "attribution fixture skill",
        version,
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
fn stamped_receipt(vault: &Vault, skill_id: &str, actor: EntityId) -> Result<String> {
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
    vault.bind_actor_attempt(attempt.id, &actor)?;
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
    queue.set_executor_model(
        attempt.id,
        "fixture-worker",
        leased.attempt_count,
        "fixture/model@1",
    )?;
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

// ─── Evidence grounding (ONE-1737 F2) ──────────────────────────────────

/// Every reference on an evidence row is resolved at the door. A string that
/// looks like a receipt, an actor nobody minted, a skill nobody minted, and a
/// skill the attempt never loaded are all FABRICATIONS — each one is a typed
/// refusal, and none of them reaches the evidence store.
#[test]
fn fabricated_evidence_references_are_refused_at_the_door() -> Result<()> {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let Grounded { actor, skill } = ground(&vault, 0x31, 0x32)?;
    let receipt = stamped_receipt(&vault, FIXTURE_SKILL_ID, actor)?;
    let unloaded_skill = put_skill(&vault, entity(0x33), "attribution.fixture.other")?;
    let wrong_revision = put_skill_version(&vault, entity(0x36), FIXTURE_SKILL_ID, "2.0.0")?;

    let cases = [
        evidence(
            "attempt:00000000000000000000000000000000",
            actor,
            skill,
            AttemptOutcome::Failed,
            true,
            true,
        ),
        evidence(
            &receipt,
            entity(0x34),
            skill,
            AttemptOutcome::Failed,
            true,
            true,
        ),
        evidence(
            &receipt,
            actor,
            entity(0x35),
            AttemptOutcome::Failed,
            true,
            true,
        ),
        evidence(
            &receipt,
            actor,
            unloaded_skill,
            AttemptOutcome::Failed,
            true,
            true,
        ),
        evidence(
            &receipt,
            actor,
            wrong_revision,
            AttemptOutcome::Failed,
            true,
            true,
        ),
    ];

    for fabricated in cases {
        let error = record_attribution_evidence(&vault, &fabricated)
            .expect_err("a fabricated reference is refused");
        assert!(
            matches!(error, Error::InvalidClaimBody(_)),
            "expected InvalidClaimBody, got {error:?}"
        );
    }
    assert_eq!(
        run_attribution_projector(&vault, 0)?.len(),
        0,
        "nothing fabricated reached the evidence store"
    );
    Ok(())
}

/// The 100%-by-label guard. Fixture ids are OPAQUE, so a judge that reads the
/// receipt id instead of reasoning over the routing facts learns nothing: it
/// cannot reach the honest tier's rate. With verdict-bearing ids
/// (`audit:skill_defect`, …) this judge scored a perfect 100% while judging
/// nothing at all.
#[test]
fn audit_fixture_ids_leak_no_verdict_signal() -> Result<()> {
    /// Answers purely from the receipt id — the cheating strategy the audit
    /// must not reward.
    struct ReceiptRefSniffingJudge;
    impl AttributionJudge for ReceiptRefSniffingJudge {
        fn judge(&self, evidence: &OutcomeEvidence) -> Result<Option<AttributionVerdict>> {
            Ok([
                AttributionVerdict::SkillDefect,
                AttributionVerdict::ExecutionLapse,
                AttributionVerdict::Discovery,
            ]
            .into_iter()
            .find(|verdict| evidence.receipt_ref.contains(verdict.as_str())))
        }
    }

    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let fixtures = held_out_audit_fixtures();

    // Mechanical guard: re-introducing an answer-bearing fixture id fails HERE,
    // before anyone has to notice a suspiciously perfect score.
    for fixture in &fixtures {
        for verdict in [
            AttributionVerdict::SkillDefect,
            AttributionVerdict::ExecutionLapse,
            AttributionVerdict::Discovery,
        ] {
            assert!(
                !fixture.evidence.receipt_ref.contains(verdict.as_str()),
                "fixture id {:?} leaks the answer {:?}",
                fixture.evidence.receipt_ref,
                verdict.as_str()
            );
        }
    }

    let honest = run_attribution_audit_with_judge(&vault, &fixtures, &RuleAttributionJudge, 40)?;
    let sniffer =
        run_attribution_audit_with_judge(&vault, &fixtures, &ReceiptRefSniffingJudge, 41)?;

    assert!(
        (honest.pass_rate() - 1.0).abs() < f32::EPSILON,
        "the honest tier still passes its own set"
    );
    assert!(
        sniffer.pass_rate() < honest.pass_rate(),
        "reading the label must not match reasoning over the facts: {} vs {}",
        sniffer.pass_rate(),
        honest.pass_rate()
    );
    Ok(())
}

mod resident;
mod sweep;
