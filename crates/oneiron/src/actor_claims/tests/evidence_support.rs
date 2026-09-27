//! Read-time support on a replica where erasure precedes a late claim.
use super::*;
use crate::authority::HostSlipIssuer;
use crate::claim::ScopedReadActorKey;
use crate::dreamer_consolidation::{ConsolidationEvidenceEnvelope, encode_consolidation_evidence};
use crate::registry::ENTITY_TYPE_CLAIM;

fn replicate_with_text(vault: &Vault, body: &ClaimBody, text: &str) -> Result<EntityId> {
    let id = EntityId::now();
    vault
        .batch()
        .put_replicated(
            &id,
            ENTITY_TYPE_CLAIM,
            t(50),
            50,
            &crate::claim::encode_claim_body(body)?,
        )
        .text(&id, &[("body", text)])
        .commit()?;
    Ok(id)
}

#[test]
fn erased_evidence_arriving_after_tombstone_is_suppressed_but_live_support_survives() -> Result<()>
{
    let (_dir, vault) = temp_vault();
    let actor = put_actor(&vault)?;
    let skill = put_skill(&vault, "sk06.erasure.fit")?;
    let session = witnessed_chat_session(&vault, 2, 30)?;
    let turns = session_turns(
        &vault,
        SittingWindow {
            started_at: 30,
            ended_at: 130,
        },
    )?;
    let evidence =
        ActorClaimEvidence::chat(session, turns.iter().map(|turn| turn.turn).collect(), 30)?;
    let ActorClaimLane::Chat { session, turns } = &evidence.lane else {
        unreachable!();
    };
    assert!(turns.len() >= 1);
    let erased = turns[0];
    let live = turns[1];
    let single_evidence = ActorClaimEvidence::chat(*session, vec![erased], 32)?;
    let mixed_evidence = ActorClaimEvidence::chat(*session, vec![erased, live], 33)?;
    let single = write_actor_claim(
        &vault,
        ActorClaimRow::Lesson {
            actor,
            text: "erasedneedle".into(),
        },
        &single_evidence,
    )?;
    let mixed = write_actor_claim(
        &vault,
        ActorClaimRow::Lesson {
            actor,
            text: "erasedneedleother".into(),
        },
        &mixed_evidence,
    )?;
    let fit = write_actor_claim(
        &vault,
        ActorClaimRow::SkillFit {
            actor,
            skill,
            fit: 0.8,
        },
        &single_evidence,
    )?;
    assert_eq!(skill_fit_for(&vault, &actor, &skill)?, Some(0.8));
    let issuer = HostSlipIssuer::from_secret(b"support read fixture")?;
    vault.ensure_host_root_slip(&issuer)?;
    let proof = vault.verified_host_root_slip(&issuer)?;
    let read = vault.scoped_read(ScopedReadActorKey::from_verified_slip(&proof).unwrap());
    assert!(read.get(&single)?.is_some());
    assert!(read.get(&mixed)?.is_some());

    // The replica already knows the erasure when its claim write arrives.
    // Mark the archived deletion in the same metadata family as replayed
    // tombstones; no body rewrite or author-side deletion sweep is involved.
    vault.with_write_txn(|txn| {
        vault.store.sync_state.put(
            txn,
            &crate::deletion::archive_tombstone_key(&erased),
            b"erased",
        )?;
        Ok(())
    })?;
    let late_single =
        replicate_with_text(&vault, &vault.get_claim(&single)?.unwrap(), "erasedneedle")?;
    let late_mixed = replicate_with_text(
        &vault,
        &vault.get_claim(&mixed)?.unwrap(),
        "erasedneedleother",
    )?;
    // The original rows and late rows remain in the history door.
    assert!(vault.get_claim(&late_single)?.is_some());
    assert!(vault.get_claim(&late_mixed)?.is_some());
    assert!(read.get(&late_single)?.is_none());
    assert!(read.get(&late_mixed)?.is_some());
    assert_eq!(skill_fit_for(&vault, &actor, &skill)?, None);
    assert!(vault.get_claim(&fit)?.is_some());

    // Typed consolidation shares the same predicate; it does not rely on an
    // actor-specific lane marker. A bare claim stays readable.
    let make_consolidated = |refs: Vec<EntityId>| {
        let mut body = ClaimBody::new(
            "test.support",
            ClaimSubject::Entity(actor),
            Value::from("belief"),
            1.0,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        );
        body.evidence = Some(encode_consolidation_evidence(
            &ConsolidationEvidenceEnvelope {
                refs,
                chain: vec![],
                source_meet: ClaimSource::Generated,
            },
        ));
        body
    };
    let unsupported = replicate_with_text(
        &vault,
        &make_consolidated(vec![erased]),
        "othererasedneedle",
    )?;
    let corroborated = replicate_with_text(
        &vault,
        &make_consolidated(vec![erased, live]),
        "othererasedneedlelive",
    )?;
    assert!(vault.get_claim(&unsupported)?.is_some());
    assert!(read.get(&unsupported)?.is_none());
    assert!(read.get(&corroborated)?.is_some());

    let hits = vault.query().search_text("erasedneedle", 10).run()?;
    assert!(
        !hits
            .iter()
            .any(|hit| hit.id == late_single || hit.id == unsupported)
    );
    assert!(hits.iter().any(|hit| hit.id == late_mixed));
    let hits = vault.query().search_text("othererasedneedle", 10).run()?;
    assert!(!hits.iter().any(|hit| hit.id == unsupported));
    assert!(hits.iter().any(|hit| hit.id == corroborated));
    Ok(())
}
