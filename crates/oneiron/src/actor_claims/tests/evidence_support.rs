//! Read-time support on a replica where erasure precedes a late claim.
use super::*;
use crate::authority::HostSlipIssuer;
use crate::claim::{PointRead, ScopedReadActorKey};
use crate::dreamer_consolidation::{ConsolidationEvidenceEnvelope, encode_consolidation_evidence};
use crate::edge::EdgeKind;
use crate::registry::ENTITY_TYPE_CLAIM;

fn replicate_with_text(vault: &Vault, body: &ClaimBody, text: &str) -> Result<EntityId> {
    let id = EntityId::now();
    let mut batch = vault
        .batch()
        .put_replicated(
            &id,
            ENTITY_TYPE_CLAIM,
            t(50),
            50,
            &crate::claim::encode_claim_body(body)?,
        )
        .text(&id, &[("body", text)]);
    if let ClaimSubject::Entity(subject) = body.subject {
        batch = batch.edge(&id, EdgeKind::ClaimOf, &subject, 1.0);
    }
    batch.commit()?;
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
    assert!(!turns.is_empty());
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
    assert!(
        read.read(&[PointRead::id(single)], None)?
            .single()
            .value
            .is_some()
    );
    assert!(
        read.read(&[PointRead::id(mixed)], None)?
            .single()
            .value
            .is_some()
    );

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
    assert!(
        read.read(&[PointRead::id(late_single)], None)?
            .single()
            .value
            .is_none()
    );
    assert!(
        read.read(&[PointRead::id(late_mixed)], None)?
            .single()
            .value
            .is_some()
    );
    // Memory reads are scoped to the facade's actor; the owner lane reads
    // every record the host holds, so only evidence support decides here.
    let facade = vault.memory(
        crate::vault::embedded_owner_actor_id()?,
        EdgeActorClass::Human,
    );
    assert!(
        facade
            .get_entity(&late_single.to_hex())
            .expect("read claim")
            .is_none()
    );
    assert!(
        facade
            .get_entity(&late_mixed.to_hex())
            .expect("read claim")
            .is_some()
    );
    let listed = facade
        .claim_list(&crate::memory::ClaimListFilter {
            subject_ref: Some(actor.to_hex()),
            predicate: None,
            lifecycle: Some("active".into()),
            limit: 100,
        })
        .expect("list claims");
    assert!(
        listed
            .iter()
            .all(|view| view.claim_ref != late_single.to_hex())
    );
    assert!(
        listed
            .iter()
            .any(|view| view.claim_ref == late_mixed.to_hex())
    );
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
        )
        .unwrap();
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
    assert!(
        read.read(&[PointRead::id(unsupported)], None)?
            .single()
            .value
            .is_none()
    );
    assert!(
        read.read(&[PointRead::id(corroborated)], None)?
            .single()
            .value
            .is_some()
    );

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

#[test]
fn receiving_room_replica_hides_claim_arriving_after_real_tombstone() -> Result<()> {
    let (_source_dir, source) = temp_vault();
    let person = put_actor(&source)?;
    let byline = crate::WriteActor::new(person, EdgeActorClass::Human);
    crate::conversation_dag::fixtures::grant(&source, byline, true);
    let room = EntityId::now();
    source.create_conversation(
        room,
        &crate::conversation::ConversationBody {
            member_ids: vec![person],
            ..Default::default()
        },
        byline,
        1,
    )?;
    let turn = source
        .append_dag_record(&crate::conversation_dag::fixtures::input(
            room, None, true, byline,
        ))?
        .id;
    let session = source.spawn_dag_sub_session(&turn, byline)?;
    let claim = write_actor_claim(
        &source,
        ActorClaimRow::Lesson {
            actor: person,
            text: "received sole evidence".into(),
        },
        &ActorClaimEvidence::chat(session, vec![turn], 25)?,
    )?;

    let (_peer_dir, peer) = temp_vault();
    for id in [person, room, turn, session] {
        let raw = source.get_raw_unsealed(&id)?.unwrap();
        let header = crate::batch::EntityMetadataHeader::parse(&raw).unwrap();
        peer.batch()
            .put_replicated(
                &id,
                header.entity_type,
                t(header.occurred_start),
                header.learned_at,
                &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
            )
            .commit()?;
    }
    peer.batch().edge_checked(&turn, &room, 1.0).commit()?;
    let request_id = *uuid::Uuid::now_v7().as_bytes();
    peer.apply_replayed_tombstone(
        &turn,
        &crate::deletion::TombstoneValueV2 {
            reason: crate::deletion::TombstoneReason::GdprDelete,
            deleted_at: 30,
            request_id,
        }
        .encode(),
    )?;
    assert!(peer.get(&turn)?.is_none());
    let late = replicate_with_text(
        &peer,
        &source.get_claim(&claim)?.unwrap(),
        "received sole evidence",
    )?;
    assert!(peer.get_claim(&late)?.is_some(), "history is retained");
    let issuer = HostSlipIssuer::from_secret(b"receiving room read")?;
    peer.ensure_host_root_slip(&issuer)?;
    let proof = peer.verified_host_root_slip(&issuer)?;
    let read = peer.scoped_read(ScopedReadActorKey::from_verified_slip(&proof).unwrap());
    assert!(
        read.read(&[PointRead::id(late)], None)?
            .single()
            .value
            .is_none()
    );
    assert!(
        !peer
            .query()
            .search_text("received sole evidence", 10)
            .run()?
            .iter()
            .any(|hit| hit.id == late)
    );
    assert!(
        peer.memory(person, EdgeActorClass::Human)
            .claim_list(&crate::memory::ClaimListFilter {
                subject_ref: Some(person.to_hex()),
                predicate: None,
                lifecycle: Some("active".into()),
                limit: 10,
            })
            .expect("list peer claims")
            .iter()
            .all(|view| view.claim_ref != late.to_hex())
    );
    Ok(())
}
