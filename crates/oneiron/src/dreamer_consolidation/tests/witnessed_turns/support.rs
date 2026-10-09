//! An attachment's Supports edge follows the MESSAGE words that justify it.
//! Erasing the cited words withdraws that support from fresh graph reads, and
//! so from PPR, which skips a retracted edge. The TURN and the approved head
//! stay, and another live attachment of the same edge keeps the support. A
//! replay or a canonical recovery of an older image keeps it withdrawn, and
//! so does a public put of the edge after its removal.
use super::*;
use crate::edge::EdgeConfirmationStatus::{self, Confirmed, Retracted};
use crate::provenance::{
    EdgeProvenanceClaimBody, EdgeProvenanceWrite, EdgeRef, PREDICATE_EDGE_PROVENANCE,
    SupersessionStatus,
};

/// An approved head and the Dreamer's attachment of it to the first of a
/// two-MESSAGE witnessed TURN, landed through real consolidation.
struct Attached {
    turn: EntityId,
    head: EntityId,
    wrapper: EntityId,
    /// The MESSAGE whose words the attachment cites.
    cited: EntityId,
    /// The TURN's other MESSAGE, which the attachment does not cite.
    other: EntityId,
}

fn attached(vault: &Vault) -> Result<Attached> {
    let said = message(0, WitnessAuthor::User, SAID, true);
    let thanks = message(1, WitnessAuthor::User, "thanks", true);
    let (cited, other) = (id_of(&said), id_of(&thanks));
    let (turn, _) = witness(vault, 0x91, vec![said, thanks]);
    super::super::prior_heads::policy(vault, vault.dreamer_authority()?.entity_ref(), true)?;
    let subject = EntityId::now();
    vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred(1), 1, b"person")?;
    let head = put_head(vault, subject)?;
    let mut name = nickname(subject, turn, name_range());
    name["predicate"] = "profile.name".into();
    let outcome = land(vault, vec![name], |admitted| {
        Ok(Some(head_scope(vault, admitted, head)?.2))
    })?;
    assert_eq!(outcome.landed, vec![head], "{outcome:?}");
    let [wrapper] = claims_with(vault, PREDICATE_EDGE_PROVENANCE)?[..] else {
        panic!("one attachment")
    };
    assert_eq!(support_status(vault, turn, head)?, [Some(Confirmed); 2]);
    Ok(Attached {
        turn,
        head,
        wrapper,
        cited,
        other,
    })
}

/// A fresh graph read of the TURN -> head Supports edge from both ends: its
/// confirmation status out of the TURN and into the head.
fn support_status(
    vault: &Vault,
    turn: EntityId,
    head: EntityId,
) -> Result<[Option<EdgeConfirmationStatus>; 2]> {
    let out = vault
        .edges_out(&turn)?
        .into_iter()
        .find(|edge| edge.kind == EdgeKind::Supports && edge.target == head);
    let into = vault
        .edges_in(&head)?
        .into_iter()
        .find(|edge| edge.kind == EdgeKind::Supports && edge.target == turn);
    Ok([out, into].map(|edge| {
        edge.expect("the support edge is kept")
            .provenance
            .map(|flags| flags.confirmation_status)
    }))
}

/// Erasing the only MESSAGE an attachment cites withdraws its support. The
/// wrapper is hidden, and a fresh graph read finds the TURN -> head edge kept
/// but retracted from both ends, while the TURN and the approved head stay
/// live and the head's row never moves.
#[test]
fn erasing_the_cited_words_retracts_their_attachments_support() -> Result<()> {
    let (_dir, vault) = open_vault();
    let fixture = attached(&vault)?;
    let head_before = vault.get_raw(&fixture.head)?;
    delete_message(&vault, fixture.cited)?;
    assert!(!current(&vault, &fixture.wrapper)?, "the wrapper is hidden");
    assert!(current(&vault, &fixture.turn)? && current(&vault, &fixture.head)?);
    assert_eq!(vault.get_raw(&fixture.head)?, head_before);
    assert_eq!(
        support_status(&vault, fixture.turn, fixture.head)?,
        [Some(Retracted); 2],
        "the erased words no longer support the head"
    );
    Ok(())
}

/// The TURN -> head edge as stored now, decoded into the value fields a
/// replay carries.
fn edge_image(vault: &Vault, fixture: &Attached) -> Result<crate::batch::EdgeValueFields> {
    let txn = vault.store.env.read_txn()?;
    let image = crate::ports::EdgeStoreStaging::port_edge_encoded(
        &vault.store,
        &txn,
        &fixture.turn,
        EdgeKind::Supports,
        &fixture.head,
    )?
    .expect("the stored edge image");
    Ok(crate::batch::EdgeValueFields::from_decoded(
        crate::edge::decode_edge_value_for_kind(EdgeKind::Supports, &image)?,
    ))
}

/// Replays `image` of the TURN -> head edge through the replicated edge put
/// that forward rematerialization heals with (`edge_with_value_fields`, the
/// `EdgeWithCreatedAt` apply arm the sync bridge's edge batch shares).
fn replay(vault: &Vault, fixture: &Attached, image: crate::batch::EdgeValueFields) -> Result<()> {
    vault.with_write_txn(|txn| {
        vault
            .batch_in()
            .edge_with_value_fields(&fixture.turn, EdgeKind::Supports, &fixture.head, image)
            .apply(txn)
    })
}

/// The TURN -> head image captured before the erase is replayed. Its
/// Confirmed bytes never bring the withdrawn support back: a fresh graph read
/// still finds the edge retracted.
#[test]
fn replaying_the_old_edge_image_keeps_the_withdrawn_support_retracted() -> Result<()> {
    let (_dir, vault) = open_vault();
    let fixture = attached(&vault)?;
    let image = edge_image(&vault, &fixture)?;
    assert_eq!(
        image.provenance.map(|flags| flags.confirmation_status),
        Some(Confirmed)
    );
    delete_message(&vault, fixture.cited)?;
    assert_eq!(
        support_status(&vault, fixture.turn, fixture.head)?,
        [Some(Retracted); 2]
    );
    replay(&vault, &fixture, image)?;
    assert_eq!(
        support_status(&vault, fixture.turn, fixture.head)?,
        [Some(Retracted); 2],
        "the old image never restores the erased words' support"
    );
    Ok(())
}

/// An edge-map removal (the `DeleteEdge` op the sync bridge stages) drops the
/// retracted TURN -> head rows but keeps the stale wrapper and its `claim_of`
/// link. A bare image of the edge replayed afterwards, with no stored edge
/// left to carry a stamp, still meets that wrapper: a fresh graph read finds
/// the edge back retracted, never undampened.
#[test]
fn a_bare_image_after_edge_removal_keeps_the_withdrawn_support_retracted() -> Result<()> {
    let (_dir, vault) = open_vault();
    let fixture = attached(&vault)?;
    let mut bare = edge_image(&vault, &fixture)?;
    bare.provenance = None;
    delete_message(&vault, fixture.cited)?;
    vault.with_write_txn(|txn| {
        vault
            .batch_in()
            .delete_edge(&fixture.turn, EdgeKind::Supports, &fixture.head)
            .apply(txn)
    })?;
    assert!(
        !vault
            .edges_out(&fixture.turn)?
            .iter()
            .any(|edge| edge.kind == EdgeKind::Supports && edge.target == fixture.head),
        "the removal drops the edge"
    );
    replay(&vault, &fixture, bare)?;
    assert_eq!(
        support_status(&vault, fixture.turn, fixture.head)?,
        [Some(Retracted); 2],
        "a bare image never supports the head undampened"
    );
    Ok(())
}

/// After the erasure, a caller removes the TURN -> head edge and puts it back
/// through each public edge door: the plain puts (`Vault::put_edge`,
/// `Vault::put_edge_with_vad`) and the timestamped batch builders. The stale
/// wrapper still names the edge, so each put lands retracted: a fresh graph
/// read never finds the erased words supporting the head again.
#[test]
fn putting_a_removed_edge_back_keeps_the_withdrawn_support_retracted() -> Result<()> {
    let (_dir, vault) = open_vault();
    let fixture = attached(&vault)?;
    delete_message(&vault, fixture.cited)?;
    let (turn, kind, head) = (fixture.turn, EdgeKind::Supports, fixture.head);
    let neutral = crate::affect::Vad::NEUTRAL;
    let doors: [(&str, &dyn Fn() -> Result<()>); 4] = [
        ("put_edge", &|| vault.put_edge(&turn, kind, &head, 1.0)),
        ("put_edge_with_vad", &|| {
            vault.put_edge_with_vad(&turn, kind, &head, 1.0, neutral)
        }),
        ("edge_with_created_at", &|| {
            vault
                .batch()
                .edge_with_created_at(&turn, kind, &head, 1.0, 7)
                .commit()
        }),
        ("edge_with_created_at_and_vad", &|| {
            vault
                .batch()
                .edge_with_created_at_and_vad(&turn, kind, &head, 1.0, 7, neutral)
                .commit()
        }),
    ];
    for (door, put) in doors {
        assert!(vault.delete_edge(&turn, kind, &head)?, "{door}: removed");
        put()?;
        assert_eq!(
            support_status(&vault, turn, head)?,
            [Some(Retracted); 2],
            "{door}: the erased words never support the head again"
        );
    }
    Ok(())
}

/// A canonical window captured while the attachment stood carries the TURN ->
/// head edge Confirmed. Once the cited words are erased, recovering that
/// window in place completes: the edge it lands is the image under the
/// retracted stamp local withdrawal decides, so a fresh graph read still finds
/// the support withdrawn.
#[cfg(feature = "sync")]
#[test]
fn recovering_a_window_over_withdrawn_support_completes_retracted() -> Result<()> {
    let (dir, vault) = open_vault();
    let fixture = attached(&vault)?;
    let image = {
        let txn = vault.store.env.read_txn()?;
        crate::ports::EdgeStoreStaging::port_edge_encoded(
            &vault.store,
            &txn,
            &fixture.turn,
            EdgeKind::Supports,
            &fixture.head,
        )?
        .expect("the stored edge image")
    };
    let window = loro::LoroDoc::new();
    let key = format!(
        "{}:{:02}:{}",
        fixture.turn.to_hex(),
        EdgeKind::Supports as u8,
        fixture.head.to_hex()
    );
    window
        .get_map("edges")
        .insert(&key, image.as_slice())
        .expect("window edge");
    let snapshot = crate::recovery::capture_canonical_window(&vault, "2026-09", &window)?;
    delete_message(&vault, fixture.cited)?;
    crate::recovery::recover_vault_window(
        &vault,
        &crate::sync::bridge::Materializer::new(),
        dir.path().join("support.manifest"),
        &snapshot,
        crate::recovery::RecoveryBudget::default(),
    )?;
    assert_eq!(
        support_status(&vault, fixture.turn, fixture.head)?,
        [Some(Retracted); 2],
        "the recovered edge keeps the withdrawn support retracted"
    );
    Ok(())
}

/// Seeds one more ordinary claim about `source` than an edge read may
/// materialize, as raw rows copying `claim`'s record (the way the neighbors
/// regression seeds a high-degree node).
fn crowd(vault: &Vault, source: EntityId, claim: EntityId) -> Result<()> {
    let mut value = [0u8; 12];
    value[0..4].copy_from_slice(&0.9_f32.to_le_bytes());
    value[4..12].copy_from_slice(&1_u64.to_le_bytes());
    vault.with_write_txn(|txn| {
        let raw = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, &claim)?
            .expect("the claim record");
        for index in 0..=crate::vault::MAX_EDGE_QUERY_RESULTS {
            let mut bytes = [0u8; 16];
            bytes[..8].copy_from_slice(&(index as u64 + 1).to_le_bytes());
            bytes[15] = 0xC9;
            let copy = EntityId::from_bytes(bytes)?;
            vault.store.entities.put(txn, copy.as_bytes(), &raw)?;
            let key = crate::store::Store::encode_edge_key(&source, EdgeKind::ClaimOf, &copy);
            vault.store.edges_in.put(txn, &key, &value)?;
        }
        Ok(())
    })
}

/// Erasing an attachment's cited words completes on a crowded TURN: the
/// refresh of its edge streams the TURN's claims, so one more ordinary claim
/// about the TURN than an edge read may materialize never refuses the
/// erasure, and the support is still withdrawn.
#[test]
fn erasing_the_cited_words_of_a_crowded_turn_still_retracts_the_support() -> Result<()> {
    let (_dir, vault) = open_vault();
    let fixture = attached(&vault)?;
    crowd(&vault, fixture.turn, fixture.head)?;
    delete_message(&vault, fixture.cited)?;
    assert!(!current(&vault, &fixture.wrapper)?, "the wrapper is hidden");
    assert_eq!(
        support_status(&vault, fixture.turn, fixture.head)?,
        [Some(Retracted); 2],
        "the erased words no longer support the head"
    );
    Ok(())
}

/// The withdrawn-support walk holds only the replayed edge's own wrappers, so
/// ordinary claims about its source never refuse a valid replay. With one
/// more ordinary claim about the TURN than an edge read may materialize
/// (seeded as raw rows, the way the neighbors regression seeds a high-degree
/// node), a bare image of a TURN -> head edge no wrapper names lands as
/// written, over no stored edge and again over its own bare copy.
#[test]
fn a_bare_replay_from_a_crowded_source_lands_as_written() -> Result<()> {
    let (_dir, vault) = open_vault();
    let fixture = attached(&vault)?;
    let mut bare = edge_image(&vault, &fixture)?;
    bare.provenance = None;
    let subject = EntityId::now();
    vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred(1), 1, b"person")?;
    let unnamed = put_head(&vault, subject)?;
    crowd(&vault, fixture.turn, unnamed)?;
    for over in ["no stored edge", "its own bare copy"] {
        vault.with_write_txn(|txn| {
            vault
                .batch_in()
                .edge_with_value_fields(&fixture.turn, EdgeKind::Supports, &unnamed, bare)
                .apply(txn)
        })?;
        assert_eq!(
            support_status(&vault, fixture.turn, unnamed)?,
            [None; 2],
            "the bare image lands as written over {over}"
        );
    }
    Ok(())
}

/// A second live attachment at the same learned time justifies the same edge.
/// Erasing one source keeps the support; once no live attachment is left the
/// edge is retracted. With one shared source both go stale in one erasure, and
/// the second refresh never elects the first, already stale, attachment.
#[test]
fn support_stays_while_a_live_attachment_still_justifies_it() -> Result<()> {
    for shared in [false, true] {
        let (_dir, vault) = open_vault();
        let fixture = attached(&vault)?;
        let second = EntityId::now();
        let source = if shared { fixture.cited } else { fixture.other };
        let actor = vault.dreamer_authority()?;
        let record =
            EdgeProvenanceClaimBody::new(actor.entity_ref(), 1.0, SupersessionStatus::Confirmed);
        let edge = EdgeRef::new(fixture.turn, EdgeKind::Supports, fixture.head);
        vault.with_write_txn(|txn| {
            let learned_at = crate::ports::EntityStoreRead::port_entity_record(
                &vault.store,
                txn,
                &fixture.wrapper,
            )?
            .expect("attachment row")
            .learned_at;
            vault.write_edge_provenance_in_txn(
                txn,
                EdgeProvenanceWrite {
                    claim_id: &second,
                    subject: &edge,
                    body: &record,
                    actor_class: actor.actor_class(),
                    learned_at,
                    explicit_prior: None,
                    imported_evidence: None,
                    generated_evidence: None,
                },
            )?;
            crate::ports::record_derived_edge_in_txn(&vault.store, txn, &second, &source)
        })?;
        for id in [fixture.wrapper, second] {
            assert_eq!(
                vault.get_claim(&id)?.expect("attachment").lifecycle,
                crate::ClaimLifecycleStatus::Active,
                "an equal learned time keeps both attachments live"
            );
        }
        if !shared {
            delete_message(&vault, fixture.cited)?;
            assert!(!current(&vault, &fixture.wrapper)? && current(&vault, &second)?);
            assert_eq!(
                support_status(&vault, fixture.turn, fixture.head)?,
                [Some(Confirmed); 2],
                "the live attachment keeps the support"
            );
        }
        delete_message(&vault, source)?;
        assert!(!current(&vault, &fixture.wrapper)? && !current(&vault, &second)?);
        assert_eq!(
            support_status(&vault, fixture.turn, fixture.head)?,
            [Some(Retracted); 2],
            "shared source {shared}: no live attachment is left"
        );
    }
    Ok(())
}
