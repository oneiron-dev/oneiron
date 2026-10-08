//! An attachment's Supports edge follows the MESSAGE words that justify it.
//! Erasing the cited words withdraws that support from fresh graph reads, and
//! so from PPR, which skips a retracted edge. The TURN and the approved head
//! stay, and another live attachment of the same edge keeps the support.
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
