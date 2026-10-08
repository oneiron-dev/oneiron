//! A stored citation keeps the MESSAGE history it names. While the citing
//! claim is live, the owner's history purge stops at the cited frontier, and
//! an in-place recovery of the same value keeps the document as it is; only a
//! recovery that must rebuild the document from another value stales the
//! claim, instead of leaving it naming lost history.
#![cfg(feature = "sync")]

use super::*;
use crate::entity_doc::DocAuthorization;
use crate::recovery::CanonicalSnapshot;

/// Lands one claim citing the name in `turn`'s streamed MESSAGE.
fn cite_message(vault: &Vault, turn: EntityId) -> Result<EntityId> {
    super::super::prior_heads::policy(vault, vault.dreamer_authority()?.entity_ref(), true)?;
    let subject = EntityId::now();
    vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred(1), 1, b"person")?;
    land(vault, vec![nickname(subject, turn, name_range())], |_| {
        Ok(None)
    })?;
    let [claim] = claims_with(vault, "profile.nickname")?[..] else {
        panic!("one landed claim")
    };
    Ok(claim)
}

/// A claim cites a MESSAGE at the frontier it was read at; a finalized
/// continuation then moves the MESSAGE on. The owner asks to purge history up
/// to the latest version. The claim is live, so the preflight refuses that
/// request and the purge itself stops at the cited frontier: the quoted words
/// still read there, and the claim stays current.
#[test]
fn an_owner_purge_keeps_the_message_version_a_live_claim_cites() -> Result<()> {
    let (_dir, vault) = open_vault();
    let (turn, _, cited, input) = stream_turn(&vault, 0x81, SAID, "finalize")?;
    let writer = EntityId::from_bytes([0x81; 16])?;
    let read_at = vault.entity_text_anchor(&cited, 0, 0)?.frontier().to_vec();
    let claim = cite_message(&vault, turn)?;
    end_stream(&vault, writer, &input, ", thanks", "finalize");
    let latest = vault.entity_text_frontier(&cited)?;
    assert_ne!(latest, read_at, "the continuation moved the document on");
    assert!(
        vault.check_entity_text_purge(&cited, &latest).is_err(),
        "a live citation floors the purge"
    );
    let owner = vault.authenticate_owner(
        writer,
        &writer.to_hex(),
        true,
        crate::store::GateDecisionId::now(),
    )?;
    let receipt =
        vault.purge_entity_text_history(&cited, &latest, &DocAuthorization::Owner(&owner), 20)?;
    assert_ne!(
        receipt.applied, receipt.requested,
        "the purge stopped short"
    );
    assert_eq!(
        vault.entity_text_at(&cited, &read_at).ok().as_deref(),
        Some(SAID),
        "the cited frontier still reads the quoted words"
    );
    assert!(current(&vault, &claim)?, "a purge is not an erasure");
    Ok(())
}

/// A canonical window holding only `message`'s row, with its document.
fn capture_message(vault: &Vault, message: EntityId) -> Result<CanonicalSnapshot> {
    let window = loro::LoroDoc::new();
    window
        .get_map("entities")
        .insert(
            &message.to_hex(),
            vault.get_raw(&message)?.expect("message row").as_slice(),
        )
        .expect("window row");
    let snapshot = crate::recovery::capture_canonical_window(vault, "2026-09", &window)?;
    assert_eq!(
        snapshot.entity_documents.len(),
        1,
        "the document is carried"
    );
    Ok(snapshot)
}

/// Windows holding a cited MESSAGE are captured (a citation floor is not a
/// quote the artifact must carry) and recovered into the MESSAGE's own vault.
/// Recovering its current value leaves the document, its history and its
/// incarnation untouched: the claim stays current and its cited frontier
/// still reads the quoted words. Recovering an older value rebuilds the
/// document from that value under a fresh incarnation, so the claim naming
/// the lost history is no longer current.
#[test]
fn in_place_recovery_keeps_cited_history_unless_the_value_differs() -> Result<()> {
    let (dir, vault) = open_vault();
    let (turn, _, cited, input) = stream_turn(&vault, 0x83, SAID, "finalize")?;
    let read_at = vault.entity_text_anchor(&cited, 0, 0)?.frontier().to_vec();
    let claim = cite_message(&vault, turn)?;
    let older = capture_message(&vault, cited)?;
    let writer = EntityId::from_bytes([0x83; 16])?;
    end_stream(&vault, writer, &input, ", thanks", "finalize");
    let latest = vault.entity_text_frontier(&cited)?;
    let recover = |snapshot: &CanonicalSnapshot, manifest: &str| {
        crate::recovery::recover_vault_window(
            &vault,
            &crate::sync::bridge::Materializer::new(),
            dir.path().join(manifest),
            snapshot,
            crate::recovery::RecoveryBudget::default(),
        )
    };
    recover(&capture_message(&vault, cited)?, "current.manifest")?;
    assert!(
        current(&vault, &claim)?,
        "a value-equal recovery keeps the citation"
    );
    assert_eq!(
        vault.entity_text_frontier(&cited)?,
        latest,
        "the document and its incarnation are untouched"
    );
    assert_eq!(
        vault.entity_text_at(&cited, &read_at).ok().as_deref(),
        Some(SAID),
        "the cited frontier still reads the quoted words"
    );
    recover(&older, "older.manifest")?;
    assert_eq!(vault.entity_text(&cited)?, SAID, "the older value is back");
    assert!(
        !current(&vault, &claim)?,
        "the rebuilt document no longer holds the cited history"
    );
    Ok(())
}
