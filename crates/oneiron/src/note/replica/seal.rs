//! A NOTE seal on a replica (FIX 2401; OF-073). The authority's seal rides
//! its state envelope, and the replica installs it in the frame's own write,
//! with the state it froze: validated before the head moves, stored beside
//! the document. A seal never moves: once held, a frame carries that seal or
//! none, and no frame moves the frozen head or text. Erasure, recovery and
//! cleanup keep their own doors; forks of a sealed NOTE stay open. Only the
//! authenticated authority lane sets a seal, never window metadata.

use super::super::document::{NoteDocument, invalid};
use super::super::lifecycle::{NOTE_SEAL, NoteSeal};
use super::super::proposals::NoteActor;
use crate::error::Result;
use crate::{EntityId, Vault};

/// The seal a frame of `note` installs, judged before the frame moves the
/// head: `carried` is the seal its envelope names, `head` the head it
/// carries, `new_head` whether it moves there, and `staged` its document.
/// `None` when nothing new is installed.
///
/// A first seal arrives with the state it froze: its head, and a document
/// holding its frontier. A held seal stops every head move, and a carried
/// seal must be the held one; only its sealer may come to read as no one.
///
/// # Errors
///
/// A seal that names another head or a state it did not freeze, a carried
/// seal that differs from the held one, or a head move of a sealed NOTE.
pub(in crate::note) fn admit_frame(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    note: EntityId,
    carried: Option<&NoteSeal>,
    head: EntityId,
    new_head: bool,
    staged: &loro::LoroDoc,
) -> Result<Option<NoteSeal>> {
    let carried = match carried {
        Some(seal) => Some(NoteSeal {
            sealed_by: seal.sealed_by.erased_here(vault, txn)?,
            ..seal.clone()
        }),
        None => None,
    };
    let Some(held) = NOTE_SEAL.get(&vault.store, txn, &note)? else {
        let Some(seal) = carried else {
            return Ok(None);
        };
        if seal.note != note || seal.document != head {
            return Err(invalid("NOTE seal names another head"));
        }
        if !holds_frontier(staged, &seal.frontier)? {
            return Err(invalid("NOTE state is not the state its seal froze"));
        }
        return Ok(Some(seal));
    };
    if new_head || head != held.document {
        return Err(frozen());
    }
    let Some(seal) = carried else {
        return Ok(None);
    };
    // The one field two copies of a seal may differ in is its sealer, and
    // only as no one (ErasedWins).
    let sealed_by =
        crate::deletion::carrier_actor_merged(held.sealed_by, seal.sealed_by, NoteActor::Erased)
            .ok_or_else(moved)?;
    let merged = NoteSeal {
        sealed_by,
        ..held.clone()
    };
    if (NoteSeal { sealed_by, ..seal }) != merged {
        return Err(moved());
    }
    Ok((merged != held).then_some(merged))
}

/// Stores `seal`, the seal [`admit_frame`] judged, in the frame's write once
/// its state is persisted.
pub(in crate::note) fn install(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    note: EntityId,
    seal: Option<&NoteSeal>,
) -> Result<()> {
    match seal {
        Some(seal) => NOTE_SEAL.put(&vault.store, txn, &note, seal),
        None => Ok(()),
    }
}

/// Refuses a replica write of `next` that moves a sealed NOTE: off its
/// sealed head, or to other text, another title or a citation it did not
/// hold. A write that only drops citations (an erasure's scrub) or replays
/// the same state keeps the freeze.
///
/// # Errors
///
/// A sealed NOTE's head or text would move, or its stored document does not
/// read.
pub(in crate::note) fn refuse_frozen_motion(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    next: &NoteDocument,
) -> Result<()> {
    let Some(seal) = NOTE_SEAL.get(&vault.store, txn, &next.id)? else {
        return Ok(());
    };
    if super::super::documents::head_in(&vault.store, txn, next.id)?.0 != seal.document {
        return Err(frozen());
    }
    let held = NoteDocument::from_loro(
        next.id,
        super::super::storage::load_for_erasure(vault, txn, next.id)?,
    )?;
    let (before, after) = (held.view()?, next.view()?);
    if before.markdown != after.markdown
        || before.title != after.title
        || after.pins.iter().any(|pin| !before.pins.contains(pin))
    {
        return Err(frozen());
    }
    Ok(())
}

/// Whether `doc` holds every operation of the encoded `frontier`.
fn holds_frontier(doc: &loro::LoroDoc, frontier: &[u8]) -> Result<bool> {
    let frontier = loro::Frontiers::decode(frontier).map_err(|_| invalid("NOTE seal frontier"))?;
    let held = doc.oplog_vv();
    Ok(frontier.iter().all(|id| held.includes_id(id)))
}

fn frozen() -> crate::Error {
    invalid("this NOTE is sealed; its document is frozen and an edit opens a fork")
}

fn moved() -> crate::Error {
    invalid("a NOTE seal never moves once written")
}
