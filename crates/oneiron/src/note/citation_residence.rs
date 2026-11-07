//! Erase reach for residence copies of NOTEs (FIX 18400). A NOTE opened in
//! Opened residence mode is held only as residence rows (`ri:b:` body,
//! `ri:d:` document, witness, opened marker, touch: see
//! `sync::client::residence::items`). No canonical row names it, so neither
//! the reverse pin index the live citation erase reads nor the type index the
//! restore reads finds it, and its saved document still carries each pin's
//! quote. A copy whose document pins an erased record goes whole, as an
//! eviction takes it; the next open fetches it again from home, whose own
//! erase scrubbed the citation. A fetched copy of an erased item, or of a
//! NOTE that cites one, is not kept.

use heed::{RoTxn, RwTxn};

use crate::registry::ENTITY_TYPE_NOTE;
use crate::store::Store;
use crate::store::document_frame_tags::{TAG_DOCUMENT, document_sub_tags};
use crate::store::legal_hold::{HoldActor, is_hold_refusal};
use crate::{EntityId, Error, Result, Vault};

/// The residence rows that hold a cached item's text document.
const DOCUMENT_ROWS: &str = "ri:d:";
/// The residence rows that hold a cached item's body, its header first.
const BODY_ROWS: &str = "ri:b:";

/// Drops the residence copy of every cached NOTE whose document pins an
/// erased document or claim ([`super::citation_erase::pin_is_erased`]), or
/// does not read as a NOTE state that could show it does not. A copy of a
/// NOTE a legal hold names stays, as age eviction keeps it: a hold keeps
/// every byte of the rows it names, a cached copy too (OF-470). Returns the
/// NOTEs whose copy went.
///
/// # Errors
///
/// Storage errors.
pub(super) fn erase_residence_citations_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
) -> Result<Vec<EntityId>> {
    let rows: Vec<(String, Vec<u8>)> = vault
        .store
        .sync_state
        .prefix_iter(txn, DOCUMENT_ROWS)?
        .map(|row| row.map(|(key, value)| (key.into_owned(), value.to_vec())))
        .collect::<std::result::Result<_, _>>()?;
    let mut gone = Vec::new();
    for (key, document) in rows {
        let item = key
            .strip_prefix(DOCUMENT_ROWS)
            .and_then(|hex| EntityId::from_hex(hex).ok());
        let Some(item) = item else {
            continue;
        };
        if is_note_copy(&vault.store, txn, item)?
            && !copy_clean(vault, txn, item, &document)?
            && !held(&vault.store, txn, item)?
        {
            gone.push(item);
        }
    }
    crate::sync::residence::erase_item_caches_in_txn(&vault.store, txn, &gone)?;
    Ok(gone)
}

/// Drops the residence copies of `items` themselves, under each one's id and
/// its derived copy's, as the purge's own reach drops them
/// (`note::delete::delete_document_in_txn`): for an erase with no canonical
/// row here to purge, or a restore of an image that held them.
///
/// # Errors
///
/// Storage errors.
pub(super) fn erase_own_copies_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    items: impl IntoIterator<Item = EntityId>,
) -> Result<()> {
    let mut ids = Vec::new();
    for item in items {
        // Both ids stay marked erased, so a home that still serves either
        // copy cannot have it cached again here.
        super::citation_erase::mark_erased(store, txn, item)?;
        ids.push(item);
        if let Ok(copy) = crate::origin::secret_projection::copy_id::copy_id(&item) {
            ids.push(copy);
        }
    }
    crate::sync::residence::erase_item_caches_in_txn(store, txn, &ids)
}

/// A replayed hard erase of `id` that found no canonical row here (FIX
/// 18400): its own residence copy goes, and so does every cached NOTE that
/// cites it, its hard-delete marker now written. Returns the NOTEs whose
/// copy went, for the replay's changed documents.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn erase_residence_copies_of_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<Vec<EntityId>> {
    erase_own_copies_in_txn(&vault.store, txn, [*id])?;
    erase_residence_citations_in_txn(vault, txn)
}

/// Refuses to keep a fetched residence copy of `item` (FIX 18400): an item
/// erased here, the derived copy of an erased record included (its copy id
/// is marked with it), or a NOTE whose document pins an erased record or
/// does not read as its admitted state. The home may not have erased it yet;
/// the next fetch tries again.
///
/// # Errors
///
/// `EntityNotFound` for an erased item, an invalid NOTE body for a NOTE copy
/// that is not clean, or storage errors.
pub(crate) fn refuse_erased_residence_copy_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    item: EntityId,
    entity_type: u8,
    document: &[u8],
) -> Result<()> {
    if super::citation_erase::is_erased(vault, txn, item)? {
        return Err(Error::EntityNotFound);
    }
    if entity_type == ENTITY_TYPE_NOTE && !copy_clean(vault, txn, item, document)? {
        return Err(super::document::invalid(
            "NOTE copy cites an erased record or is no admitted state",
        ));
    }
    Ok(())
}

/// Whether a standing customer legal hold names `item`.
fn held(store: &Store, txn: &RoTxn<'_>, item: EntityId) -> Result<bool> {
    match store.reject_legal_holds_in_txn(txn, &[item], &HoldActor::UNATTRIBUTED) {
        Ok(()) => Ok(false),
        Err(error) if is_hold_refusal(&error) => Ok(true),
        Err(error) => Err(error),
    }
}

/// Whether `item`'s cached body is a NOTE's.
fn is_note_copy(store: &Store, txn: &RoTxn<'_>, item: EntityId) -> Result<bool> {
    let key = format!("{BODY_ROWS}{}", item.to_hex());
    let Some(body) = store.sync_state.get(txn, &key)? else {
        return Ok(false);
    };
    Ok(crate::batch::EntityMetadataHeader::parse(&body)
        .is_some_and(|header| header.entity_type == ENTITY_TYPE_NOTE))
}

/// Whether a cached NOTE document shows no citation of an erased record: a
/// state frame of `item` whose envelope and document read and whose every
/// pin's document and claim stand. Anything else (an update frame, another
/// item's frame, an envelope or document that does not read) cannot show
/// it, so it is not clean.
fn copy_clean(vault: &Vault, txn: &RoTxn<'_>, item: EntityId, bytes: &[u8]) -> Result<bool> {
    let Some(framed) = bytes.strip_prefix(&[TAG_DOCUMENT]) else {
        return Ok(false);
    };
    let Ok(frame) = crate::sync::transport::decode_unsplit_document(framed) else {
        return Ok(false);
    };
    if frame.entity != item || frame.kind != document_sub_tags::STATE {
        return Ok(false);
    }
    let Ok(envelope) = super::frame_envelope::NoteStateEnvelope::decode(item, frame.payload) else {
        return Ok(false);
    };
    let read =
        super::document::NoteDocument::load(item, envelope.document).and_then(|doc| doc.pins());
    let Ok(pins) = read else {
        return Ok(false);
    };
    for pin in &pins {
        if super::citation_erase::pin_is_erased(vault, txn, pin)? {
            return Ok(false);
        }
    }
    Ok(true)
}
