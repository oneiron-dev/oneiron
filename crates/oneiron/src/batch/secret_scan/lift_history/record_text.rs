//! Text a record keeps beside its body and the text it was indexed with,
//! which the records census reads too (OF-067):
//!
//! - the index inputs a storage-managed record staged for idle publication.
//!   The sweep sends the live revision's staged text through the batch door
//!   in place of the text it was indexed with, so the door masks it where it
//!   waits, and drops staged text that still holds a hit once the record is
//!   written again, so its publication reads the lifted body;
//! - a NOTE's title and its pins' quotes. A hit there goes to the NOTE's own
//!   door ([`crate::note::lift_note_in_txn`]), which marks it where it is
//!   kept, as it marks the NOTE's body and index text: the title, the pin's
//!   quote and hash and the history stay as they are (FIX 2967). A NOTE's
//!   text a mark covers is done.

use heed::{RoTxn, RwTxn};

use super::super::write_payload_hit;
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::registry::ENTITY_TYPE_NOTE;
use crate::secret_custody::masked_file_in_txn;

/// The door's reason for a hit in the text record `id` staged for idle
/// publication, or, for a NOTE, in its title or a pin's quote.
pub(super) fn hit(
    vault: &Vault,
    txn: &RoTxn<'_>,
    id: &EntityId,
    entity_type: u8,
) -> Result<Option<&'static str>> {
    let note = entity_type == ENTITY_TYPE_NOTE;
    for (_, text) in staged(vault, txn, id)? {
        if let Some(reason) = unmarked_hit(vault, txn, note, text.as_bytes())? {
            return Ok(Some(reason));
        }
    }
    if !note {
        return Ok(None);
    }
    // A NOTE whose document does not load has no title or pin to read here;
    // its body and index text were read, and its door reads the rest.
    let Ok(side) = crate::note::note_side_text_in_txn(vault, txn, *id) else {
        return Ok(None);
    };
    for text in side {
        if let Some(reason) = unmarked_hit(vault, txn, true, text.as_bytes())? {
            return Ok(Some(reason));
        }
    }
    Ok(None)
}

/// The door's reason for a hit in `text`, a text a record keeps; for a
/// NOTE's (`note`), only one no mark covers, as its lift leaves it (FIX
/// 2967).
pub(super) fn unmarked_hit(
    vault: &Vault,
    txn: &RoTxn<'_>,
    note: bool,
    text: &[u8],
) -> Result<Option<&'static str>> {
    let Some(reason) = write_payload_hit(text) else {
        return Ok(None);
    };
    if note && masked_file_in_txn(&vault.store, txn, blake3::hash(text).as_bytes())?.is_some() {
        return Ok(None);
    }
    Ok(Some(reason))
}

/// Every text field record `id` staged, whatever revision it was staged for.
pub(super) fn staged(
    vault: &Vault,
    txn: &RoTxn<'_>,
    id: &EntityId,
) -> Result<Vec<(String, String)>> {
    crate::vault::entity_revision::staged_index_fields(&vault.store, txn, id)
}

/// The text record `id` staged for its live revision's idle publication.
pub(super) fn staged_live(
    vault: &Vault,
    txn: &RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<Vec<(String, String)>>> {
    crate::vault::entity_revision::staged_live_index_fields(&vault.store, txn, id)
}

/// Once record `id` is written again: staged text that still holds a hit
/// (staged for a revision no publication reads, or kept beside text the door
/// indexed at once) is dropped, and its publication reads the lifted body.
pub(super) fn settle_staged(vault: &Vault, txn: &mut RwTxn<'_>, id: &EntityId) -> Result<()> {
    if staged_hit(vault, txn, id)?.is_some() {
        crate::vault::entity_revision::drop_staged_index_fields(&vault.store, txn, id)?;
    }
    Ok(())
}

fn staged_hit(vault: &Vault, txn: &RoTxn<'_>, id: &EntityId) -> Result<Option<&'static str>> {
    Ok(staged(vault, txn, id)?
        .iter()
        .find_map(|(_, text)| write_payload_hit(text.as_bytes())))
}
