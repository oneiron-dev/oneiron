//! Text a record keeps beside its body and the text it was indexed with,
//! which the records census reads too (OF-067):
//!
//! - the index inputs a storage-managed record staged for idle publication.
//!   The sweep sends the live revision's staged text through the batch door
//!   in place of the text it was indexed with, so the door masks it where it
//!   waits, and drops staged text that still holds a hit once the record is
//!   written again, so its publication reads the lifted body;
//! - a NOTE's title and its pins' quotes. A hit there goes to the NOTE's own
//!   door ([`crate::note::lift_note_in_txn`]), which refuses it as an edit's
//!   is: the title has no handle form and a pin's hash binds its quote.

use heed::{RoTxn, RwTxn};

use super::super::write_payload_hit;
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::registry::ENTITY_TYPE_NOTE;

/// The door's reason for a hit in the text record `id` staged for idle
/// publication, or, for a NOTE, in its title or a pin's quote.
pub(super) fn hit(
    vault: &Vault,
    txn: &RoTxn<'_>,
    id: &EntityId,
    entity_type: u8,
) -> Result<Option<&'static str>> {
    if let Some(reason) = staged_hit(vault, txn, id)? {
        return Ok(Some(reason));
    }
    if entity_type != ENTITY_TYPE_NOTE {
        return Ok(None);
    }
    // A NOTE whose document does not load has no title or pin to read here;
    // its body and index text were read, and its door reads the rest.
    let Ok(side) = crate::note::note_side_text_in_txn(vault, txn, *id) else {
        return Ok(None);
    };
    Ok(side
        .iter()
        .find_map(|text| write_payload_hit(text.as_bytes())))
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
    Ok(
        crate::vault::entity_revision::staged_index_fields(&vault.store, txn, id)?
            .iter()
            .find_map(|(_, text)| write_payload_hit(text.as_bytes())),
    )
}
