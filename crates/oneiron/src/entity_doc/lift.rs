//! Entity documents the historical lift sweep reads again (OF-067, Engine
//! ruling G2 = b). A record's prose lives in its document, whose operation
//! history and revisions keep what each edit wrote, so no door rewrites it,
//! and a new write that brings a key into it is refused. The sweep marks the
//! keys of the live text (owner ruling C2), under its hash: each key goes to
//! custody, the record naming where it was found, and its text, operations,
//! revisions and hashes stay as they are. A reader other than the owner reads
//! each lifted key as its handle (`Memory::entity_view_of_in_txn`). A writer
//! that carries a handle back writes its value again, one that deletes it
//! removes the secret, and a commit whose text still holds a lifted value is
//! admitted for it and marked again.

use heed::{RoTxn, RwTxn};

use super::storage::{Head, head, load};
use crate::Vault;
use crate::batch::secret_scan::{CarrierText, LiftedKeys, mark_carrier_text_in_txn};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::Store;

/// Where a lifted key of a record's prose was found, for its custody record.
const PLACE: &str = "document";

/// Marks the keys of `entity`'s live document text, in the caller's
/// transaction.
pub(crate) fn lift_entity_text_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    entity: &EntityId,
) -> Result<CarrierText> {
    let h = head(&vault.store, txn, entity)?;
    let text = load(&vault.store, txn, &h)?.text();
    mark_carrier_text_in_txn(vault, txn, *entity, PLACE, text.as_bytes())
}

/// The keys the lifted text of the document `h` heads holds.
pub(super) fn lifted_keys_in_txn(store: &Store, txn: &RoTxn<'_>, h: &Head) -> Result<LiftedKeys> {
    let text = load(store, txn, h)?.text();
    LiftedKeys::of_in_txn(store, txn, [text])
}

/// `text` read with each value `h`'s lifted text holds as its handle, when
/// that reading is one the write door admits: a text whose only hits are
/// lifted values the document held before this write. `None` for a birth,
/// which held none.
pub(super) fn screened_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    h: &Head,
    text: &str,
) -> Result<Option<String>> {
    if h.generation == 0 {
        return Ok(None);
    }
    Ok(lifted_keys_in_txn(store, txn, h)?.masked(text))
}

/// After a commit the door admitted for its lifted values: the text it
/// leaves is marked, each value keeping its record.
pub(super) fn remark_entity_text_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    entity: &EntityId,
    text: &str,
) -> Result<()> {
    mark_carrier_text_in_txn(vault, txn, *entity, PLACE, text.as_bytes())?;
    Ok(())
}
