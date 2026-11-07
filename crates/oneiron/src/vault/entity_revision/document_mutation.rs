//! The vault's document-mutation head (FIX 2860): one row that moves with
//! every committed document edit, so an action digest sees a live edit to a
//! document its request does not name.
//!
//! The document writer advances the head in the transaction that commits the
//! edit, from the entity-bound live revision the revision ledger captures
//! there. The new head is BLAKE3 of the head before it, the entity and that
//! revision, so it never returns to an earlier value. A write that leaves the
//! document's live revision as it was (a compaction, a counter, a birth that
//! restates its record's own text) keeps the head. A vault where no document
//! edit was ever committed holds no row.

use heed::{RoTxn, RwTxn};

use super::RevisionRef;
use crate::EntityId;
use crate::error::Result;
use crate::side_table::{self, Raw, SideTable};
use crate::store::ManifestDbs;

const HEAD: SideTable<(), [u8; 16], Raw> =
    SideTable::new(&side_table::PORTS_DOCUMENT_MUTATION_HEAD);

/// The domain the head's digest is taken in.
const HEAD_DOMAIN: &str = "oneiron.document_mutation_head.v1";

/// The vault's document-mutation head in `txn`; `None` when no document edit
/// was ever committed.
///
/// # Errors
///
/// Storage errors, and a stored head that is not 16 bytes.
pub(crate) fn document_mutation_head_in_txn(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
) -> Result<Option<[u8; 16]>> {
    HEAD.get(store, txn, &())
}

/// Advances the head in `txn`, the writer that commits `entity`'s document
/// at its new live `revision`.
///
/// # Errors
///
/// Storage errors, and a stored head that is not 16 bytes.
pub(crate) fn advance_document_mutation_head_in_txn(
    store: &impl ManifestDbs,
    txn: &mut RwTxn<'_>,
    entity: &EntityId,
    revision: RevisionRef,
) -> Result<()> {
    let mut hash = blake3::Hasher::new_derive_key(HEAD_DOMAIN);
    if let Some(before) = HEAD.get(store, txn, &())? {
        hash.update(&[1]).update(&before);
    } else {
        hash.update(&[0]);
    }
    hash.update(entity.as_bytes()).update(&revision.0);
    let mut next = [0; 16];
    next.copy_from_slice(&hash.finalize().as_bytes()[..16]);
    HEAD.put(store, txn, &(), &next)
}
