//! Recognition material and render refs leave with their subject (FIX 10219).
//! Entry: erase_recognition_for_subject_in_txn.
//!
//! The subject's delete and erase remove, in that transaction, every print
//! generation, every enrollment sample with its vector and the active-space
//! pointer, through the one deletion routine withdrawal and retention
//! pruning use, and every render-reference bank row the subject holds,
//! through the routine withdrawal uses. Erasing a counterparty contact
//! removes the prints enrolled for it. The consent log keeps its
//! non-biometric decisions; no read filter stands in for the removal.

use heed::RwTxn;

use super::storage_admission::{
    active_print_subjects, delete_voice_prints_in_txn, read_active_print,
};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_COUNTERPARTY_CONTACT;
use crate::store::Store;

/// The deletion eraser for recognition material and render refs: run in the
/// delete or erase transaction of `id`, before its row goes. A row that is
/// no subject and no enrolled contact holds nothing here.
pub(crate) fn erase_recognition_for_subject_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    delete_voice_prints_in_txn(store, wtxn, id)?;
    super::ref_bank::delete_owner_refs(store, wtxn, id)?;
    let contact = store
        .port_entity_raw(wtxn, id)?
        .is_some_and(|raw| raw.first() == Some(&ENTITY_TYPE_COUNTERPARTY_CONTACT));
    if !contact {
        return Ok(());
    }
    for subject in active_print_subjects(store, wtxn)? {
        if read_active_print(store, wtxn, &subject)?
            .is_some_and(|print| print.contact_ref == Some(*id))
        {
            delete_voice_prints_in_txn(store, wtxn, &subject)?;
        }
    }
    Ok(())
}
