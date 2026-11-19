//! Door for `tests/room_speaker_entries.rs`
//! (PLAN-RUN-RESULT-GUARD-SPEAKER-ENTRIES): the owner-alone room read a plan
//! run's result is filed under, and the speaker-entry index it asks.

use crate::{EntityId, Result, Vault};

/// The live vault owner who alone reads `room`, as the plan run's result
/// filing reads it; `None` when anyone else may read it.
///
/// # Errors
/// The read's.
#[doc(hidden)]
pub fn room_sole_owner_reader(vault: &Vault, room: EntityId) -> Result<Option<EntityId>> {
    let txn = vault.store.env.read_txn()?;
    crate::workspace_roster::room_sole_owner_reader_in(vault, &txn, room)
}

/// Drops the whole speaker-entry index and its flag, as a vault file older
/// than the index holds neither.
///
/// # Errors
/// The write's.
#[doc(hidden)]
pub fn forget_speaker_entry_index(vault: &Vault) -> Result<()> {
    crate::task_verb::speaker_entry_index::forget_speaker_entry_index(vault)
}

/// The rebuild of the speaker-entry index a writable open runs.
///
/// # Errors
/// None: a failed rebuild warns and leaves the index incomplete, as at open.
#[doc(hidden)]
pub fn backfill_speaker_entry_index(vault: &Vault) -> Result<()> {
    crate::task_verb::speaker_entry_index::backfill_speaker_entry_index(vault, false)
}

/// Withdraws row `id` here as a same-vault Shell cutoff withdraws it
/// (FIX 931): marked stale through the retrieval stale writer, then
/// scrubbed to its Shell, its header with no body. Whether it took the
/// Shell.
///
/// # Errors
/// The write's.
#[doc(hidden)]
pub fn withdraw_to_shell(vault: &Vault, id: EntityId) -> Result<bool> {
    let mut txn = vault.store.env.write_txn()?;
    crate::ports::RetrievalIndex::port_retrieval_mark_stale(vault, &mut txn, &id)?;
    let scrubbed = crate::deletion::scrub_withdrawn_record_in_txn(&vault.store, &mut txn, &id)?;
    txn.commit()?;
    Ok(scrubbed)
}
