//! Door for `tests/do_not_contact_subject_reads.rs` (L6-22, ARCH-0057 H174
//! party-key index): the PERSONs the do-not-contact scan names for a
//! counterparty, and the PERSON rows it read on the calling thread.

use crate::{EntityId, Result, Vault};

/// The PERSONs whose synced body carries `counterparty`'s trimmed party key,
/// in id order, as the external-effect gate's do-not-contact leg and the
/// campaign compliance gate read them.
///
/// # Errors
/// The scan's.
#[doc(hidden)]
pub fn do_not_contact_subjects(vault: &Vault, counterparty: &str) -> Result<Vec<EntityId>> {
    let txn = vault.store.env.read_txn()?;
    crate::campaign::claims::do_not_contact_subjects_in_txn(&vault.store, &txn, counterparty)
}

/// The PERSON rows the do-not-contact scan read on this thread since the
/// last call, which resets the tally to zero.
#[doc(hidden)]
pub fn take_person_party_key_reads() -> usize {
    crate::campaign::claims::take_person_party_key_reads()
}

/// Drops the PERSON party-key index and its completeness flag, as a vault
/// file older than the index holds neither; the scan then reads every PERSON.
///
/// # Errors
/// The write transaction's.
#[doc(hidden)]
pub fn forget_person_party_key_index(vault: &Vault) -> Result<()> {
    crate::store::person_party_keys::forget_person_party_key_index(vault)
}

/// The rebuild of the PERSON party-key index a writable open runs.
///
/// # Errors
/// None: a failed rebuild warns and leaves the index incomplete, as at open.
#[doc(hidden)]
pub fn backfill_person_party_key_index(vault: &Vault) -> Result<()> {
    crate::store::person_party_keys::backfill_person_party_key_index(vault, false)
}
