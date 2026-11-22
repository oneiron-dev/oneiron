//! Door for `tests/comm_party_lookup_reads.rs` (FIX
//! COMM-PARTY-LOOKUP-INDEX-CANDIDATES, after the L6-22 PERSON party-key
//! index): the party a read-only lookup resolves a key to, and the PERSON
//! rows the party validator read on the calling thread.

use crate::comm::CommResult;
use crate::{EntityId, Vault};

/// The party `party` resolves to on one read transaction, as
/// `resolve_party_ref_in_txn` resolves it: the shortcut when it is fresh,
/// otherwise the smallest active comm-owned PERSON carrying the key. It
/// never repairs the shortcut.
///
/// # Errors
/// An invalid party key, or the lookup's storage error.
#[doc(hidden)]
pub fn resolve_comm_party_ref(vault: &Vault, party: &str) -> CommResult<Option<EntityId>> {
    let txn = vault.store.env.read_txn()?;
    crate::comm::resolve_party_ref_in_txn(vault, &txn, party)
}

/// The PERSON rows the party validator read on this thread since the last
/// call, which resets the tally to zero.
#[doc(hidden)]
pub fn take_comm_party_row_reads() -> usize {
    crate::comm::take_comm_party_row_reads()
}
