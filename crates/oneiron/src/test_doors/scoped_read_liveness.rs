//! Doors for `tests/deleted_holder_slip.rs` (RULING DELETED-ACTOR-SLIP-AUTH
//! = A): the credential recheck a scoped read lane runs before each row it
//! admits, so a test reads whether a kept read key still stands.

use crate::claim::ScopedRead;
use crate::error::Result;

/// Whether `read`'s credential stands in a fresh snapshot, as each row
/// admission of the lane rechecks it (`ScopedRead::proof_live_in`).
pub fn scoped_read_proof_live(read: &ScopedRead<'_>) -> Result<bool> {
    let rtxn = read.vault().store.env.read_txn()?;
    read.proof_live_in(&rtxn)
}
