//! A reveal closed with a named cause when its secret is erased (FIX 8350).

use super::notice::settle_reveal_notices_in_txn;
use super::{REVEALS, SecretRevealCause, SecretRevealState};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::vault::Vault;

/// Closes every still-open reveal of `secret` with `cause` (FIX 8350): an
/// ask filed before the secret's erase finds no value afterwards, and reads
/// unavailable instead of waiting. One scan of `REVEALS`, in the erase's own
/// transaction, reading no value: a row that names `secret` and may still go
/// out closes, its notices settled. Delivered, denied and expired rows stay
/// as they are (history).
///
/// # Errors
/// Storage errors, or a reveal row that cannot be read.
pub(crate) fn close_secret_reveals_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    secret: &EntityId,
    cause: SecretRevealCause,
) -> Result<()> {
    let now = crate::ports::recorded_at_in_txn(&vault.store, wtxn)?;
    let mut closed = Vec::new();
    for (reveal, mut row) in REVEALS.scan(&vault.store, wtxn)? {
        let names = row.secret == *secret
            || row
                .file
                .as_ref()
                .is_some_and(|file| file.keys.iter().any(|(key, _)| key == secret));
        if !names || !row.still_open(now) {
            continue;
        }
        row.state = SecretRevealState::Unavailable;
        row.closed = Some(cause);
        settle_reveal_notices_in_txn(vault, wtxn, &mut row)?;
        closed.push((reveal, row));
    }
    for (reveal, row) in &closed {
        REVEALS.put(&vault.store, wtxn, reveal, row)?;
    }
    Ok(())
}
