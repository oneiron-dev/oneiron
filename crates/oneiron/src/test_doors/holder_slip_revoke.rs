//! Door for `oneiron-server/tests/memory_verb_owner_proof_at_commit.rs`
//! (FIX MEMORY-VERB-OWNER-PROOF-NOT-REVALIDATED-AT-COMMIT): a holder's slips
//! revoked inside a writer this door holds, so a door that opens its own
//! writer meanwhile waits on the lock behind the revocation.

use crate::Vault;
use crate::authority::HostSlipIssuer;
use crate::error::Result;

/// Opens `vault`'s writer on this thread, revokes in it every live slip
/// `holder_ref` holds, and calls `while_held` with the writer still open
/// and the revocation not yet committed; then commits, tells the live
/// revocation watchers as the public revoke does, and returns the ids it
/// revoked.
///
/// # Errors
///
/// `issuer` is not this vault's host; storage errors.
pub fn revoke_holder_slips_holding_writer(
    vault: &Vault,
    issuer: &HostSlipIssuer,
    holder_ref: &str,
    while_held: impl FnOnce(),
) -> Result<Vec<[u8; 32]>> {
    let mut txn = vault.store.env.write_txn()?;
    let revoked = vault.revoke_held_capability_slips_in_txn(&mut txn, issuer, holder_ref, None)?;
    while_held();
    txn.commit()?;
    if !revoked.is_empty() {
        vault.store.notify_credential_revocations();
    }
    Ok(revoked)
}
