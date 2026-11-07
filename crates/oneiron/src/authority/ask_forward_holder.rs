//! The holder's operation proof on a relayed ask word (FIX 7494).
//!
//! A replica relays a person's word on a `tasks.ask` it did not admit to
//! the ask's admitting node. The holder signs their slip's binding
//! transcript over a challenge the receiving door rebuilds from the intent
//! itself (`task_verb::ask_forward_challenge`), so the signature binds that
//! one operation. This door checks it under the slip's actual logged mint
//! signer, in the caller's snapshot, as
//! [`Vault::verify_logged_capability_slip_request`] does. It only reads: the
//! challenge carries no nonce, and none is spent.

use super::*;
use crate::Vault;
use crate::error::Result;

impl Vault {
    /// Verifies `slip` and the holder's `signature` over its binding
    /// transcript of `challenge`, in `txn` (FIX 7494): the host and caveat
    /// signatures under the slip's actual logged mint signer, its authority
    /// ancestry, the holder's current binding key, its references and its
    /// current view, a reusable slip, live now. No caller supplies the
    /// signer, a host or metadata; the caller rebuilt `challenge` from the
    /// operation. `None` while the slip's mint has not reached this node's
    /// authority log: the relayed intent waits for it.
    ///
    /// # Errors
    /// An invalid-authority refusal when any check fails; a storage error.
    pub(crate) fn verify_ask_forward_holder_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        slip: &CapabilitySlip,
        challenge: &[u8],
        signature: &[u8],
    ) -> Result<Option<VerifiedSlip>> {
        let fold = self.authority_view_readonly_in_txn(txn)?;
        let now = self.instant_in_txn(txn)?.secs();
        let Some(mint) = fold.slips.mints.get(&slip.claims.slip_id) else {
            return Ok(None);
        };
        let verified = slip.verify(&mint.signer, &fold, now, challenge, signature)?;
        let verified = self.admitted_slip_view_in_txn(txn, verified, now)?;
        if verified.claims().single_use || !self.capability_slip_is_live_in_txn(txn, &verified)? {
            return Err(invalid_authority());
        }
        Ok(Some(verified))
    }
}
