//! OF-606: what every slip door reads of a support slip beside the fold's
//! own standing (lifetime, revocation, vault and pact).
//!
//! A support slip's claims carry the customer's signed delegation. It stands
//! only while recording time is before the delegation's wall deadline, on the
//! store's nondecreasing recording clock (never first-seen time, and never
//! the recoverable proof-freshness floor), while the presented holder key is
//! the key its logged mint bound (no transfer), and while its holder PERSON
//! is still live. Every verified-proof door reads it through
//! `require_live_slip_refs_in_txn`, and the liveness doors that check only
//! lifetime, fold and pact read it as well, so invocation bindings, scoped
//! reads and owner proofs inherit it. Each request a support slip is
//! admitted on also lands the standard Gate receipt that names the support
//! PERSON and joins the grant by its slip id (`support_receipt`).

use super::*;
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;

impl Vault {
    /// A support slip (OF-606) stands only while its delegation does: see
    /// [`Self::support_delegation_stands_in_txn`]. A slip that carries no
    /// delegation passes.
    pub(super) fn require_live_delegation_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        claims: &SlipClaims,
    ) -> Result<()> {
        if self.support_delegation_stands_in_txn(txn, claims)? {
            Ok(())
        } else {
            Err(invalid_authority())
        }
    }

    /// Whether the support delegation `claims` carry still stands in `txn`:
    /// recording time is before its wall deadline (ending at equality), its
    /// logged mint names this same delegation, holder and binding key with
    /// no parent, and the holder PERSON is live. `true` for a slip with no
    /// delegation. An error is a failure to judge, never a refusal.
    pub(crate) fn support_delegation_stands_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        claims: &SlipClaims,
    ) -> Result<bool> {
        let Some(delegation) = &claims.delegation else {
            return Ok(true);
        };
        let recording_now = crate::ports::job_recorded_at_in_txn(&self.store, txn)?;
        if recording_now >= delegation.wall_expires_at {
            return Ok(false);
        }
        let fold = self.authority_view_readonly_in_txn(txn)?;
        let Some(mint) = fold.slips.mints.get(&claims.slip_id) else {
            return Ok(false);
        };
        let minted = &mint.action.claims;
        if minted.delegation.as_ref() != Some(delegation)
            || minted.holder_ref != claims.holder_ref
            || minted.binding_key != claims.binding_key
            || minted.parent_id.is_some()
            || claims.parent_id.is_some()
        {
            return Ok(false);
        }
        let Ok(holder) = EntityId::from_hex(&claims.holder_ref) else {
            return Ok(false);
        };
        crate::consent::person_is_live_in_txn(self, txn, &holder)
    }
}
