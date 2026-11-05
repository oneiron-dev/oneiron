//! Positive explicit credential revocation, separate from current admission.

use crate::{Result, Vault};

impl Vault {
    /// Whether a verified `SlipRevoke` names this slip or one of its signed
    /// delegation parents in the current authority snapshot.
    ///
    /// This blocking read is not an admission check. Expiry, host standing,
    /// grant withdrawal, collisions, consumption and renewal-only lineage do
    /// not make it true. A missing mint or a repeated parent ends the walk,
    /// never supplies a revocation. Errors remain unknown, not revoked.
    /// Callers that already attributed a verified credential may use only a
    /// positive result to end its ongoing work; false grants no authority.
    pub fn capability_slip_is_explicitly_revoked(&self, slip_id: &[u8; 32]) -> Result<bool> {
        let txn = self.store.env.read_txn()?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        Ok(fold.slips.is_explicitly_revoked(slip_id))
    }
}
