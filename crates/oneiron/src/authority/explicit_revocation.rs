//! Positive explicit credential revocation, separate from current admission.

use super::VerifiedSlip;
use crate::{Result, Vault};

impl Vault {
    /// Whether a current verified `SlipRevoke` names this slip or one of the
    /// signed delegation parents captured by its successful verification.
    ///
    /// This blocking read is not an admission check. Expiry, host standing,
    /// grant withdrawal, collisions, consumption and renewal-only lineage do
    /// not make it true. Parent links are never read again: a later colliding
    /// mint cannot replace the credential's admitted ancestry. Errors remain
    /// unknown, not revoked. A positive result may end its ongoing work;
    /// false grants no authority.
    pub fn capability_slip_is_explicitly_revoked(&self, slip: &VerifiedSlip) -> Result<bool> {
        let txn = self.store.env.read_txn()?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        Ok(fold
            .slips
            .is_explicitly_revoked(slip.explicit_revocation_ancestry()))
    }
}
