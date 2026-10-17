//! The owner's removal door (OF-519). Installation is the only way a pack
//! runs, so removal undoes exactly that, in one transaction: the receipt
//! leaves the Active catalog and every hook binding of the pack stops. The
//! source, its CODE entities and its history stay, so the pack installs
//! again through the ordinary door. A built-in goes back to its seeded
//! Candidate and qualifies again on its checked setup.
use super::{PackInstallReceipt, admission, invalid};
use crate::consent::AuthenticatedOwner;
use crate::{Vault, error::Result};

impl Vault {
    /// Removes the installed `pack` and returns the receipt it had.
    pub fn remove_pack(
        &self,
        owner: &AuthenticatedOwner,
        pack: &str,
    ) -> Result<PackInstallReceipt> {
        let name = pack.to_owned();
        let removed = self.with_write_txn_grouped(|txn| {
            let receipt = admission::PACK_INSTALL
                .get(&self.store, txn, &name)?
                .ok_or_else(|| invalid("pack is not installed"))?;
            self.disable_pack_hooks_in_txn(txn, owner, pack)?;
            admission::PACK_INSTALL.delete(&self.store, txn, &name)?;
            if let Some(candidate) = super::builtin::reseeded_candidate(&receipt) {
                admission::PACK_CANDIDATE.put(
                    &self.store,
                    txn,
                    &candidate.content_hash,
                    &candidate,
                )?;
            }
            Ok(receipt)
        })?;
        self.verb_hook_bindings_changed();
        Ok(removed)
    }
}
