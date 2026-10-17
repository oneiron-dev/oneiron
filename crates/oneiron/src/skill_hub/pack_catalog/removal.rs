//! The owner's removal door (OF-519). Installation is the only way a pack
//! runs, so removal undoes exactly that, in one transaction: the receipt
//! leaves the Active catalog, every hook binding of the pack stops, the
//! bundled skills no other holder keeps stop loading, its kinds take no new
//! writes and its predicates lose their owner. The source, its CODE entities,
//! its skill revisions and its history stay, so the pack installs again
//! through the ordinary door, which brings back the skills removal retired.
//! Its setup sessions end too: the grants their permissions minted are
//! revoked with the owner's receipts, while stored credentials stay in
//! custody. A built-in goes back to its seeded Candidate and qualifies again
//! on a fresh checked setup.
use super::{PackInstallReceipt, admission, invalid};
use crate::consent::AuthenticatedOwner;
use crate::side_table::{self, Raw, SideTable};
use crate::{Vault, error::Result};

/// The predicate-owner index the install door writes.
const PACK_PREDICATE: SideTable<String, String, Raw> =
    SideTable::new(&side_table::SKILL_HUB_PACK_PREDICATE);

impl Vault {
    /// Removes the installed `pack` and returns the receipt it had.
    pub fn remove_pack(
        &self,
        owner: &AuthenticatedOwner,
        pack: &str,
    ) -> Result<PackInstallReceipt> {
        let name = pack.to_owned();
        let at = crate::unix_seconds_now();
        let removed = self.with_write_txn_grouped(|txn| {
            let receipt = admission::PACK_INSTALL
                .get(&self.store, txn, &name)?
                .ok_or_else(|| invalid("pack is not installed"))?;
            self.disable_pack_hooks_in_txn(txn, owner, pack)?;
            self.retire_pack_skills_in_txn(txn, &receipt, at)?;
            self.uninstall_pack_kinds_in_txn(txn, &receipt.kinds)?;
            self.end_pack_setup_sessions_in_txn(txn, Some(owner), pack, &receipt.content_hash)?;
            for predicate in &receipt.predicates {
                // Only a row still naming this pack is its own; an update
                // that moved the predicate already rewrote it.
                if PACK_PREDICATE.get(&self.store, txn, predicate)?.as_deref() == Some(pack) {
                    PACK_PREDICATE.delete(&self.store, txn, predicate)?;
                }
            }
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
