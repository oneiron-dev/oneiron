//! Kit issue, phase 1: a fresh recovery root and its signed record, held in
//! memory until the kit issuer reports the pieces saved. Nothing is stored
//! here, so a crash before activation publishes no root.

use super::RecoveryRootSeed;
use crate::authority::{
    AuthorityLogEntry, AuthorityOp, MACHINE_ENCRYPTION_SUITE_HYBRID_V1, MachineEncryptionKey,
    OwnerRootRecord,
};
use crate::consent::AuthenticatedOwner;
use crate::error::Result;
use crate::vault::Vault;

/// A root drawn for a kit, not yet published: its seed for the kit issuer,
/// and its record signed by its own anchor. `Debug` is redacted, and it is
/// never stored.
pub struct PreparedRoot {
    seed: RecoveryRootSeed,
    entry: AuthorityLogEntry,
}

impl std::fmt::Debug for PreparedRoot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PreparedRoot(<redacted>)")
    }
}

impl PreparedRoot {
    /// The seed, for the kit issuer only.
    #[must_use]
    pub fn seed(&self) -> &RecoveryRootSeed {
        &self.seed
    }

    /// The root's signed record, which activation publishes.
    pub(crate) fn entry(&self) -> &AuthorityLogEntry {
        &self.entry
    }
}

impl Vault {
    /// Kit issue, phase 1: a fresh seed and its `OwnerRoot` entry, signed by
    /// the seed's anchor alone on this vault's current heads, and not stored.
    pub fn prepare_owner_root(&self, owner: &AuthenticatedOwner) -> Result<PreparedRoot> {
        self.prepare_owner_root_from_seed(owner, RecoveryRootSeed::generate()?)
    }

    /// Phase 1 for a given seed: [`Self::prepare_owner_root`] draws one, and
    /// a kit's confirm passes the one its re-entered pieces rebuild.
    pub(crate) fn prepare_owner_root_from_seed(
        &self,
        owner: &AuthenticatedOwner,
        seed: RecoveryRootSeed,
    ) -> Result<PreparedRoot> {
        let txn = self.store.env.read_txn()?;
        let actor = owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        let vault_id = fold
            .vault_id
            .ok_or_else(|| super::refused("the vault has no authority genesis yet"))?;
        let root = seed.public(&vault_id)?;
        let record = OwnerRootRecord {
            owner: actor,
            root: root.id,
            recovery_key: MachineEncryptionKey {
                suite: MACHINE_ENCRYPTION_SUITE_HYBRID_V1,
                key: root.recovery_key.to_bytes(),
            },
            anchor_key: root.anchor_key,
        };
        let now = self.instant_in_txn(&txn)?.secs();
        let entry = crate::authority::anchor_signed_entry(
            &fold,
            &seed.anchor(),
            AuthorityOp::OwnerRoot(record),
            now,
        )?;
        Ok(PreparedRoot { seed, entry })
    }
}
