//! One vault identity, resolved once at open and held on the handle.
//!
//! Every check that asks "do these two handles belong to one vault" compares a
//! [`VaultId`], never a pointer: a pointer tells two handles on one vault apart
//! and says nothing about a vault, while this value is the vault's own.

use rand_core::{OsRng, RngCore};

use super::Vault;
use crate::error::Result;
use crate::side_table::{self, Raw, SideTable};
use crate::store::Store;

const VAULT_STORE_ID: SideTable<(), [u8; 32], Raw> =
    SideTable::new(&side_table::VAULT_IDENTITY_LOCAL);

/// Which vault store a handle belongs to.
///
/// Canon (identity.md, "Vault identity") names a vault by the BLAKE3 hash of
/// its genesis authority entry, which the authority fold carries. That name
/// cannot tell two handles' stores apart: an unrooted vault has none until its
/// host root slip is first minted, and every replica that syncs the log shares
/// it. A handle therefore compares the random id its store persisted at its
/// first open: every handle on one store holds the same value, before and
/// after a rooting, and a replica is another store with its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct VaultId([u8; 32]);

impl VaultId {
    /// Reads the id `store` persisted at its first open, minting it on that
    /// first open.
    pub(super) fn resolve_at_open(store: &Store) -> Result<Self> {
        let mut wtxn = store.env.write_txn()?;
        if let Some(id) = VAULT_STORE_ID.get(store, &wtxn, &())? {
            return Ok(Self(id));
        }
        let mut id = [0; 32];
        OsRng.fill_bytes(&mut id);
        VAULT_STORE_ID.put(store, &mut wtxn, &(), &id)?;
        wtxn.commit()?;
        Ok(Self(id))
    }
}

impl Vault {
    /// The identity this handle resolved at open.
    pub(crate) fn vault_id(&self) -> VaultId {
        self.vault_id
    }
}
