//! One vault identity, resolved once at open and held on the handle.
//!
//! Every check that asks "do these two handles belong to one vault" compares a
//! [`VaultId`], never a pointer: a pointer tells two handles on one vault apart
//! and says nothing about a vault, while this value is the vault's own.

use rand_core::{OsRng, RngCore};

use super::Vault;
use crate::HostingPrivacyPosture;
use crate::authority::{AuthorityVaultId, authority_fold_readonly_for_store_in_txn};
use crate::error::{Error, Result};
use crate::side_table::{self, Raw, SideTable};
use crate::store::Store;

const LOCAL_VAULT_ID: SideTable<(), [u8; 32], Raw> =
    SideTable::new(&side_table::VAULT_IDENTITY_LOCAL);

/// Which vault a handle belongs to.
///
/// Canon (identity.md, "Vault identity") names a vault by the BLAKE3 hash of
/// its genesis authority entry. A vault gets that entry lazily, when its host
/// root slip is first minted, and the opener holds no signer to write it, so
/// an unrooted vault is named by a random id it persists at its first open
/// instead. Two opens of one vault resolve to the same value; two vaults never
/// share one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VaultId {
    /// The canonical `vault_id` the authority fold carries: the
    /// `genesis_vault_id` of the log's genesis entry.
    Genesis(AuthorityVaultId),
    /// The persisted random id of a vault whose log folds to no genesis.
    Local([u8; 32]),
}

impl VaultId {
    /// Resolves the identity of the vault behind `store`, minting and
    /// persisting the local id on the first open of an unrooted vault.
    ///
    /// Read once per open: a handle keeps the identity it opened with, so a
    /// vault rooted while open names itself by its genesis from its next open.
    pub(super) fn resolve_at_open(store: &Store, posture: HostingPrivacyPosture) -> Result<Self> {
        let mut wtxn = store.env.write_txn()?;
        // `None` for an unrooted log and for a log that folds to two roots.
        let genesis = match authority_fold_readonly_for_store_in_txn(store, posture, &wtxn) {
            Ok(fold) => fold.vault_id,
            Err(error @ (Error::Storage(_) | Error::Io(_))) => return Err(error),
            // Every other refusal is an authority verdict (a first-seen gap, a
            // damaged sidecar, a log row that does not decode): the authority
            // surfaces refuse owner verbs on it after open, and it must not
            // refuse the open itself. Such a vault is named by its local id.
            Err(_) => None,
        };
        if let Some(id) = genesis {
            return Ok(Self::Genesis(id));
        }
        if let Some(id) = LOCAL_VAULT_ID.get(store, &wtxn, &())? {
            return Ok(Self::Local(id));
        }
        let mut id = [0; 32];
        OsRng.fill_bytes(&mut id);
        LOCAL_VAULT_ID.put(store, &mut wtxn, &(), &id)?;
        wtxn.commit()?;
        Ok(Self::Local(id))
    }
}

impl Vault {
    /// The identity this handle resolved at open.
    pub(crate) fn vault_id(&self) -> VaultId {
        self.vault_id
    }
}
