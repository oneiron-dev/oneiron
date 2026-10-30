//! One vault identity, resolved once at open and held on the handle.
//!
//! Every check that asks "do these two handles belong to one vault" compares a
//! [`VaultId`], never a pointer: a pointer tells two handles on one vault apart
//! and says nothing about a vault, while this value is the vault's own.

use rand_core::{OsRng, RngCore};

use super::Vault;
use crate::error::{Error, Result, StoreError};
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
    /// first open: `adopt` when given ([`OpenOptions::adopt_storage_id`]),
    /// else `preset` (a sealed vault's, which its page seal's wraps are bound
    /// to), else at random. A store that holds an id other than `adopt`, or
    /// an `adopt` that is not the page seal's, refuses, and nothing is
    /// rewritten.
    pub(super) fn resolve_at_open(
        store: &Store,
        preset: Option<[u8; 32]>,
        adopt: Option<VaultStorageId>,
    ) -> Result<Self> {
        let mut wtxn = store.env.write_txn()?;
        let mismatch = || Error::Store(StoreError::StorageIdMismatch);
        if let Some(id) = VAULT_STORE_ID.get(store, &wtxn, &())? {
            if adopt.is_some_and(|adopt| adopt.0 != id) {
                return Err(mismatch());
            }
            return Ok(Self(id));
        }
        let id = match (adopt, preset) {
            (Some(adopt), Some(preset)) if adopt.0 != preset => return Err(mismatch()),
            (Some(adopt), _) => adopt.0,
            (None, Some(preset)) => preset,
            (None, None) => {
                let mut id = [0; 32];
                OsRng.fill_bytes(&mut id);
                id
            }
        };
        VAULT_STORE_ID.put(store, &mut wtxn, &(), &id)?;
        wtxn.commit()?;
        Ok(Self(id))
    }

    /// The id's bytes, for binding a value to this vault's store.
    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Vault {
    /// The identity this handle resolved at open.
    pub(crate) fn vault_id(&self) -> VaultId {
        self.vault_id
    }
}

/// A vault store's id as an open adopts it in place of a fresh random one
/// (FIX 3375, L01 04:55): the home's, for a device that joins it from an
/// empty store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VaultStorageId([u8; 32]);

impl VaultStorageId {
    /// The home store's id `pin` names (`AuthorityCheckpointPin::vault_id`).
    /// Take it only from a pin verified against the owner's pairing link:
    /// `device enrol` takes it after `verify_join_pin`
    /// (`oneiron-server` `device_sync::enrolment::join`) has checked the
    /// pin's digest against the link's and each of its key bindings under
    /// its root, never from a link's raw bytes.
    #[must_use]
    pub fn from_verified_pin(pin: &crate::authority::AuthorityCheckpointPin) -> Self {
        Self(pin.vault_id)
    }

    /// The id's bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// What one open does beyond its configuration.
#[derive(Debug, Clone, Copy, Default)]
pub struct OpenOptions {
    adopt_storage_id: Option<VaultStorageId>,
}

impl OpenOptions {
    /// Creates the store under `id` instead of a fresh random id. It applies
    /// only to an open that creates the store, one with no id row yet: the
    /// id is written in the transaction that would mint the random one,
    /// before the open seeds its rows. A store that already holds `id` opens
    /// as usual; one that holds another refuses with
    /// [`StoreError::StorageIdMismatch`], and nothing is rewritten.
    #[must_use]
    pub fn adopt_storage_id(mut self, id: VaultStorageId) -> Self {
        self.adopt_storage_id = Some(id);
        self
    }

    pub(super) fn adopted_storage_id(&self) -> Option<VaultStorageId> {
        self.adopt_storage_id
    }
}
