//! The ruled screen (L6-03-RULED-SCREEN-LOCAL; Engine RULING 14 Nov 08:35:
//! "a ruling must hold on all of the owner's machines"). A found key the
//! owner, or the person who wrote it, ruled no secret or kept as text stays
//! a kept value of its record on every install of the vault, not only on
//! the one where the ruling was made.
//!
//! The screen holds no value: one digest per ruled value, keyed BLAKE3 under
//! the vault's screen key, which every install derives from the vault's one
//! data key ([`RULED_SCREEN_CONTEXT`]). It is never an unkeyed hash that a
//! short value could be guessed back from. The ruling writes its record's
//! row in its own transaction, and its revoke carries the same screen to the
//! owner's other machines ([`CustodyRevokeScreen`]), where the owner work
//! drain writes the row ([`Vault::settle_revoked_custody`]). The write door
//! reads the row through [`super::KeptValues`] before it masks.
//!
//! The screen key is held in memory, for every handle on the store, while
//! the vault data key is held, and it goes when that key is locked. It never
//! rests. A store that holds no screen key tests no digest, so the door
//! masks as it did before the screen existed (fail closed).

use std::sync::{Arc, PoisonError, RwLock};

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::authority::CustodyRevokeScreen;
use crate::entity_id::EntityId;
use crate::error::{Error, GateError, Result};
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;
use crate::vault::Vault;
use crate::world_keys::VaultKeyStatus;

/// The context the screen key derives from the vault data key under.
const RULED_SCREEN_CONTEXT: &str = "oneiron/found-key-ruled-screen/v1";

/// Each record's ruled screen. Key: the record's id.
const SCREEN: SideTable<EntityId, RuledScreen, Named> =
    SideTable::new(&side_table::SECRET_RULED_SCREEN);

/// The digests of the values ruled no secret or kept as text in one record,
/// ascending, each once. It holds no value and names no person.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct RuledScreen {
    digests: Vec<[u8; 32]>,
}

/// The vault's screen key: what each ruled value's digest is keyed by.
pub(crate) struct RuledScreenKey(Zeroizing<[u8; 32]>);

impl std::fmt::Debug for RuledScreenKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RuledScreenKey(..)")
    }
}

impl RuledScreenKey {
    /// The keyed digest of `value`.
    pub(crate) fn digest(&self, value: &[u8]) -> [u8; 32] {
        *blake3::keyed_hash(&self.0, value).as_bytes()
    }
}

/// The screen key every handle on one store reads, held while the vault
/// data key is held. Never persisted.
#[derive(Default)]
pub(crate) struct RuledScreenSlot(RwLock<Option<Arc<RuledScreenKey>>>);

impl RuledScreenSlot {
    /// Holds the screen key `key`, the vault data key of vault `vault_id`,
    /// derives.
    pub(crate) fn admit(
        &self,
        key: &oneiron_store::vault_page_seal::VaultDataKey,
        vault_id: &[u8; 32],
    ) {
        let screen = RuledScreenKey(key.derive(RULED_SCREEN_CONTEXT, vault_id));
        *self.0.write().unwrap_or_else(PoisonError::into_inner) = Some(Arc::new(screen));
    }

    /// Drops the screen key, as the vault data key is locked.
    pub(crate) fn clear(&self) {
        *self.0.write().unwrap_or_else(PoisonError::into_inner) = None;
    }

    /// The screen key, while it is held.
    pub(crate) fn get(&self) -> Option<Arc<RuledScreenKey>> {
        self.0
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

/// The digests of `record`'s ruled screen, read in `txn`.
pub(super) fn ruled_digests_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    record: &EntityId,
) -> Result<Vec<[u8; 32]>> {
    Ok(SCREEN
        .get(store, txn, record)?
        .map(|screen| screen.digests)
        .unwrap_or_default())
}

/// Whether `screen` already stands in its record's row.
pub(crate) fn holds_ruled_screen_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    screen: &CustodyRevokeScreen,
) -> Result<bool> {
    Ok(ruled_digests_in_txn(store, txn, &screen.record)?
        .binary_search(&screen.digest)
        .is_ok())
}

/// Puts `screen` in its record's row, in `wtxn`. Returns whether it was new.
pub(crate) fn hold_ruled_screen_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    screen: &CustodyRevokeScreen,
) -> Result<bool> {
    let mut row = SCREEN.get(store, wtxn, &screen.record)?.unwrap_or_default();
    let Err(at) = row.digests.binary_search(&screen.digest) else {
        return Ok(false);
    };
    row.digests.insert(at, screen.digest);
    SCREEN.put(store, wtxn, &screen.record, &row)?;
    Ok(true)
}

/// Moves `old`'s ruled screen under `new` with its found keys
/// ([`super::move_side_row_custody_in_txn`]): the digests join `new`'s.
pub(super) fn move_ruled_screen_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    old: &EntityId,
    new: &EntityId,
) -> Result<()> {
    let Some(moved) = SCREEN.get(store, wtxn, old)? else {
        return Ok(());
    };
    for digest in moved.digests {
        hold_ruled_screen_in_txn(
            store,
            wtxn,
            &CustodyRevokeScreen {
                record: *new,
                digest,
            },
        )?;
    }
    SCREEN.delete(store, wtxn, old)?;
    Ok(())
}

impl Vault {
    /// The screen key a ruling digests its value with, read before the
    /// ruling's transaction; `None` for a vault with no data key, which has
    /// never made the checkpoint a second install of it opens from, so the
    /// ruling has no other machine to reach.
    ///
    /// # Errors
    /// [`GateError::InvalidConsentBound`] while the vault's data key is
    /// locked: the ruling would not hold on the owner's other machines, so
    /// it waits for the owner to unlock the key. The store's errors.
    pub(super) fn ruled_screen_key(&self) -> Result<Option<Arc<RuledScreenKey>>> {
        if let Some(key) = self.store.ruled_screen.get() {
            return Ok(Some(key));
        }
        match self.vault_key_status()? {
            VaultKeyStatus::NoKey => Ok(None),
            VaultKeyStatus::Locked | VaultKeyStatus::Unlocked => {
                Err(Error::Gate(GateError::InvalidConsentBound(
                    "the vault key is locked, so this ruling would not reach your other \
                     machines; unlock the vault key, then rule again",
                )))
            }
        }
    }
}

/// The screen of `value` ruled in `record`, under `key`.
pub(super) fn ruled_screen(
    key: &RuledScreenKey,
    record: EntityId,
    value: &[u8],
) -> CustodyRevokeScreen {
    CustodyRevokeScreen {
        record,
        digest: key.digest(value),
    }
}
