//! Vault reads in a snapshot the caller holds (FIX 5870): [`Vault::get`] and
//! the TURN doors' admission and rows, so a door that judges a row and
//! serves its words does both in one snapshot, never admitting in one read
//! and hydrating in a later one.

use heed::RoTxn;

use crate::Vault;
use crate::claim::ScopedRead;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ports::{EntityStoreRead, TombstoneStore, TombstoneStoreRead};

impl Vault {
    /// Runs `read` in one read snapshot of this vault.
    ///
    /// # Errors
    ///
    /// The snapshot's own failure to open, or `read`'s.
    pub fn with_read_snapshot<T, E: From<crate::Error>>(
        &self,
        read: impl FnOnce(&RoTxn<'_>) -> std::result::Result<T, E>,
    ) -> std::result::Result<T, E> {
        let txn = self.store.env.read_txn().map_err(crate::Error::from)?;
        read(&txn)
    }

    /// [`Self::get`] in `txn`: the same safe text, and the same empty body
    /// for a soft-erased shell.
    ///
    /// # Errors
    ///
    /// As [`Self::get`].
    pub fn get_in_txn(&self, txn: &RoTxn<'_>, id: &EntityId) -> Result<Option<Vec<u8>>> {
        if let Some(body) = crate::ports::safe_read_text(self, txn, id)? {
            return Ok(Some(body));
        }
        // The blob facade preserves a soft-erased shell as Some(empty). This
        // is not live text: safe hydration still excludes it, and stale or
        // archived rows stay absent. Never expose a tombstoned body awaiting scrub.
        let Some(row) = self.store.port_entity_record(txn, id)? else {
            return Ok(None);
        };
        let visibility = TombstoneStoreRead::port_deletion_state(self, txn, id)?;
        Ok(
            (row.body.is_empty()
                && visibility.deleted
                && !visibility.archived
                && !visibility.stale)
                .then(Vec::new),
        )
    }

    /// [`Self::is_deleted_shell`] in `txn`.
    ///
    /// # Errors
    ///
    /// As [`Self::is_deleted_shell`].
    pub fn is_deleted_shell_in_txn(&self, txn: &RoTxn<'_>, id: &EntityId) -> Result<bool> {
        TombstoneStore::port_tombstone_is_deleted(self, txn, id)
    }

    /// [`Self::turn_doors_owner`] in `txn`.
    ///
    /// # Errors
    ///
    /// As [`Self::turn_doors_owner`].
    pub fn turn_doors_owner_in_txn(&self, read: &ScopedRead<'_>, txn: &RoTxn<'_>) -> Result<bool> {
        self.turn_doors_owner_in(read, txn)
    }

    /// Whether the TURN doors serve the row `id` to `read`'s caller in
    /// `txn`: the owner's own read (`owner`,
    /// [`Self::turn_doors_owner_in_txn`]) under each private thread alone
    /// (FIX 5652), any other caller under its lane's whole row admission
    /// (FIX 5938).
    ///
    /// # Errors
    ///
    /// A failed admission read.
    pub fn turn_door_admits_in_txn(
        &self,
        read: &ScopedRead<'_>,
        txn: &RoTxn<'_>,
        owner: bool,
        id: &EntityId,
    ) -> Result<bool> {
        if owner {
            read.private_threads_admit_in(txn, id)
        } else {
            read.is_entity_readable_in(txn, id)
        }
    }

    /// The rows `ids` as the TURN doors serve them to `read`'s caller, each
    /// admitted and read in `txn` (FIX 5870): for the owner's own read
    /// (`owner`), a row its private threads admit, with its stored kind,
    /// time and safe body ([`Self::get_in_txn`]); for any other caller, the
    /// row its lane reads. `None` in a slot is a row not served.
    ///
    /// # Errors
    ///
    /// A failed admission or row read.
    pub fn turn_door_parts_in_txn(
        &self,
        read: &ScopedRead<'_>,
        txn: &RoTxn<'_>,
        owner: bool,
        ids: &[EntityId],
    ) -> Result<Vec<Option<(u8, u64, Vec<u8>)>>> {
        if !owner {
            return read.get_entities_parts_in_txn(txn, ids);
        }
        ids.iter()
            .map(|id| {
                if !read.private_threads_admit_in(txn, id)? {
                    return Ok(None);
                }
                let Some(header) = self.entity_header_in_txn(txn, id)? else {
                    return Ok(None);
                };
                Ok(self
                    .get_in_txn(txn, id)?
                    .map(|body| (header.entity_type, header.learned_at, body)))
            })
            .collect()
    }
}
