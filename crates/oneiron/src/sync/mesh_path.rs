//! Path receipts for paired-machine mesh connections (OF-535). Canon
//! (CROSS-ARCH-0019): every connection leaves a path receipt, direct or
//! relayed. The mesh transport writes one when it admits a connection, and
//! the same row again when that connection closes, with the paths that
//! carried its data meanwhile. A refused or failed attempt leaves one too.
//! The transport folds the refusals from one machine, or from keys no MACHINE
//! names, into one receipt a window ([`MeshPathReceipt::attempts`]), so a
//! stranger cycling keys adds at most one row a window. Local only, never
//! synced. A write drops the receipts older than
//! [`MESH_PATH_RECEIPT_RETAIN_MS`].

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::error::Result;
use crate::side_table::{self, Named, SideTable};

/// This vault's mesh path receipts, keyed by receipt id: the open time in
/// milliseconds as 16 hex digits, then a minted entity id, so key order is
/// time order.
const PATH_RECEIPTS: SideTable<String, MeshPathReceipt, Named> =
    SideTable::new(&side_table::SYNC_MESH_PATH_RECEIPT);

/// The ALPN sync rides (OF-535): the sync server's HTTP/1.1 routes and their
/// WebSocket upgrades, on one long-lived stream per connection. A peer sync
/// session's receipt names it (FIX 4748).
pub const SYNC_ALPN: &[u8] = b"oneiron/sync/1";

/// How long a path receipt is kept: 90 days.
pub const MESH_PATH_RECEIPT_RETAIN_MS: u64 = 90 * 24 * 60 * 60 * 1000;

/// The most expired receipts one write drops.
const PRUNE_PER_WRITE: usize = 64;

/// The most receipts one read returns.
pub const MESH_PATH_RECEIPTS_READ_MAX: usize = 1024;

#[doc(hidden)]
pub use oneiron_verb_wire::sync::mesh_path::{
    MeshPathDirection, MeshPathKind, MeshPathOutcome, MeshPathReceipt,
};

/// The open time a receipt id starts with.
fn opened_at(id: &str) -> Option<u64> {
    u64::from_str_radix(id.get(..16)?, 16).ok()
}

impl Vault {
    /// Writes `receipt` and returns its id: a new row when `receipt.id` is
    /// empty, else the row it names, replaced. The same transaction drops up
    /// to 64 receipts older than [`MESH_PATH_RECEIPT_RETAIN_MS`].
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn record_mesh_path_receipt(&self, receipt: &MeshPathReceipt) -> Result<String> {
        let id = if receipt.id.is_empty() {
            format!(
                "{:016x}{}",
                receipt.opened_at_ms,
                self.store.clock.entity_id()?.to_hex()
            )
        } else {
            receipt.id.clone()
        };
        let mut row = receipt.clone();
        row.id.clone_from(&id);
        let cutoff = crate::unix_millis_now().saturating_sub(MESH_PATH_RECEIPT_RETAIN_MS);
        self.with_write_txn_grouped(|wtxn| {
            let expired = PATH_RECEIPTS
                .iter_from(&self.store, &*wtxn, &[])?
                .take(PRUNE_PER_WRITE)
                .map_while(|row| match row {
                    Ok((key, _)) if opened_at(&key).is_some_and(|at| at < cutoff) => Some(Ok(key)),
                    Ok(_) => None,
                    Err(error) => Some(Err(error)),
                })
                .collect::<Result<Vec<_>>>()?;
            for key in &expired {
                PATH_RECEIPTS.delete(&self.store, wtxn, key)?;
            }
            PATH_RECEIPTS.put(&self.store, wtxn, &id, &row)
        })?;
        Ok(id)
    }

    /// [`Self::record_mesh_path_receipt`] for a transport that never fails a
    /// connection over its receipt: one that does not land is logged and
    /// lost.
    pub fn leave_mesh_path_receipt(&self, receipt: &MeshPathReceipt) -> Option<String> {
        match self.record_mesh_path_receipt(receipt) {
            Ok(id) => Some(id),
            Err(error) => {
                tracing::warn!(%error, "mesh path receipt not written");
                None
            }
        }
    }

    /// The newest `limit` path receipts, newest first, and never more than
    /// [`MESH_PATH_RECEIPTS_READ_MAX`].
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn mesh_path_receipts(&self, limit: usize) -> Result<Vec<MeshPathReceipt>> {
        let txn = self.store.env.read_txn()?;
        PATH_RECEIPTS
            .iter_rev_from(&self.store, &txn, &[])?
            .take(limit.min(MESH_PATH_RECEIPTS_READ_MAX))
            .map(|row| row.map(|(_, receipt)| receipt))
            .collect()
    }
}
