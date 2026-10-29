//! A catalog connector's route halts wherever the pack install it is bound
//! to leaves the vault, in the transaction that takes it out: the owner's
//! removal (`removal.rs`, FIX 5941), a delete or erase of the pack's source, and a
//! restore over a live vault whose image does not hold the live install
//! (FIX 6034). Each runs [`Vault::halt_pack_connector_routes_in_txn`].
use std::collections::{BTreeMap, BTreeSet};

use super::admission::PACK_INSTALL;
use crate::{EntityId, Vault, error::Result};

/// Each installed pack's source and content hash, by pack name.
pub(crate) type InstalledPackSources = BTreeMap<String, (String, String)>;

impl Vault {
    /// The packs installed here, by name. A receipt that does not decode
    /// names no source and is passed over.
    pub(crate) fn installed_pack_sources(&self) -> Result<InstalledPackSources> {
        let txn = self.store.env.read_txn()?;
        Ok(PACK_INSTALL
            .iter_from(&self.store, &txn, &[])?
            .filter_map(Result::ok)
            .map(|(name, receipt)| (name, (receipt.source_id, receipt.content_hash)))
            .collect())
    }

    /// After a restore over a live vault that held `before`, on the restored
    /// vault: an install its rows no longer hold halts its routes as the
    /// owner's removal does, and one they hold at another source or hash as
    /// an update does. A restored receipt that does not decode holds none.
    pub(crate) fn halt_departed_pack_routes(
        &self,
        before: &InstalledPackSources,
        at: u64,
    ) -> Result<()> {
        if before.is_empty() {
            return Ok(());
        }
        self.with_write_txn_grouped(|txn| {
            for (name, (source, hash)) in before {
                match PACK_INSTALL.get(&self.store, txn, name).ok().flatten() {
                    None => self.halt_pack_connector_routes_in_txn(txn, source, hash, at)?,
                    Some(kept) if kept.source_id != *source || kept.content_hash != *hash => {
                        self.follow_updated_pack_connector_routes_in_txn(
                            txn, source, hash, &kept, at,
                        )?;
                    }
                    Some(_) => {}
                }
            }
            Ok(())
        })
    }

    /// The delete or erase of `id`, in its transaction, before its body is
    /// scrubbed: when `id` is a pack source, every catalog route bound to it
    /// halts as the owner's removal halts it, at its own content hash and at
    /// each an install naming it holds (FIX 6034; a plain delete too, FIX
    /// 6086). Any other row halts nothing.
    pub(crate) fn halt_deleted_pack_source_routes_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        id: &EntityId,
    ) -> Result<()> {
        let source_ref = id.to_hex();
        let mut hashes = BTreeSet::new();
        if let Ok(Some(source)) = self.pack_source_in_txn(txn, id) {
            hashes.insert(source.content_hash().to_hex());
        }
        let installed: Vec<_> = PACK_INSTALL
            .iter_from(&self.store, txn, &[])?
            .filter_map(Result::ok)
            .collect();
        for (_, receipt) in installed {
            if receipt.source_id == source_ref {
                hashes.insert(receipt.content_hash);
            }
        }
        let at = crate::unix_seconds_now();
        for hash in hashes {
            self.halt_pack_connector_routes_in_txn(txn, &source_ref, &hash, at)?;
        }
        Ok(())
    }
}
