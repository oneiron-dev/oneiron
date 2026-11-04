//! The policy manifest's fold of one committed snapshot, kept on the vault
//! between resolutions: a light recall resolves the manifest about a hundred
//! times, in snapshots no write has moved.

use std::sync::{Arc, Mutex};

use crate::error::Result;
use crate::gate::PolicyManifestResolution;

use super::{SessionStoreView, Store, StoreRead};

/// One committed snapshot's fold, under its LMDB transaction id. A read
/// transaction's id is the id of the write it sees, so every read of one
/// snapshot shares the entry, and the fold reads nothing but the snapshot
/// and pure decodes. Per vault, never process-wide: two vaults, or a
/// reopened environment, number their writes apart.
#[derive(Default)]
pub(crate) struct PolicyFoldCache(Mutex<Option<(usize, Arc<PolicyManifestResolution>)>>);

/// Where a write target keeps its policy fold: the vault's cache and the
/// environment its committed-snapshot probe opens in. A room's view reads
/// overlay ∪ base, and overlay writes move no LMDB id, so it has none.
pub(crate) trait PolicyFoldSource {
    fn policy_fold_cache(&self) -> Option<(&PolicyFoldCache, &heed::Env)>;
}

impl PolicyFoldSource for Store {
    fn policy_fold_cache(&self) -> Option<(&PolicyFoldCache, &heed::Env)> {
        Some((&self.core.policy_fold_cache, &*self.core.env))
    }
}

impl PolicyFoldSource for StoreRead<'_> {
    fn policy_fold_cache(&self) -> Option<(&PolicyFoldCache, &heed::Env)> {
        if self.is_union() {
            return None;
        }
        self.base.policy_fold_cache()
    }
}

impl PolicyFoldSource for SessionStoreView<'_> {
    fn policy_fold_cache(&self) -> Option<(&PolicyFoldCache, &heed::Env)> {
        None
    }
}

impl PolicyFoldCache {
    /// `fold`'s value for the snapshot `txn` reads: the kept one when the
    /// cache holds that snapshot, else `fold` run now.
    ///
    /// A write never reads or publishes here. Under the vault's write door it
    /// folds fresh outright. A write transaction's id is the one it will
    /// commit as, one past every committed snapshot a fold was kept for, and
    /// a fold is kept only when the probe shows `txn` reads the committed
    /// snapshot: so staged manifest rows and an aborted write's id (which the
    /// next write reuses) never publish and never match. A poisoned lock
    /// folds fresh.
    pub(crate) fn per_snapshot(
        &self,
        env: &heed::Env,
        txn: &heed::RoTxn<'_>,
        fold: impl FnOnce() -> Result<PolicyManifestResolution>,
    ) -> Result<Arc<PolicyManifestResolution>> {
        if crate::store::active_write_txn_depth() > 0 {
            return fold().map(Arc::new);
        }
        let id = txn.id();
        let hit = self.0.lock().ok().and_then(|slot| {
            slot.as_ref()
                .filter(|(kept_id, _)| *kept_id == id)
                .map(|(_, value)| Arc::clone(value))
        });
        if let Some(value) = hit {
            return Ok(value);
        }
        let value = Arc::new(fold()?);
        // A second read txn on this thread fails with MDB_BAD_RSLOT while
        // `txn` lives; probe on a separate thread, as the authority caches
        // do. It sees committed writes only.
        let committed = std::thread::scope(|scope| {
            scope
                .spawn(|| env.read_txn().ok().map(|committed| committed.id()))
                .join()
                .ok()
                .flatten()
        });
        if committed == Some(id)
            && let Ok(mut slot) = self.0.lock()
        {
            *slot = Some((id, Arc::clone(&value)));
        }
        Ok(value)
    }
}
