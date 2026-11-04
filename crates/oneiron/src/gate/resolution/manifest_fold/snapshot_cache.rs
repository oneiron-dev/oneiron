//! The policy manifest resolved once per committed snapshot: the fold is a
//! pure function of the snapshot it reads, so every read of one snapshot
//! shares the vault's kept fold (L01 04:13, L02 04:12).

use std::sync::Arc;

use super::*;

/// The policy manifest `txn` resolves to, owned.
pub(crate) fn resolve_policy_manifest(
    store: &impl crate::store::ManifestDbs,
    txn: &heed::RoTxn<'_>,
) -> Result<PolicyManifestResolution> {
    resolve_policy_manifest_shared(store, txn).map(Arc::unwrap_or_clone)
}

/// The policy manifest `txn` resolves to: the vault's kept fold of the
/// committed snapshot `txn` reads, else a fold now. A room's view and a
/// write fold fresh, so a staged manifest row is always seen.
///
/// A fold's only effect beyond its value is a scan check it parks when a
/// scan reads past its threshold row. That check is the snapshot's (its
/// rows and threshold are the snapshot's), the first fold of each snapshot
/// still parks it, and it leaves the waiting map only once a write keeps it,
/// which moves the snapshot.
pub(crate) fn resolve_policy_manifest_shared(
    store: &impl crate::store::ManifestDbs,
    txn: &heed::RoTxn<'_>,
) -> Result<Arc<PolicyManifestResolution>> {
    let fold = || super::fold::fold_policy_manifest(store, txn);
    match store.policy_fold_cache() {
        Some((cache, env)) => cache.per_snapshot(env, txn, fold),
        None => fold().map(Arc::new),
    }
}
