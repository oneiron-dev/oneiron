//! What an erase since a checkpoint's cut took from rows, taken again from
//! the rows a restore lands (FIX 10461, 10533, 10631, 10436). An image
//! binds each row-held response under its instance, and an erase retires
//! every instance its owner's obligations name, so those rows land erased
//! already. What no obligation names goes here, through the erase's own
//! erasers: a verdict memo whose sources are not known whole (any erase
//! takes it), a reply assertion row its key alone proves, a model step
//! submission an image carried unbound, and an erased blob's channel
//! pointers and serving descriptors. Only an erase counts: a delete keeps
//! every key, and the restore window with them (ARCH-0038 card A).

use std::collections::BTreeSet;

use heed::{RoTxn, RwTxn};

use super::super::{SideRestoreSource, Source};
use crate::ports::{DeletionMarker, TombstoneStoreRead};
use crate::store::Store;
use crate::{EntityId, Result};

/// The ids of `live`, the hard-erased ids of a restore's live source, whose
/// erase the restored rows in `txn` hold no marker of: those erased after
/// the image's cut.
pub(in crate::recovery::checkpoint) fn erased_since_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    live: &BTreeSet<EntityId>,
) -> Result<BTreeSet<EntityId>> {
    let mut since = BTreeSet::new();
    for id in live {
        if !store.port_deletion_marked(txn, DeletionMarker::HardDelete, id)? {
            since.insert(*id);
        }
    }
    Ok(since)
}

/// Runs each erase in `since` again over the restored rows in `wtxn`, the
/// restore's image-write transaction, once its rows and actor sweep landed.
pub(in crate::recovery::checkpoint) fn scrub_in_txn(
    write: &crate::secret_custody::CustodyWrite<'_>,
    wtxn: &mut RwTxn<'_>,
    since: &BTreeSet<EntityId>,
) -> Result<()> {
    let store = write.store;
    for id in since {
        crate::llm::erase_submissions_in_txn(store, wtxn, id)?;
        crate::saved_query::erase_memos_for_source_in_txn(store, wtxn, id)?;
        crate::memory::erase_birth_reply_assertions_in_txn(store, wtxn, id)?;
        // The whole blob-artifact teardown, not only its pointers, so the
        // restored copy releases the erased artifact's ASSETs as the erase
        // here did (FIX 11671). On an id no blob chain names it reads none
        // and removes only the pointers, as before.
        crate::blob_artifact::delete_blob_artifact_lifecycle_in_txn(
            store,
            wtxn,
            id,
            &|txn, id| crate::batch::deindex_entity(write, txn, id),
        )?;
    }
    Ok(())
}

/// On a side copy, once it opened: every catalog route bound to a pack
/// source its live source hard-erased halts, as that erase halted the
/// source's own (FIX 6034, 6086). The copy's install and route rows came
/// from its image or archive, so they still name the erased source. An id
/// that is no pack source, and that no install names, halts nothing.
pub(in crate::recovery::checkpoint) fn halt_erased_pack_routes(
    vault: &crate::Vault,
    erased: &BTreeSet<EntityId>,
) -> Result<()> {
    if erased.is_empty() {
        return Ok(());
    }
    vault.with_write_txn_grouped(|txn| {
        erased
            .iter()
            .try_for_each(|id| vault.halt_deleted_pack_source_routes_in_txn(txn, id))
    })
}

impl SideRestoreSource<'_> {
    pub(in crate::recovery::checkpoint) fn erased_ids(&self) -> BTreeSet<EntityId> {
        self.erasure_state().0
    }

    /// The source's hard IDs and known privacy information in the same read.
    pub(in crate::recovery::checkpoint) fn erasure_state(
        &self,
    ) -> (
        BTreeSet<EntityId>,
        std::collections::BTreeMap<EntityId, crate::deletion::TombstoneValueV2>,
    ) {
        let read = match &self.0 {
            Source::Open(vault) => (|| {
                let txn = vault.store.env.read_txn()?;
                Ok::<_, crate::Error>((
                    crate::ports::hard_erased_ids_in_txn(&vault.store, &txn)?,
                    crate::deletion::privacy_erasure_info_in_txn(&vault.store, &txn)?,
                ))
            })(),
            Source::Disk { dir, page_seal, .. } => {
                let prefix = crate::side_table::DELETION_HARD_DELETE_MARKER.prefix;
                crate::world_keys::read_sealed(dir, page_seal.as_ref(), || {
                    crate::store::read_existing_sync_state_rows(dir, &[prefix])
                })
                .map(|rows| {
                    let mut ids = BTreeSet::new();
                    let mut privacy = std::collections::BTreeMap::new();
                    for (key, value) in &rows {
                        let Some(id) = key
                            .strip_prefix(prefix)
                            .and_then(|key| std::str::from_utf8(key).ok())
                            .and_then(|hex| EntityId::from_hex(hex).ok())
                        else {
                            continue;
                        };
                        ids.insert(id);
                        if let Some(info) = crate::deletion::privacy_erasure_info(value) {
                            privacy.insert(id, info);
                        }
                    }
                    (ids, privacy)
                })
            }
        };
        read.unwrap_or_else(|error| {
            tracing::warn!(
                kind = ?error.kind(),
                "a side restore's source erase markers did not read; the copy's sweep takes \
                 only those its image holds"
            );
            (BTreeSet::new(), std::collections::BTreeMap::new())
        })
    }
}
