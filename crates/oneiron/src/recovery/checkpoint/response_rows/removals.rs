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
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    since: &BTreeSet<EntityId>,
) -> Result<()> {
    for id in since {
        crate::llm::erase_submissions_in_txn(store, wtxn, id)?;
        crate::saved_query::erase_memos_for_source_in_txn(store, wtxn, id)?;
        crate::memory::erase_birth_reply_assertions_in_txn(store, wtxn, id)?;
        crate::artifact_hosting::remove_blob_pointers_in_txn(store, wtxn, id)?;
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
            .try_for_each(|id| vault.halt_erased_pack_source_routes_in_txn(txn, id))
    })
}

impl SideRestoreSource<'_> {
    /// Every id this source has hard-erased, read now, so a side copy's
    /// sweep takes what it erased after the image's cut too (FIX 4753). A
    /// source whose markers do not read gives none, warned: the copy lands
    /// as it would without them.
    pub(in crate::recovery::checkpoint) fn erased_ids(&self) -> BTreeSet<EntityId> {
        let read = match &self.0 {
            Source::Open(vault) => crate::deletion::hard_erased_ids_in(vault),
            Source::Disk { dir, page_seal, .. } => {
                let prefix = crate::side_table::DELETION_HARD_DELETE_MARKER.prefix;
                crate::world_keys::read_sealed(dir, page_seal.as_ref(), || {
                    crate::store::read_existing_sync_state_rows(dir, &[prefix])
                })
                .map(|rows| {
                    // A key that spells no id names no erase.
                    rows.iter()
                        .filter_map(|(key, _)| {
                            let hex = std::str::from_utf8(key.strip_prefix(prefix)?).ok()?;
                            EntityId::from_hex(hex).ok()
                        })
                        .collect()
                })
            }
        };
        read.unwrap_or_else(|error| {
            tracing::warn!(
                kind = ?error.kind(),
                "a side restore's source erase markers did not read; the copy's sweep takes \
                 only those its image holds"
            );
            BTreeSet::new()
        })
    }
}
