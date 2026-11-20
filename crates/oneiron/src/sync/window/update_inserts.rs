//! The entity ids a window update's history inserts (census L6-05, ARCH-0038
//! `#housekeeping-sla-open`). A late re-put of a row hard-deleted here can
//! arrive as history only: an update that inserts the row's body and deletes
//! it again leaves no live value for ingest to refuse, yet the stored update
//! holds the erased body, which only a compaction drops. So the writer that
//! makes an update durable owes the erasure sweep a compaction of its window,
//! in the same transaction, when an insert it carries names a row
//! hard-deleted here ([`UpdateInserts::owe_in_txn`]).

use std::collections::BTreeSet;

use loro::json::{JsonOpContent, MapOp};
use loro::{ContainerID, ContainerType, LoroDoc, VersionVector};

use super::super::types::WindowKey;
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;

/// The entity ids an update's history inserts into its window's entities
/// map: every insert, one a later operation of the same update deletes
/// included. Admission reads them for an update it admits
/// ([`super::admit_window_update_residence_with_vault`]).
#[derive(Debug, Default)]
pub struct UpdateInserts {
    ids: BTreeSet<EntityId>,
    /// The history was not read whole: the window owes a compaction as if
    /// an insert named a row hard-deleted here.
    unread: bool,
}

impl UpdateInserts {
    /// The inserts `ids`, read whole.
    pub(crate) fn of_ids(ids: BTreeSet<EntityId>) -> Self {
        Self { ids, unread: false }
    }

    /// The inserts of every operation `doc` holds past `base`: an update
    /// `doc` imported over `base`, and any operation it took meanwhile. An
    /// operation `doc` does not hold whole (below its shallow root) leaves
    /// them unread.
    pub(crate) fn past(doc: &LoroDoc, base: &VersionVector) -> Self {
        let end = doc.oplog_vv();
        let operations = doc.export_json_updates(base, &end);
        let expected = end.iter().try_fold(0_usize, |total, (peer, end)| {
            let start = base.get(peer).copied().unwrap_or(0).min(*end);
            let count = usize::try_from(end.checked_sub(start)?).ok()?;
            total.checked_add(count)
        });
        let read = operations
            .changes
            .iter()
            .flat_map(|change| &change.ops)
            .try_fold(0_usize, |total, op| total.checked_add(op.content.op_len()));
        let entities = ContainerID::new_root("entities", ContainerType::Map);
        let ids = operations
            .changes
            .iter()
            .flat_map(|change| &change.ops)
            .filter(|op| op.container == entities)
            .filter_map(|op| match &op.content {
                JsonOpContent::Map(MapOp::Insert { key, .. }) => EntityId::from_hex(key).ok(),
                _ => None,
            })
            .collect();
        Self {
            ids,
            unread: expected.is_none() || expected != read,
        }
    }

    /// The entity ids read: an own device's held burst names them as rows
    /// its bytes carry, so an erase of any scrubs them (#9226 review round
    /// 2). Admission reads them on the home window, where a delta that
    /// builds on the home's own operations applies.
    pub fn ids(&self) -> impl Iterator<Item = EntityId> + '_ {
        self.ids.iter().copied()
    }

    /// Owes the erasure sweep a compaction of window `key` in `wtxn`, the
    /// transaction that makes the update durable, when an insert names a row
    /// hard-deleted here (its permanent marker, read in `wtxn`) or the
    /// history was not read whole. A marker that cannot be read owes one too:
    /// a compaction too many costs one cut.
    ///
    /// # Errors
    ///
    /// Storage errors raising the owed row.
    pub(crate) fn owe_in_txn(
        &self,
        vault: &Vault,
        wtxn: &mut heed::RwTxn<'_>,
        key: &WindowKey,
    ) -> Result<()> {
        let txn: &heed::RoTxn<'_> = wtxn;
        let erased = self.unread
            || self.ids.iter().any(|id| {
                vault
                    .local_hard_delete_marker_exists_in_txn(txn, id)
                    .unwrap_or(true)
            });
        if !erased {
            return Ok(());
        }
        tracing::warn!(%key, "window update inserts a row hard-deleted here — compaction owed");
        crate::deletion::owed_window_compaction::owe_window_compaction_in_txn(vault, wtxn, key)
    }
}
