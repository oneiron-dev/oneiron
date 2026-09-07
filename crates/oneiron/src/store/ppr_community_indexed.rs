//! Indexed query validation is deliberately not whole-family validation. Read
//! the metadata and all selected coarse closures from the supplied transaction.
//! Unrelated corruption is detected by full load/refresh, not by a hot query.
//! No environment-latest identity or process state participates in correctness.

use std::collections::{BTreeMap, BTreeSet};

use heed::RoTxn;

use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ppr::read_graph_version;
use crate::ppr_community::{
    CommunityCacheMeta, CommunityId, CommunityMembership, CommunityQueryView,
    PPR_COMMUNITY_CACHE_PREFIX, decode_community_members,
};

use super::Store;
use super::ppr_community::{COMMUNITY_META_KEY, MAX_COMMUNITY_CACHE_BYTES, MAX_COMMUNITY_NODES};

#[cfg(test)]
thread_local! {
    static QUERY_READ_WORK: std::cell::Cell<(usize, usize)> = const { std::cell::Cell::new((0, 0)) };
}

pub(super) fn record_query_read(_bytes: usize) {
    #[cfg(test)]
    QUERY_READ_WORK.with(|work| {
        let (rows, bytes) = work.get();
        work.set((rows + 1, bytes + _bytes));
    });
}

fn corrupt() -> Error {
    Error::CorruptedIndex("ppr community cache")
}

/// Accounts bytes before decoding/allocating. Deduplication below ensures that
/// each node and member row is read at most once, even for overlapping seeds.
struct IndexedRows<'a, 'txn> {
    store: &'a Store,
    txn: &'a RoTxn<'txn>,
    bytes: usize,
}

impl IndexedRows<'_, '_> {
    fn get(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let value = self.store.vault_meta.get(self.txn, key)?;
        let bytes = key.len() + value.as_ref().map_or(0, |v| v.len());
        record_query_read(bytes);
        self.bytes = self.bytes.checked_add(bytes).ok_or_else(corrupt)?;
        if self.bytes > MAX_COMMUNITY_CACHE_BYTES
            || value.as_ref().is_some_and(|v| v.len() > MAX_COMMUNITY_NODES * 16)
        {
            return Err(corrupt());
        }
        Ok(value.map(|v| v.to_vec()))
    }

    fn node(&mut self, id: EntityId) -> Result<Option<CommunityMembership>> {
        self.get(format!("{PPR_COMMUNITY_CACHE_PREFIX}node:{}", id.to_hex()).as_bytes())?
            .map(|raw| CommunityMembership::decode_row(&raw).map_err(|_| corrupt()))
            .transpose()
    }

    fn members(&mut self, id: CommunityId, count: usize) -> Result<Vec<EntityId>> {
        let raw = self
            .get(format!("{PPR_COMMUNITY_CACHE_PREFIX}members:{}", id.to_hex()).as_bytes())?
            .ok_or_else(corrupt)?;
        decode_community_members(id, &raw, count).map_err(|_| corrupt())
    }
}

impl Store {
    #[cfg(test)]
    pub(crate) fn take_ppr_community_read_work(&self) -> (usize, usize) {
        QUERY_READ_WORK.with(|work| work.replace((0, 0)))
    }

    /// Validate metadata before choosing the current indexed path. Missing or
    /// stale metadata sends queries to the strict full-family refresh path.
    pub(crate) fn ppr_community_meta_in_txn(
        &self,
        txn: &RoTxn<'_>,
    ) -> Result<Option<(CommunityCacheMeta, usize)>> {
        let raw = self.vault_meta.get(txn, COMMUNITY_META_KEY)?;
        record_query_read(COMMUNITY_META_KEY.len() + raw.as_ref().map_or(0, |v| v.len()));
        raw.map(|v| CommunityCacheMeta::decode_row(&v, MAX_COMMUNITY_NODES).map_err(|_| corrupt()))
            .transpose()
    }

    pub(crate) fn ppr_community_query_view_in_txn(
        &self,
        txn: &RoTxn<'_>,
        selected: &BTreeSet<EntityId>,
    ) -> Result<CommunityQueryView> {
        let (meta, graph_size) = self.ppr_community_meta_in_txn(txn)?.ok_or_else(corrupt)?;
        if meta.graph_version != read_graph_version(self, txn)?
            || selected.len() > MAX_COMMUNITY_NODES
        {
            return Err(corrupt());
        }
        let mut rows = IndexedRows {
            store: self,
            txn,
            bytes: 0,
        };
        let mut nodes = BTreeMap::new();
        let mut absent = BTreeSet::new();
        let mut coarse_ids = BTreeSet::new();
        for &id in selected {
            if let Some(m) = rows.node(id)? {
                nodes.insert(id, m);
                coarse_ids.insert(m.coarse);
            } else {
                // A current snapshot covers every canonical live entity. A
                // graph-only ID may be absent; a missing live node is torn even
                // when its orphaned singleton members row is not discoverable.
                if let Some(raw) = self.entities.get(txn, id.as_bytes())?
                    && self.ppr_community_live_entity_in_txn(txn, &id, &raw)?
                {
                    return Err(corrupt());
                }
                absent.insert(id);
            }
        }
        let mut all_members = BTreeMap::new();
        let mut parents = BTreeMap::new();
        for coarse in coarse_ids {
            // Validate the whole accessed coarse row, its node backlinks and
            // every fine group in it. Do not follow inconsistent pointers into
            // other communities: they are corruption, not an expansion request.
            let members = rows.members(coarse, graph_size)?;
            let mut fine_groups: BTreeMap<CommunityId, Vec<EntityId>> = BTreeMap::new();
            for &id in &members {
                if absent.contains(&id) {
                    return Err(corrupt());
                }
                let m = if let Some(&m) = nodes.get(&id) {
                    m
                } else {
                    let m = rows.node(id)?.ok_or_else(corrupt)?;
                    nodes.insert(id, m);
                    m
                };
                if m.coarse != coarse || nodes.len() > graph_size {
                    return Err(corrupt());
                }
                if parents.insert(m.fine, coarse).is_some_and(|old| old != coarse) {
                    return Err(corrupt());
                }
                fine_groups.entry(m.fine).or_default().push(id);
            }
            if all_members.insert(coarse, members).is_some() {
                return Err(corrupt());
            }
            for (fine, expected) in fine_groups {
                if let std::collections::btree_map::Entry::Vacant(entry) = all_members.entry(fine) {
                    entry.insert(rows.members(fine, graph_size)?);
                }
                if all_members[&fine] != expected {
                    return Err(corrupt());
                }
            }
        }
        // A selected node pointing at a valid but unrelated community must not
        // silently disappear from that community's backlinks.
        for (&id, m) in &nodes {
            if [m.fine, m.coarse].iter().any(|c| {
                all_members.get(c).is_none_or(|members| members.binary_search(&id).is_err())
            }) {
                return Err(corrupt());
            }
        }
        nodes.retain(|id, _| selected.contains(id));
        let sizes = nodes
            .values()
            .flat_map(|m| [m.fine, m.coarse])
            .map(|id| (id, all_members[&id].len()))
            .collect();
        Ok(CommunityQueryView {
            nodes,
            sizes,
            graph_size,
        })
    }
}
