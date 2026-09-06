//! Bounded, local community snapshots in the existing `vault_meta` database.
//! Shared rows describe the canonical vault only. Actor-scoped and session
//! walks must not consume them: a filtered ranking cannot undo a hidden bridge.

use std::collections::BTreeSet;

use heed::{RoTxn, RwTxn};

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::edge::parse_strict_edge_record;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ppr::read_graph_version;
use crate::ppr_community::{
    CommunityEdge, CommunityGraphInput, CommunityMembership, CommunityRefreshReport,
    CommunitySnapshot, PPR_COMMUNITY_CACHE_PREFIX, PprCommunityConfig, compute_communities,
};
use crate::registry::ENTITY_TYPE_CLAIM;

use super::Store;

// Hard allocation/scan ceilings, not experimental ranking defaults. Fail closed
// before cloning a corrupt row or allocating an unbounded projection.
const MAX_COMMUNITY_NODES: usize = 100_000;
const MAX_COMMUNITY_EDGES: usize = 1_000_000;
const MAX_COMMUNITY_CACHE_BYTES: usize = 64 * 1024 * 1024;
const COMMUNITY_META_KEY: &[u8] = b"ppr_community_cache:v0:meta";

fn cache_error(_: crate::ppr_community::CommunityError) -> Error {
    Error::CorruptedIndex("ppr community cache")
}

impl Store {
    /// Loads and validates the complete family, including stale snapshots used
    /// as incremental-refresh input. A missing family is not a corrupt family.
    pub(crate) fn ppr_community_snapshot_in_txn(
        &self,
        txn: &RoTxn<'_>,
    ) -> Result<Option<CommunitySnapshot>> {
        let mut rows = Vec::new();
        let mut bytes = 0usize;
        for entry in self.vault_meta.prefix_iter(txn, PPR_COMMUNITY_CACHE_PREFIX.as_bytes())? {
            let (key, value) = entry?;
            bytes = bytes.checked_add(key.len()).and_then(|n| n.checked_add(value.len()))
                .ok_or(Error::CorruptedIndex("ppr community cache size"))?;
            if rows.len() > MAX_COMMUNITY_NODES * 3
                || bytes > MAX_COMMUNITY_CACHE_BYTES
                || key.len() > PPR_COMMUNITY_CACHE_PREFIX.len() + 8 + 32
                || value.len() > MAX_COMMUNITY_NODES * 16
            {
                return Err(Error::CorruptedIndex("ppr community cache bounds"));
            }
            rows.push((key.to_vec(), value.to_vec()));
        }
        if rows.is_empty() {
            return Ok(None);
        }
        let meta = rows.iter().find(|(key, _)| key.as_slice() == COMMUNITY_META_KEY)
            .map(|(_, value)| value)
            .ok_or(Error::CorruptedIndex("ppr community cache metadata"))?;
        let version = meta.get(1..9).and_then(|bytes| bytes.try_into().ok())
            .map(u64::from_le_bytes)
            .ok_or(Error::CorruptedIndex("ppr community cache metadata"))?;
        CommunitySnapshot::decode_rows(&rows, version, MAX_COMMUNITY_NODES)
            .map(Some).map_err(cache_error)
    }

    pub(crate) fn ppr_community_membership_in_txn(
        &self,
        txn: &RoTxn<'_>,
        entity: &EntityId,
    ) -> Result<Option<CommunityMembership>> {
        let Some(snapshot) = self.ppr_community_snapshot_in_txn(txn)? else {
            return Ok(None);
        };
        if snapshot.meta.graph_version != read_graph_version(self, txn)? {
            return Ok(None);
        }
        Ok(snapshot.nodes.get(entity).copied())
    }

    /// Validates before the first mutation. Replacement and its metadata commit
    /// together in the caller's transaction; unrelated `vault_meta` rows survive.
    pub(crate) fn replace_ppr_community_cache_in_txn(
        &self,
        txn: &mut RwTxn<'_>,
        snapshot: &CommunitySnapshot,
    ) -> Result<()> {
        snapshot.validate(read_graph_version(self, txn)?).map_err(cache_error)?;
        if snapshot.nodes.len() > MAX_COMMUNITY_NODES {
            return Err(Error::CorruptedIndex("ppr community cache bounds"));
        }
        let rows = snapshot.encode_rows().map_err(cache_error)?;
        let bytes = rows.iter().try_fold(0usize, |n, (key, value)| {
            n.checked_add(key.len()).and_then(|n| n.checked_add(value.len()))
        }).ok_or(Error::CorruptedIndex("ppr community cache size"))?;
        if bytes > MAX_COMMUNITY_CACHE_BYTES {
            return Err(Error::CorruptedIndex("ppr community cache bounds"));
        }
        let mut old_keys = Vec::new();
        for entry in self.vault_meta.prefix_iter(txn, PPR_COMMUNITY_CACHE_PREFIX.as_bytes())? {
            let (key, _) = entry?;
            if old_keys.len() > MAX_COMMUNITY_NODES * 3
                || key.len() > PPR_COMMUNITY_CACHE_PREFIX.len() + 8 + 32
            {
                return Err(Error::CorruptedIndex("ppr community cache bounds"));
            }
            old_keys.push(key.to_vec());
        }
        for key in old_keys {
            self.vault_meta.delete(txn, &key)?;
        }
        for (key, value) in rows {
            self.vault_meta.put(txn, &key, &value)?;
        }
        Ok(())
    }

    /// Materializes only live entity rows and edges with two live endpoints.
    /// Graph-only IDs do not inflate the graph-size safety denominator. Deleted
    /// shells, unpublished claims and lexical index side claims never connect
    /// communities. Every read (including deletion truth) uses this transaction.
    pub(crate) fn compute_ppr_communities_in_txn(
        &self,
        txn: &RoTxn<'_>,
        previous: Option<&CommunitySnapshot>,
        changed: &[EntityId],
        now: u64,
        config: &PprCommunityConfig,
    ) -> Result<(CommunitySnapshot, CommunityRefreshReport)> {
        crate::config::validate_ppr_community(config)?;
        let mut entities = BTreeSet::new();
        for (scanned, entry) in self.entities.iter(txn)?.enumerate() {
            if scanned >= MAX_COMMUNITY_NODES {
                return Err(Error::CorruptedIndex("ppr community graph bounds"));
            }
            let (key, raw) = entry?;
            let id = EntityId::from_bytes(key.as_ref().try_into()
                .map_err(|_| Error::CorruptedIndex("ppr community entity id"))?)?;
            let header = EntityMetadataHeader::parse(&raw)
                .ok_or(Error::CorruptedIndex("entity header"))?;
            if self.sync_state.get(txn, &crate::deletion::local_hard_delete_key(&id))?.is_some()
                || self.entity_deletion_present_in_txn(txn, &id, header.learned_at)?
            {
                continue;
            }
            if header.entity_type == ENTITY_TYPE_CLAIM {
                let body = crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
                if !crate::claim::claim_surfaceable(&body)
                    || body.predicate == crate::claim::PREDICATE_LEXICAL_QUERY_HINT
                {
                    continue;
                }
            }
            entities.insert(id);
        }
        let mut edges = Vec::new();
        // Scan outgoing rows once; reading the inverse index would double weight.
        for (scanned, entry) in self.edges_out.iter(txn)?.enumerate() {
            if scanned >= MAX_COMMUNITY_EDGES {
                return Err(Error::CorruptedIndex("ppr community graph bounds"));
            }
            let (key, value) = entry?;
            let edge = parse_strict_edge_record(&key, &value)?;
            if entities.contains(&edge.source) && entities.contains(&edge.target) {
                edges.push(CommunityEdge {
                    source: edge.source,
                    target: edge.target,
                    kind: edge.kind,
                    value: edge.decoded,
                    deleted: false,
                });
            }
        }
        let entities: Vec<_> = entities.into_iter().collect();
        compute_communities(
            &CommunityGraphInput {
                entities: &entities,
                edges: &edges,
                changed,
                graph_version: read_graph_version(self, txn)?,
            },
            previous,
            now,
            config,
        ).map_err(cache_error)
    }

    pub(crate) fn refresh_ppr_communities(
        &self,
        changed: &[EntityId],
        now: u64,
        config: &PprCommunityConfig,
    ) -> Result<CommunityRefreshReport> {
        crate::config::validate_ppr_community(config)?;
        let mut txn = self.env.write_txn()?;
        let previous = self.ppr_community_snapshot_in_txn(&txn)?;
        let (snapshot, report) = self.compute_ppr_communities_in_txn(
            &txn, previous.as_ref(), changed, now, config,
        )?;
        self.replace_ppr_community_cache_in_txn(&mut txn, &snapshot)?;
        txn.commit()?;
        Ok(report)
    }
}
