//! LMDB entity, edge and place adapters. Reads share the caller's snapshot.
use super::*;

use crate::edge::EdgeInfo;
use crate::error::{Error, Result};
use crate::registry::*;
use crate::store::{ManifestDbs, Store};
use crate::{EdgeKind, EntityId, Vault};
use heed::{RoTxn, RwTxn};
use std::collections::BTreeSet;

impl EntityStore for Vault {
    fn port_entity_get(&self, txn: &RoTxn<'_>, id: &EntityId) -> Result<Option<EntityRecord>> {
        let Some(mut row) = self.port_entity_record(txn, id)? else {
            return Ok(None);
        };
        if row.entity_type == ENTITY_TYPE_SECRET_CUSTODY {
            return Err(crate::secret_custody::reject_secret_custody_byte());
        }
        if self.port_tombstone_is_deleted(txn, id)? || stale_in_txn(&self.store, txn, id)? {
            return Ok(None);
        }
        if super::safe_read::body_is_stale(&row.body) {
            return Ok(None);
        }
        #[cfg(feature = "sync")]
        if crate::entity_doc::has_record_head(&self.store, txn, id)? {
            if row.entity_type == ENTITY_TYPE_NOTE {
                crate::note::ensure_citations_ready(&self.store, txn, *id)?;
            }
            row.body = crate::entity_doc::resolve_record_body(&self.store, txn, id, &row.body)?;
            return Ok(Some(row));
        }
        row.body = crate::note::live_body_in_txn(&self.store, txn, id, row.entity_type, &row.body)?
            .into_owned();
        Ok(Some(row))
    }
    fn port_entity_put(
        &self,
        txn: &mut RwTxn<'_>,
        id: &EntityId,
        row: &EntityRecord,
    ) -> Result<()> {
        self.batch_in()
            .put(id, row.entity_type, row.occurred, row.learned_at, &row.body)
            .apply(txn)
    }
    fn port_entity_delete(&self, txn: &mut RwTxn<'_>, id: &EntityId) -> Result<bool> {
        // The public delete facade still owns publish/receipt/sweep ordering.
        let (existed, vector, graph, neighbors) =
            crate::batch::deindex_entity(&self.store, txn, id)?;
        crate::ppr::invalidate_ppr_for_delete(&self.store, txn, id, &neighbors)?;
        if vector {
            crate::hnsw::increment_vector_version(&self.store, txn)?;
        }
        if graph {
            crate::ppr::increment_graph_version(&self.store, txn)?;
        }
        Ok(existed)
    }
    fn port_list_turns_by_session(
        &self,
        txn: &RoTxn<'_>,
        session: &EntityId,
    ) -> Result<Vec<EntityId>> {
        let mut result = Vec::new();
        let prefix = [b"session_turns:v1:".as_slice(), session.as_bytes()].concat();
        for (scanned, row) in self.store.vault_meta.prefix_iter(txn, &prefix)?.enumerate() {
            if scanned >= 100_000 {
                return Err(Error::IndexOverflow("session turns index"));
            }
            let (key, value) = row?;
            let id = key
                .get(prefix.len()..)
                .and_then(|bytes| <[u8; 16]>::try_from(bytes).ok())
                .ok_or(Error::CorruptedIndex("session turns index"))?;
            let id = EntityId::from_bytes(id)?;
            if value.as_ref() != [1] {
                return Err(Error::CorruptedIndex("session turns index"));
            }
            if self
                .port_entity_get(txn, &id)?
                .is_none_or(|row| row.entity_type != ENTITY_TYPE_TURN)
            {
                continue;
            }
            if crate::compaction::turn_session_membership_in_txn(&self.store, txn, &id)?
                != Some(*session)
            {
                return Err(Error::CorruptedIndex("session turns index"));
            }
            result.push(id);
        }
        Ok(result)
    }
    fn port_list_sessions_by_relationship(
        &self,
        txn: &RoTxn<'_>,
        relationship: &EntityId,
    ) -> Result<Vec<EntityId>> {
        indexed_entities(self, txn, ENTITY_TYPE_SESSION, relationship.as_bytes())
    }
    fn port_list_summaries_by_level(&self, txn: &RoTxn<'_>, level: u64) -> Result<Vec<EntityId>> {
        indexed_entities(self, txn, ENTITY_TYPE_SUMMARY, &level.to_be_bytes())
    }
    fn port_list_assets_by_relationship(
        &self,
        txn: &RoTxn<'_>,
        relationship: &EntityId,
    ) -> Result<Vec<EntityId>> {
        indexed_entities(self, txn, ENTITY_TYPE_ASSET, relationship.as_bytes())
    }
}
pub(super) fn type_ids(vault: &Vault, txn: &RoTxn<'_>, kind: u8) -> Result<Vec<EntityId>> {
    let mut ids = Vec::new();
    for row in vault.store.type_index.prefix_iter(txn, &[kind])? {
        if ids.len() >= 100_000 {
            return Err(Error::IndexOverflow("port type index"));
        }
        let (key, _) = row?;
        ids.push(crate::vault::entity_id_from_type_index_key(&key)?);
    }
    Ok(ids)
}
pub(super) fn field<'a>(body: &'a rmpv::Value, name: &str) -> Option<&'a rmpv::Value> {
    body.as_map()?
        .iter()
        .find(|(key, _)| key.as_str() == Some(name))
        .map(|(_, v)| v)
}
fn query_prefix(kind: u8, selector: &[u8]) -> Vec<u8> {
    [b"named_entity:v1:".as_slice(), &[kind], selector].concat()
}

fn query_prefixes(kind: u8, data: &[u8]) -> BTreeSet<Vec<u8>> {
    if !matches!(
        kind,
        ENTITY_TYPE_SESSION | ENTITY_TYPE_ASSET | ENTITY_TYPE_SUMMARY
    ) {
        return BTreeSet::new();
    }
    let Ok(body) = rmpv::decode::read_value(&mut std::io::Cursor::new(data)) else {
        return BTreeSet::new();
    };
    if kind == ENTITY_TYPE_SUMMARY {
        return field(&body, "level")
            .and_then(rmpv::Value::as_u64)
            .map(|level| query_prefix(kind, &level.to_be_bytes()))
            .into_iter()
            .collect();
    }
    ["rel", "relationship", "relationshipId"]
        .into_iter()
        .filter_map(|name| match field(&body, name) {
            Some(rmpv::Value::Binary(bytes)) if bytes.len() == 16 => {
                Some(query_prefix(kind, bytes))
            }
            _ => None,
        })
        .collect()
}

pub(crate) fn reindex_named_entities(
    store: &impl ManifestDbs,
    txn: &mut RwTxn<'_>,
    id: &EntityId,
    replacement: Option<(u8, &[u8])>,
) -> Result<()> {
    let prior = store.entities().get(txn, id.as_bytes())?;
    let old = prior.as_ref().and_then(|raw| {
        let header = crate::batch::EntityMetadataHeader::parse(raw)?;
        let body = raw.get(crate::batch::ENTITY_METADATA_HEADER_LEN..)?;
        Some(query_prefixes(header.entity_type, body))
    });
    for mut prefix in old.into_iter().flatten() {
        prefix.extend_from_slice(id.as_bytes());
        store.vault_meta().delete(txn, &prefix)?;
    }
    if let Some((kind, body)) = replacement {
        for mut prefix in query_prefixes(kind, body) {
            prefix.extend_from_slice(id.as_bytes());
            store.vault_meta().put(txn, &prefix, &[])?;
        }
    }
    Ok(())
}

fn indexed_entities(
    vault: &Vault,
    txn: &RoTxn<'_>,
    kind: u8,
    selector: &[u8],
) -> Result<Vec<EntityId>> {
    let prefix = query_prefix(kind, selector);
    let mut ids = Vec::new();
    for (scanned, row) in vault
        .store
        .vault_meta
        .prefix_iter(txn, &prefix)?
        .enumerate()
    {
        if scanned >= 100_000 {
            return Err(Error::IndexOverflow("named entity query index"));
        }
        let (key, value) = row?;
        let bytes = key
            .get(prefix.len()..)
            .and_then(|bytes| <[u8; 16]>::try_from(bytes).ok())
            .ok_or(Error::CorruptedIndex("named entity query index"))?;
        if !value.is_empty() {
            return Err(Error::CorruptedIndex("named entity query index"));
        }
        let id = EntityId::from_bytes(bytes)?;
        let Some(row) = vault.port_entity_get(txn, &id)? else {
            continue;
        };
        if row.entity_type != kind || !query_prefixes(kind, &row.body).contains(&prefix) {
            return Err(Error::CorruptedIndex("named entity query index"));
        }
        ids.push(id);
    }
    Ok(ids)
}
impl EdgeStore for Vault {
    fn port_edge_upsert(
        &self,
        txn: &mut RwTxn<'_>,
        src: &EntityId,
        kind: EdgeKind,
        dst: &EntityId,
        weight: f32,
    ) -> Result<()> {
        self.batch_in().edge(src, kind, dst, weight).apply(txn)
    }
    fn port_edge_mark_stale(
        &self,
        txn: &mut RwTxn<'_>,
        src: &EntityId,
        kind: EdgeKind,
        dst: &EntityId,
    ) -> Result<bool> {
        // A stale edge is excluded from both graph directions, not a zero-weight ghost.
        self.port_edge_delete(txn, src, kind, dst)
    }
    fn port_edge_delete(
        &self,
        txn: &mut RwTxn<'_>,
        src: &EntityId,
        kind: EdgeKind,
        dst: &EntityId,
    ) -> Result<bool> {
        crate::edge::validate_public_edge_kind(kind)?;
        let out = Store::encode_edge_key(src, kind, dst);
        let incoming = Store::encode_edge_key(dst, kind, src);
        let existed = self.store.edges_out.delete(txn, &out)?;
        self.store.edges_in.delete(txn, &incoming)?;
        if existed {
            crate::ppr::invalidate_ppr_for_edge(&self.store, txn, src, dst)?;
            crate::ppr::increment_graph_version(&self.store, txn)?;
        }
        Ok(existed)
    }
    fn port_edge_neighbors(
        &self,
        txn: &RoTxn<'_>,
        id: &EntityId,
        direction: EdgeDirection,
        kind: Option<EdgeKind>,
        limit: usize,
    ) -> Result<Vec<EdgeInfo>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let mut result = Vec::new();
        for (scanned, row) in self.port_edges(txn, id, direction, kind, None)?.enumerate() {
            if scanned >= 100_000 {
                return Err(Error::IndexOverflow("edge neighbors"));
            }
            if result.len() >= limit {
                break;
            }
            result.push(row?);
        }
        Ok(result)
    }
    fn port_edge_list_by_dst(
        &self,
        txn: &RoTxn<'_>,
        id: &EntityId,
        kind: Option<EdgeKind>,
        after: Option<&EntityId>,
        limit: usize,
    ) -> Result<Vec<EntityId>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let mut result = Vec::new();
        // With a kind the adapter seeks straight to the exclusive peer cursor.
        if kind.is_some() {
            for row in self
                .port_edges(txn, id, EdgeDirection::In, kind, after.copied())?
                .take(limit.min(100_000))
            {
                result.push(row?.target);
            }
        } else {
            let mut peers = std::collections::BTreeSet::new();
            for (scanned, row) in self
                .port_edges(txn, id, EdgeDirection::In, None, None)?
                .enumerate()
            {
                if scanned >= 100_000 {
                    return Err(Error::IndexOverflow("edge neighbors"));
                }
                let peer = row?.target;
                if after.is_none_or(|after| peer > *after) {
                    peers.insert(peer);
                }
            }
            result.extend(peers.into_iter().take(limit));
        }
        Ok(result)
    }
}
fn matching_bodies(
    vault: &Vault,
    txn: &RoTxn<'_>,
    kind: u8,
    matches: impl Fn(&rmpv::Value) -> bool,
) -> Result<Vec<EntityId>> {
    let mut ids = Vec::new();
    for id in type_ids(vault, txn, kind)? {
        let Some(row) = vault.port_entity_get(txn, &id)? else {
            continue;
        };
        let body = rmpv::decode::read_value(&mut std::io::Cursor::new(row.body))
            .map_err(|_| Error::CorruptedIndex("named entity query body"))?;
        if matches(&body) {
            ids.push(id);
        }
    }
    Ok(ids)
}
impl PlaceStore for Vault {
    fn port_place_get(&self, txn: &RoTxn<'_>, id: &EntityId) -> Result<Option<EntityRecord>> {
        let row = self.port_entity_get(txn, id)?;
        if row
            .as_ref()
            .is_some_and(|row| row.entity_type != ENTITY_TYPE_PLACE)
        {
            return Err(Error::CorruptedIndex("place type"));
        }
        Ok(row)
    }
    fn port_place_put(&self, txn: &mut RwTxn<'_>, id: &EntityId, row: &EntityRecord) -> Result<()> {
        if row.entity_type != ENTITY_TYPE_PLACE {
            return Err(Error::InvalidConfig("place type".into()));
        }
        self.port_entity_put(txn, id, row)
    }
    fn port_place_find_by_provider_id(
        &self,
        txn: &RoTxn<'_>,
        provider: &str,
        provider_id: &str,
    ) -> Result<Vec<EntityId>> {
        matching_bodies(self, txn, ENTITY_TYPE_PLACE, |body| {
            field(body, "provider").and_then(rmpv::Value::as_str) == Some(provider)
                && field(body, "providerId").and_then(rmpv::Value::as_str) == Some(provider_id)
        })
    }
    fn port_place_find_by_name(&self, txn: &RoTxn<'_>, name: &str) -> Result<Vec<EntityId>> {
        matching_bodies(self, txn, ENTITY_TYPE_PLACE, |body| {
            field(body, "name").and_then(rmpv::Value::as_str) == Some(name)
        })
    }
    fn port_place_list_children(&self, txn: &RoTxn<'_>, id: &EntityId) -> Result<Vec<EntityId>> {
        let mut result = Vec::new();
        for peer in self.port_edge_list_by_dst(txn, id, Some(EdgeKind::ChildOf), None, 100_000)? {
            if self
                .port_entity_get(txn, &peer)?
                .is_some_and(|r| r.entity_type == ENTITY_TYPE_PLACE)
            {
                result.push(peer);
            }
        }
        Ok(result)
    }
}
