//! LMDB entity, edge and place adapters. Reads share the caller's snapshot.
use super::*;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::edge::EdgeInfo;
use crate::error::{Error, Result};
use crate::registry::*;
use crate::store::Store;
use crate::{EdgeKind, EntityId, Vault};
use heed::{RoTxn, RwTxn};

impl EntityStore for Vault {
    fn port_entity_get(&self, txn: &RoTxn<'_>, id: &EntityId) -> Result<Option<EntityRecord>> {
        let Some(raw) = self.store.entities.get(txn, id.as_bytes())? else {
            return Ok(None);
        };
        let h = EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if h.entity_type == ENTITY_TYPE_SECRET_CUSTODY {
            return Err(crate::secret_custody::reject_secret_custody_byte());
        }
        if self.port_tombstone_is_deleted(txn, id)? || stale_in_txn(&self.store, txn, id)? {
            return Ok(None);
        }
        Ok(Some(EntityRecord {
            entity_type: h.entity_type,
            occurred: crate::TimeRange {
                start: h.occurred_start,
                end: h.occurred_end,
            },
            learned_at: h.learned_at,
            body: raw[ENTITY_METADATA_HEADER_LEN..].to_vec(),
        }))
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
        for id in type_ids(self, txn, ENTITY_TYPE_TURN)? {
            if self.port_entity_get(txn, &id)?.is_some()
                && crate::compaction::turn_session_membership_in_txn(&self.store, txn, &id)?
                    == Some(*session)
            {
                result.push(id);
            }
        }
        Ok(result)
    }
    fn port_list_sessions_by_relationship(
        &self,
        txn: &RoTxn<'_>,
        relationship: &EntityId,
    ) -> Result<Vec<EntityId>> {
        related_entities(self, txn, relationship, ENTITY_TYPE_SESSION)
    }
    fn port_list_summaries_by_level(&self, txn: &RoTxn<'_>, level: u64) -> Result<Vec<EntityId>> {
        matching_bodies(self, txn, ENTITY_TYPE_SUMMARY, |body| {
            field(body, "level").and_then(rmpv::Value::as_u64) == Some(level)
        })
    }
    fn port_list_assets_by_relationship(
        &self,
        txn: &RoTxn<'_>,
        relationship: &EntityId,
    ) -> Result<Vec<EntityId>> {
        related_entities(self, txn, relationship, ENTITY_TYPE_ASSET)
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
fn related_entities(
    vault: &Vault,
    txn: &RoTxn<'_>,
    relationship: &EntityId,
    kind: u8,
) -> Result<Vec<EntityId>> {
    matching_bodies(vault, txn, kind, |body| {
        ["rel", "relationship", "relationshipId"]
            .iter()
            .any(|key| match field(body, key) {
                Some(rmpv::Value::Binary(value)) => value.as_slice() == relationship.as_bytes(),
                _ => false,
            })
    })
}
pub(super) fn field<'a>(body: &'a rmpv::Value, name: &str) -> Option<&'a rmpv::Value> {
    body.as_map()?
        .iter()
        .find(|(key, _)| key.as_str() == Some(name))
        .map(|(_, v)| v)
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
        let mut scanned = 0;
        for (enabled, db) in [
            (direction != EdgeDirection::In, &self.store.edges_out),
            (direction != EdgeDirection::Out, &self.store.edges_in),
        ] {
            if !enabled {
                continue;
            }
            let mut prefix = id.as_bytes().to_vec();
            if let Some(kind) = kind {
                prefix.push(kind as u8);
            }
            for row in db.prefix_iter(txn, &prefix)? {
                scanned += 1;
                if scanned > 100_000 {
                    return Err(Error::IndexOverflow("edge neighbors"));
                }
                let (key, value) = row?;
                result.push(crate::edge::parse_strict_edge_record(&key, &value)?.into_edge_info());
                if result.len() >= limit {
                    return Ok(result);
                }
            }
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
        let mut ids: Vec<_> = self
            .port_edge_neighbors(txn, id, EdgeDirection::In, kind, 100_000)?
            .into_iter()
            .map(|edge| edge.target)
            .filter(|id| after.is_none_or(|after| id > after))
            .collect();
        ids.sort();
        ids.dedup();
        ids.truncate(limit);
        Ok(ids)
    }
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
