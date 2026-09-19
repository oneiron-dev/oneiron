//! LMDB/session adapters for the read halves. No cursor opens a transaction.
use super::{EntityRecord, EntityStoreRead, PortRows, Transactions};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::store::ManifestDbs;
use crate::{
    EntityId, Vault,
    error::{Error, Result},
};
use heed::RoTxn;

impl<T: ManifestDbs> Transactions for T {
    type Read<'a> = heed::RoTxn<'a>;
    type Write<'a> = heed::RwTxn<'a>;
}
impl<T: ManifestDbs> EntityStoreRead for T {
    fn port_entity_records<'a>(
        &self,
        txn: &'a RoTxn<'_>,
    ) -> Result<PortRows<'a, (EntityId, EntityRecord)>> {
        Ok(Box::new(self.entities().iter(txn)?.map(|row| {
            let (key, value) = row?;
            let id = EntityId::from_bytes(
                key.as_ref()
                    .try_into()
                    .map_err(|_| Error::CorruptedIndex("entity key"))?,
            )?;
            Ok((id, decode_record(&value)?))
        })))
    }
    fn port_entity_count(&self, txn: &RoTxn<'_>) -> Result<u64> {
        self.entities().len(txn)
    }
    fn port_entity_ids_by_type_descending<'a>(
        &self,
        txn: &'a RoTxn<'_>,
        kind: u8,
    ) -> Result<PortRows<'a, EntityId>> {
        use std::ops::Bound;
        let start = [kind];
        let mut end = vec![kind];
        end.extend_from_slice(&[255; 16]);
        Ok(Box::new(
            self.type_index()
                .rev_range(
                    txn,
                    &(
                        Bound::Included(start.as_slice()),
                        Bound::Included(end.as_slice()),
                    ),
                )?
                .map(|row| crate::vault::entity_id_from_type_index_key(&row?.0)),
        ))
    }
    fn port_entity_long_spanning<'a>(
        &self,
        txn: &'a RoTxn<'_>,
        started_before: u64,
        ended_after: u64,
    ) -> Result<PortRows<'a, (EntityId, crate::TimeRange)>> {
        use std::ops::Bound;
        let mut lower = ended_after.to_be_bytes().to_vec();
        lower.extend_from_slice(&[255; 16]);
        let rows = self.temporal_long_intervals().range(
            txn,
            &(Bound::Excluded(lower.as_slice()), Bound::<&[u8]>::Unbounded),
        )?;
        Ok(Box::new(rows.filter_map(move |row| {
            let decoded = (|| {
                let (key, value) = row?;
                if key.len() != 24 || value.len() != 8 {
                    return Err(Error::CorruptedIndex("temporal long interval"));
                }
                let start = u64::from_be_bytes(
                    value
                        .as_ref()
                        .try_into()
                        .map_err(|_| Error::CorruptedIndex("interval start"))?,
                );
                let end = u64::from_be_bytes(
                    key[..8]
                        .try_into()
                        .map_err(|_| Error::CorruptedIndex("interval end"))?,
                );
                let id = EntityId::from_bytes(
                    key[8..]
                        .try_into()
                        .map_err(|_| Error::CorruptedIndex("interval id"))?,
                )?;
                Ok((id, crate::TimeRange { start, end }))
            })();
            match decoded {
                Ok((_, range)) if range.start >= started_before => None,
                other => Some(other),
            }
        })))
    }

    fn port_entity_timeline<'a>(
        &self,
        txn: &'a RoTxn<'_>,
        query: super::TimelineQuery,
    ) -> Result<PortRows<'a, super::EntityTime>> {
        super::lmdb_timeline::timeline(self, txn, query)
    }

    fn port_entity_record(&self, txn: &RoTxn<'_>, id: &EntityId) -> Result<Option<EntityRecord>> {
        self.entities()
            .get(txn, id.as_bytes())?
            .map(|raw| decode_record(&raw))
            .transpose()
    }
    fn port_entity_ids_by_type<'a>(
        &self,
        txn: &'a RoTxn<'_>,
        kind: u8,
        after: Option<EntityId>,
    ) -> Result<PortRows<'a, EntityId>> {
        use std::ops::Bound;
        let start = after.map_or_else(
            || vec![kind],
            |id| crate::store::Store::encode_type_key(kind, &id).to_vec(),
        );
        let lower = if after.is_some() {
            Bound::Excluded(start.as_slice())
        } else {
            Bound::Included(start.as_slice())
        };
        let rows = self
            .type_index()
            .range(txn, &(lower, Bound::<&[u8]>::Unbounded))?;
        Ok(Box::new(
            rows.take_while(move |row| {
                row.as_ref()
                    .map_or(true, |(key, _)| key.first() == Some(&kind))
            })
            .map(|row| {
                let (key, _) = row?;
                crate::vault::entity_id_from_type_index_key(&key)
            }),
        ))
    }
}
impl EntityStoreRead for Vault {
    fn port_entity_records<'a>(
        &self,
        txn: &'a RoTxn<'_>,
    ) -> Result<PortRows<'a, (EntityId, EntityRecord)>> {
        self.store.port_entity_records(txn)
    }
    fn port_entity_count(&self, txn: &RoTxn<'_>) -> Result<u64> {
        self.store.port_entity_count(txn)
    }
    fn port_entity_ids_by_type_descending<'a>(
        &self,
        txn: &'a RoTxn<'_>,
        kind: u8,
    ) -> Result<PortRows<'a, EntityId>> {
        self.store.port_entity_ids_by_type_descending(txn, kind)
    }
    fn port_entity_long_spanning<'a>(
        &self,
        txn: &'a RoTxn<'_>,
        started_before: u64,
        ended_after: u64,
    ) -> Result<PortRows<'a, (EntityId, crate::TimeRange)>> {
        self.store
            .port_entity_long_spanning(txn, started_before, ended_after)
    }

    fn port_entity_timeline<'a>(
        &self,
        txn: &'a RoTxn<'_>,
        query: super::TimelineQuery,
    ) -> Result<PortRows<'a, super::EntityTime>> {
        self.store.port_entity_timeline(txn, query)
    }

    fn port_entity_record(&self, txn: &RoTxn<'_>, id: &EntityId) -> Result<Option<EntityRecord>> {
        self.store.port_entity_record(txn, id)
    }
    fn port_entity_ids_by_type<'a>(
        &self,
        txn: &'a RoTxn<'_>,
        kind: u8,
        after: Option<EntityId>,
    ) -> Result<PortRows<'a, EntityId>> {
        self.store.port_entity_ids_by_type(txn, kind, after)
    }
}
pub(super) fn decode_record(raw: &[u8]) -> Result<EntityRecord> {
    let header = EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("entity header"))?;
    Ok(EntityRecord {
        entity_type: header.entity_type,
        occurred: crate::TimeRange {
            start: header.occurred_start,
            end: header.occurred_end,
        },
        learned_at: header.learned_at,
        body: raw[ENTITY_METADATA_HEADER_LEN..].to_vec(),
    })
}

impl<T: ManifestDbs> super::EdgeStoreRead for T {
    fn port_edge_cursor<'a>(
        &self,
        txn: &'a RoTxn<'_>,
        center: &EntityId,
        direction: super::EdgeDirection,
        after: Option<(u8, EntityId)>,
    ) -> Result<PortRows<'a, crate::edge::EdgeInfo>> {
        use std::ops::Bound;
        let prefix = center.as_bytes().to_vec();
        let mut start = prefix.clone();
        if let Some((kind, id)) = after {
            start.push(kind);
            start.extend_from_slice(id.as_bytes());
        }
        let lower = if after.is_some() {
            Bound::Excluded(start.as_slice())
        } else {
            Bound::Included(start.as_slice())
        };
        let mut streams: Vec<PortRows<'a, crate::edge::EdgeInfo>> = Vec::new();
        for (enabled, db) in [
            (direction != super::EdgeDirection::In, self.edges_out()),
            (direction != super::EdgeDirection::Out, self.edges_in()),
        ] {
            if !enabled {
                continue;
            }
            let prefix = prefix.clone();
            streams.push(Box::new(
                db.range(txn, &(lower, Bound::<&[u8]>::Unbounded))?
                    .take_while(move |row| {
                        row.as_ref()
                            .map_or(true, |(key, _)| key.starts_with(&prefix))
                    })
                    .map(|row| {
                        let (key, value) = row?;
                        Ok(crate::edge::parse_strict_edge_record(&key, &value)?.into_edge_info())
                    }),
            ));
        }
        Ok(Box::new(streams.into_iter().flatten()))
    }

    fn port_edge_consistent(
        &self,
        txn: &RoTxn<'_>,
        source: &EntityId,
        kind: crate::EdgeKind,
        target: &EntityId,
    ) -> Result<bool> {
        let out = self.edges_out().get(
            txn,
            &crate::store::Store::encode_edge_key(source, kind, target),
        )?;
        let incoming = self.edges_in().get(
            txn,
            &crate::store::Store::encode_edge_key(target, kind, source),
        )?;
        Ok(out == incoming)
    }

    fn port_edges<'a>(
        &self,
        txn: &'a RoTxn<'_>,
        center: &EntityId,
        direction: super::EdgeDirection,
        kind: Option<crate::EdgeKind>,
        after: Option<EntityId>,
    ) -> Result<PortRows<'a, crate::edge::EdgeInfo>> {
        use std::ops::Bound;
        let mut prefix = center.as_bytes().to_vec();
        if let Some(kind) = kind {
            prefix.push(kind as u8);
        }
        // A peer cursor is ordered only inside one kind. Reject ambiguous cursors.
        if after.is_some() && kind.is_none() {
            return Err(Error::InvalidConfig("edge cursor requires a kind".into()));
        }
        let mut start = prefix.clone();
        if let Some(id) = after {
            start.extend_from_slice(id.as_bytes());
        }
        let lower = if after.is_some() {
            Bound::Excluded(start.as_slice())
        } else {
            Bound::Included(start.as_slice())
        };
        let mut streams: Vec<PortRows<'a, crate::edge::EdgeInfo>> = Vec::new();
        for (enabled, db) in [
            (direction != super::EdgeDirection::In, self.edges_out()),
            (direction != super::EdgeDirection::Out, self.edges_in()),
        ] {
            if !enabled {
                continue;
            }
            let prefix = prefix.clone();
            let rows = db.range(txn, &(lower, Bound::<&[u8]>::Unbounded))?;
            streams.push(Box::new(
                rows.take_while(move |row| {
                    row.as_ref()
                        .map_or(true, |(key, _)| key.starts_with(&prefix))
                })
                .map(|row| {
                    let (key, value) = row?;
                    Ok(crate::edge::parse_strict_edge_record(&key, &value)?.into_edge_info())
                }),
            ));
        }
        Ok(Box::new(streams.into_iter().flatten()))
    }
    fn port_edge_get(
        &self,
        txn: &RoTxn<'_>,
        source: &EntityId,
        kind: crate::EdgeKind,
        target: &EntityId,
    ) -> Result<Option<crate::edge::EdgeInfo>> {
        let key = crate::store::Store::encode_edge_key(source, kind, target);
        self.edges_out()
            .get(txn, &key)?
            .map(|value| Ok(crate::edge::parse_strict_edge_record(&key, &value)?.into_edge_info()))
            .transpose()
    }
}
impl super::EdgeStoreRead for Vault {
    fn port_edge_cursor<'a>(
        &self,
        txn: &'a RoTxn<'_>,
        center: &EntityId,
        direction: super::EdgeDirection,
        after: Option<(u8, EntityId)>,
    ) -> Result<PortRows<'a, crate::edge::EdgeInfo>> {
        self.store.port_edge_cursor(txn, center, direction, after)
    }

    fn port_edge_consistent(
        &self,
        txn: &RoTxn<'_>,
        source: &EntityId,
        kind: crate::EdgeKind,
        target: &EntityId,
    ) -> Result<bool> {
        self.store.port_edge_consistent(txn, source, kind, target)
    }

    fn port_edges<'a>(
        &self,
        txn: &'a RoTxn<'_>,
        center: &EntityId,
        direction: super::EdgeDirection,
        kind: Option<crate::EdgeKind>,
        after: Option<EntityId>,
    ) -> Result<PortRows<'a, crate::edge::EdgeInfo>> {
        self.store.port_edges(txn, center, direction, kind, after)
    }
    fn port_edge_get(
        &self,
        txn: &RoTxn<'_>,
        source: &EntityId,
        kind: crate::EdgeKind,
        target: &EntityId,
    ) -> Result<Option<crate::edge::EdgeInfo>> {
        self.store.port_edge_get(txn, source, kind, target)
    }
}

impl<T: ManifestDbs> super::ShortIdStoreRead for T {
    fn port_short_id_reference(
        &self,
        txn: &RoTxn<'_>,
        id: &EntityId,
    ) -> Result<Option<(String, u8)>> {
        self.short_ids_reverse()
            .get(txn, id.as_bytes())?
            .map(|value| {
                crate::batch::parse_short_id_value(&value)
                    .map(|(name, hash)| (name.to_owned(), hash))
            })
            .transpose()
    }
}
impl super::ShortIdStoreRead for Vault {
    fn port_short_id_reference(
        &self,
        txn: &RoTxn<'_>,
        id: &EntityId,
    ) -> Result<Option<(String, u8)>> {
        super::ShortIdStoreRead::port_short_id_reference(&self.store, txn, id)
    }
}
