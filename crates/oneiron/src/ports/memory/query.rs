//! Memory implementation of the same lazy read contracts as LMDB.
use super::*;
impl EntityStoreRead for Memory {
    fn port_entity_raw(&self, txn: &Snapshot, id: &EntityId) -> Result<Option<Vec<u8>>> {
        Ok(txn.entities.get(id).map(EntityRecord::encode))
    }
    fn port_entity_records<'a>(
        &self,
        txn: &'a Snapshot,
    ) -> Result<PortRows<'a, (EntityId, EntityRecord)>> {
        Ok(Box::new(
            txn.entities.iter().map(|(id, row)| Ok((*id, row.clone()))),
        ))
    }
    fn port_entity_count(&self, txn: &Snapshot) -> Result<u64> {
        Ok(txn.entities.len() as u64)
    }
    fn port_entity_ids_by_type_descending<'a>(
        &self,
        txn: &'a Snapshot,
        kind: u8,
    ) -> Result<PortRows<'a, EntityId>> {
        Ok(Box::new(
            txn.entities
                .iter()
                .rev()
                .filter(move |(_, row)| row.entity_type == kind)
                .map(|(id, _)| Ok(*id)),
        ))
    }
    fn port_entity_long_spanning<'a>(
        &self,
        txn: &'a Snapshot,
        started_before: u64,
        ended_after: u64,
    ) -> Result<PortRows<'a, (EntityId, crate::TimeRange)>> {
        let q = TimelineQuery {
            axis: TimeAxis::OccurredEnd,
            start: std::ops::Bound::Excluded(ended_after),
            ..Default::default()
        };
        Ok(Box::new(self.port_entity_timeline(txn, q)?.filter_map(
            move |row| match row {
                Err(error) => Some(Err(error)),
                Ok(time) => {
                    let row = &txn.entities[&time.id];
                    (row.occurred.start < started_before
                        && row.occurred.end.saturating_sub(row.occurred.start)
                            > crate::batch::LONG_INTERVAL_THRESHOLD_SECS)
                        .then_some(Ok((time.id, row.occurred)))
                }
            },
        )))
    }

    fn port_entity_timeline<'a>(
        &self,
        txn: &'a Snapshot,
        q: TimelineQuery,
    ) -> Result<PortRows<'a, EntityTime>> {
        use std::ops::Bound;
        let mut cursor = q.after;
        let mut exhausted = false;
        Ok(Box::new(std::iter::from_fn(move || {
            if exhausted {
                return None;
            }
            let rows = txn
                .entities
                .iter()
                .filter(|(_, row)| {
                    q.axis != TimeAxis::OccurredEnd || row.occurred.start != row.occurred.end
                })
                .map(|(id, row)| EntityTime {
                    id: *id,
                    timestamp: match q.axis {
                        TimeAxis::Learned => row.learned_at,
                        TimeAxis::OccurredStart => row.occurred.start,
                        TimeAxis::OccurredEnd => row.occurred.end,
                    },
                })
                .filter(|r| match q.start {
                    Bound::Unbounded => true,
                    Bound::Included(t) => r.timestamp >= t,
                    Bound::Excluded(t) => r.timestamp > t,
                })
                .filter(|r| match q.end {
                    Bound::Unbounded => true,
                    Bound::Included(t) => r.timestamp <= t,
                    Bound::Excluded(t) => r.timestamp < t,
                })
                .filter(|r| {
                    cursor.is_none_or(|c| {
                        if q.reverse {
                            (r.timestamp, r.id) < (c.timestamp, c.id)
                        } else {
                            (r.timestamp, r.id) > (c.timestamp, c.id)
                        }
                    })
                });
            let next = if q.reverse {
                rows.max_by_key(|r| (r.timestamp, r.id))
            } else {
                rows.min_by_key(|r| (r.timestamp, r.id))
            };
            exhausted = next.is_none();
            cursor = next;
            next.map(Ok)
        })))
    }

    fn port_entity_record(&self, txn: &Snapshot, id: &EntityId) -> Result<Option<EntityRecord>> {
        Ok(txn.entities.get(id).cloned())
    }
    fn port_entity_ids_by_type<'a>(
        &self,
        txn: &'a Snapshot,
        kind: u8,
        after: Option<EntityId>,
    ) -> Result<PortRows<'a, EntityId>> {
        Ok(Box::new(
            txn.entities
                .iter()
                .filter(move |(id, row)| {
                    row.entity_type == kind && after.is_none_or(|after| **id > after)
                })
                .map(|(id, _)| Ok(*id)),
        ))
    }
}

impl EdgeStoreRead for Memory {
    fn port_edge_cursor<'a>(
        &self,
        txn: &'a Snapshot,
        center: &EntityId,
        direction: EdgeDirection,
        after: Option<(u8, EntityId)>,
    ) -> Result<PortRows<'a, EdgeInfo>> {
        Ok(Box::new(
            self.port_edges(txn, center, direction, None, None)?
                .filter(move |row| {
                    row.as_ref().map_or(true, |edge| {
                        after.is_none_or(|after| (edge.kind as u8, edge.target) > after)
                    })
                }),
        ))
    }

    fn port_edge_consistent(
        &self,
        _txn: &Snapshot,
        _source: &EntityId,
        _kind: EdgeKind,
        _target: &EntityId,
    ) -> Result<bool> {
        Ok(true)
    }

    fn port_edges<'a>(
        &self,
        txn: &'a Snapshot,
        center: &EntityId,
        direction: EdgeDirection,
        kind: Option<EdgeKind>,
        after: Option<EntityId>,
    ) -> Result<PortRows<'a, EdgeInfo>> {
        if after.is_some() && kind.is_none() {
            return Err(Error::InvalidConfig("edge cursor requires a kind".into()));
        }
        let center = *center;
        let mut streams: Vec<PortRows<'a, EdgeInfo>> = Vec::new();
        for outbound in [true, false] {
            if (outbound && direction == EdgeDirection::In)
                || (!outbound && direction == EdgeDirection::Out)
            {
                continue;
            }
            let rows = (0_u8..=u8::MAX)
                .filter(move |k| kind.is_none_or(|kind| kind as u8 == *k))
                .flat_map(move |k| {
                    txn.edges
                        .iter()
                        .filter(move |((s, stored_kind, d), _)| {
                            *stored_kind == k
                                && (if outbound { *s } else { *d }) == center
                                && after
                                    .is_none_or(|after| (if outbound { *d } else { *s }) > after)
                        })
                        .map(move |((s, _, d), value)| {
                            let kind = EdgeKind::try_from_u8(k)
                                .ok_or(Error::CorruptedIndex("edge kind"))?;
                            let peer = if outbound { *d } else { *s };
                            let decoded = crate::edge::decode_edge_value_for_kind(kind, value)?;
                            Ok(EdgeInfo {
                                kind,
                                target: peer,
                                target_short_id: None,
                                weight: decoded.weight,
                                created_at: decoded.created_at,
                                vad: decoded.vad,
                                provenance: decoded.provenance,
                            })
                        })
                });
            streams.push(Box::new(rows));
        }
        Ok(Box::new(streams.into_iter().flatten()))
    }
    fn port_edge_get(
        &self,
        txn: &Snapshot,
        source: &EntityId,
        kind: EdgeKind,
        target: &EntityId,
    ) -> Result<Option<EdgeInfo>> {
        let key = crate::store::Store::encode_edge_key(source, kind, target);
        txn.edges
            .get(&(*source, kind as u8, *target))
            .map(|value| Ok(crate::edge::parse_strict_edge_record(&key, value)?.into_edge_info()))
            .transpose()
    }
}

impl TombstoneStoreRead for Memory {
    fn port_tombstone_records<'a>(
        &self,
        txn: &'a Snapshot,
        family: DeletionFamily,
    ) -> Result<PortRows<'a, (EntityId, crate::deletion::DecodedTombstoneValue)>> {
        Ok(Box::new(
            txn.tombstones
                .iter()
                .filter(move |(_, value)| match family {
                    DeletionFamily::Archive => {
                        value.reason == crate::deletion::TombstoneReason::ArchivedByCleanup
                    }
                    DeletionFamily::HardDelete => matches!(
                        value.reason,
                        crate::deletion::TombstoneReason::UserHardDelete
                            | crate::deletion::TombstoneReason::GdprDelete
                            | crate::deletion::TombstoneReason::PolicyDelete
                    ),
                })
                .map(|(id, value)| {
                    Ok((
                        *id,
                        crate::deletion::decode_tombstone_value(&value.encode()),
                    ))
                }),
        ))
    }

    fn port_deletion_state(&self, txn: &Snapshot, id: &EntityId) -> Result<DeletionState> {
        Ok(DeletionState {
            archived: false,
            deleted: txn.tombstones.contains_key(id),
            stale: txn.stale.contains(id),
        })
    }
}

impl ShortIdStoreRead for Memory {
    fn port_short_id_reference(
        &self,
        txn: &Snapshot,
        id: &EntityId,
    ) -> Result<Option<(String, u8)>> {
        Ok(txn.shorts.get(id).cloned())
    }
}

impl RetrievalIndexRead for Memory {
    fn port_retrieval_phonetic_search(
        &self,
        txn: &Snapshot,
        codes: &[String],
    ) -> Result<Vec<ScoredEntity>> {
        let mut counts = BTreeMap::<EntityId, usize>::new();
        let mut distinct_codes = BTreeSet::new();
        for code in codes {
            if !distinct_codes.insert(code) {
                continue;
            }
            if let Some(ids) = txn.phonetic.get(code) {
                for id in ids {
                    *counts.entry(*id).or_default() += 1;
                }
            }
        }
        let mut rows: Vec<_> = counts
            .into_iter()
            .map(|(id, count)| ScoredEntity {
                id,
                score: count as f32 * if count >= 2 { 1.2 } else { 1.0 },
            })
            .collect();
        crate::fusion::sort_scored_entities_desc(&mut rows);
        Ok(rows)
    }
}

impl RetrievalIndexExecution for Memory {
    fn port_retrieval_text_scoped(
        &self,
        txn: &Snapshot,
        query: TextQuery<'_>,
    ) -> Result<Vec<ScoredEntity>> {
        if query.limit == 0 {
            return Ok(Vec::new());
        }
        let mut rows = Vec::new();
        for row in self.port_retrieval_text_search(txn, query.query, usize::MAX)? {
            if !query.filter_all || (query.matches_scope)(&row.id)? {
                rows.push(row);
            }
            if rows.len() >= query.limit {
                break;
            }
        }
        if query.limit == 0 {
            rows.clear();
        }
        Ok(rows)
    }
}
