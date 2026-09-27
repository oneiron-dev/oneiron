//! Receipted graph and timeline reads under the resolved actor floor.
use super::{ScopedRead, ScopedReadResult};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::deletion::{MemoryTimeline, MemoryTimelineRecord, MemoryTimelineRecordState};
use crate::edge::EdgeKind;
use crate::gate::{PolicyManifestResolution, ResolvedRetrievalFilter, RetrievalFilter};
use crate::ports::{EdgeDirection, EdgeStoreRead};
use crate::vault::ReadMode;
use crate::{EdgeInfo, EntityId, Error, Result};
use std::collections::HashSet;

type GraphAskNeighbors = Vec<(EntityId, u8, Vec<u8>)>;
type TimelineEntityParts = (u8, u64, Vec<u8>);
type SupersessionParts = (TimelineEntityParts, TimelineEntityParts);

impl ScopedRead<'_> {
    /// The graph-ask recipe reads at most `limit` usable outgoing neighbors.
    /// Cap the raw scan too, so an invisible high-degree region cannot force
    /// an unbounded authority walk. Unit and neighbors share one read snapshot.
    pub(crate) fn graph_ask_neighbors(
        &self,
        unit: &EntityId,
        limit: usize,
        scan_limit: usize,
        max_body_bytes: usize,
    ) -> Result<Option<GraphAskNeighbors>> {
        let txn = self.vault.store.env.read_txn()?;
        let (filter, policy) = self.resolve_retrieval_filter_in(&txn, None)?;
        if !self.is_entity_retrievable_with_policy_in(&txn, &policy, &filter, unit)? {
            return Ok(None);
        }
        let mut kept = Vec::new();
        let mut seen = HashSet::new();
        seen.insert(*unit);
        for entry in self.out_edges_in(&txn, unit, None)?.take(scan_limit) {
            let edge = entry?;
            if !seen.insert(edge.target) {
                continue;
            }
            let Some(raw) = self.entity_raw_with_mode_in(
                &txn,
                &policy,
                &filter,
                &edge.target,
                crate::vault::ReadMode::Live,
            )?
            else {
                continue;
            };
            let header = EntityMetadataHeader::parse(&raw)
                .ok_or(Error::CorruptedIndex("graph ask neighbor header"))?;
            let body = &raw[ENTITY_METADATA_HEADER_LEN..];
            if (header.entity_type != crate::registry::ENTITY_TYPE_CLAIM
                && (64..100).contains(&header.entity_type))
                || body.is_empty()
                || body.len() > max_body_bytes
            {
                continue;
            }
            kept.push((edge.target, header.entity_type, body.to_vec()));
            if kept.len() >= limit {
                break;
            }
        }
        Ok(Some(kept))
    }

    /// Edges and both endpoints share one authority snapshot and a mandatory receipt.
    pub fn edges_out(&self, id: &EntityId) -> Result<ScopedReadResult<Option<Vec<EdgeInfo>>>> {
        let txn = self.grant_read_txn()?;
        let (filter, policy) = self.resolve_retrieval_filter_in(&txn, None)?;
        let mut suppressed = 0;
        let value = if self.is_entity_retrievable_with_policy_in(&txn, &policy, &filter, id)? {
            let mut kept = Vec::new();
            for edge in self.edges_out_in(&txn, id)? {
                if self.is_entity_retrievable_with_policy_in(
                    &txn,
                    &policy,
                    &filter,
                    &edge.target,
                )? {
                    kept.push(edge);
                } else if self.entity_record_in(&txn, &edge.target)?.is_some() {
                    suppressed += 1;
                }
            }
            Some(kept)
        } else {
            suppressed += usize::from(self.entity_record_in(&txn, id)?.is_some());
            None
        };
        Ok(ScopedReadResult {
            value,
            receipt: self.receipt_for(None, &policy, &filter, suppressed),
        })
    }

    /// Timeline metadata is rechecked against both the initial and final authority.
    pub fn memory_timeline(&self, anchor: &EntityId) -> Result<ScopedReadResult<MemoryTimeline>> {
        let (filter, policy) = {
            let txn = self.grant_read_txn()?;
            let (filter, policy) = self.resolve_retrieval_filter_in(&txn, None)?;
            if !self.timeline_anchor_allowed_in(&txn, &policy, &filter, anchor)? {
                let suppressed = usize::from(self.entity_record_in(&txn, anchor)?.is_some());
                return Ok(ScopedReadResult {
                    value: MemoryTimeline {
                        anchor: *anchor,
                        records: Vec::new(),
                    },
                    receipt: self.receipt_for(None, &policy, &filter, suppressed),
                });
            }
            (filter, policy)
        };
        let mut timeline = self.vault.memory_timeline(anchor)?;
        let txn = self.grant_read_txn()?;
        let (fresh_filter, fresh_policy) = self.resolve_retrieval_filter_in(&txn, None)?;
        let anchor_allowed = self.timeline_anchor_allowed_in(&txn, &policy, &filter, anchor)?
            && self.timeline_anchor_allowed_in(&txn, &fresh_policy, &fresh_filter, anchor)?;
        let mut suppressed = 0;
        let mut kept = Vec::new();
        for record in timeline.records {
            if anchor_allowed
                && self.timeline_record_allowed_in(&txn, &policy, &filter, &record)?
                && self.timeline_record_allowed_in(&txn, &fresh_policy, &fresh_filter, &record)?
            {
                kept.push(record);
            } else if self.entity_record_in(&txn, &record.id)?.is_some() {
                suppressed += 1;
            }
        }
        let ids: HashSet<_> = kept.iter().map(|record| record.id).collect();
        for record in &mut kept {
            record.supersedes.retain(|id| ids.contains(id));
            record.superseded_by.retain(|id| ids.contains(id));
        }
        timeline.records = kept;
        let mut receipt = self.receipt_for(None, &policy, &filter, 0);
        receipt.restrict_with(&self.receipt_for(None, &fresh_policy, &fresh_filter, suppressed));
        Ok(ScopedReadResult {
            value: timeline,
            receipt,
        })
    }

    /// Read the bodies of already-authorized timeline rows. This is NOT a
    /// retrieval search: closed claims are history, but their audience,
    /// predicate, world, sensitivity and policy gates still apply. Recheck
    /// each row against the caller's current authority snapshot before giving
    /// its bytes to a renderer.
    pub fn memory_timeline_parts_with_receipt(
        &self,
        records: &[MemoryTimelineRecord],
        requested: Option<&RetrievalFilter>,
    ) -> Result<ScopedReadResult<Vec<Option<TimelineEntityParts>>>> {
        let txn = self.vault.store.env.read_txn()?;
        let (filter, policy) = self.resolve_retrieval_filter_in(&txn, requested)?;
        let mut suppressed = 0;
        let mut value = Vec::with_capacity(records.len());
        for record in records {
            if record.state == MemoryTimelineRecordState::Deleted {
                value.push(None);
                continue;
            }
            if !self.timeline_record_allowed_in(&txn, &policy, &filter, record)? {
                suppressed += usize::from(self.entity_record_in(&txn, &record.id)?.is_some());
                value.push(None);
                continue;
            }
            let Some(raw) = self
                .entity_record_in(&txn, &record.id)?
                .map(|row| row.encode())
            else {
                value.push(None);
                continue;
            };
            let header =
                EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
            value.push(Some((
                header.entity_type,
                header.learned_at,
                raw[ENTITY_METADATA_HEADER_LEN..].to_vec(),
            )));
        }
        Ok(ScopedReadResult {
            value,
            receipt: self.receipt_for(requested, &policy, &filter, suppressed),
        })
    }

    /// A closed claim is not eligible for ordinary retrieval. This history
    /// door tests ALL the ordinary authority predicates on the stored row,
    /// changing only the lifecycle input to the retrieval status gate. It
    /// never returns the normalized bytes; the caller receives the original.
    fn history_row_readable_in(
        &self,
        txn: &heed::RoTxn<'_>,
        policy: &PolicyManifestResolution,
        filter: &ResolvedRetrievalFilter,
        id: &EntityId,
        raw: &[u8],
    ) -> Result<bool> {
        let header =
            EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM
            || raw.len() == ENTITY_METADATA_HEADER_LEN
        {
            return self.is_entity_raw_readable_with_filter_in(txn, policy, id, raw, filter);
        }
        let mut claim = crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
        if claim.lifecycle == crate::claim::ClaimLifecycleStatus::Active {
            return self.is_entity_raw_readable_with_filter_in(txn, policy, id, raw, filter);
        }
        claim.lifecycle = crate::claim::ClaimLifecycleStatus::Active;
        let mut normalized = raw[..ENTITY_METADATA_HEADER_LEN].to_vec();
        normalized.extend_from_slice(&crate::claim::encode_claim_body(&claim)?);
        self.is_entity_raw_readable_with_filter_in(txn, policy, id, &normalized, filter)
    }

    /// Reads the immutable A→B pair recorded with an accepted Supersedes edge.
    /// Both exact frontiers AND both current rows must still pass this actor's
    /// present read policy. A peer without the local event/frontiers, an erased
    /// row or a restricted side yields no before/after data, never live fallback.
    pub fn memory_supersession_parts_with_receipt(
        &self,
        old: &EntityId,
        new: &EntityId,
        requested: Option<&RetrievalFilter>,
    ) -> Result<ScopedReadResult<Option<SupersessionParts>>> {
        let txn = self.vault.store.env.read_txn()?;
        let (filter, policy) = self.resolve_retrieval_filter_in(&txn, requested)?;
        let receipt = |suppressed| self.receipt_for(requested, &policy, &filter, suppressed);
        let mut linked = false;
        for edge in self.vault.port_edges(
            &txn,
            new,
            EdgeDirection::Out,
            Some(EdgeKind::Supersedes),
            None,
        )? {
            if edge?.target == *old {
                linked = true;
                break;
            }
        }
        if !linked {
            return Ok(ScopedReadResult {
                value: None,
                receipt: receipt(0),
            });
        }
        let Some(pair) =
            crate::claim::supersession_diff::load_in_txn(self.vault, &txn, *old, *new)?
        else {
            return Ok(ScopedReadResult {
                value: None,
                receipt: receipt(0),
            });
        };
        let revisions = [
            (*old, pair.before, pair.before_hash),
            (*new, pair.after, pair.after_hash),
        ];
        let mut parts = Vec::with_capacity(2);
        for (id, revision, expected_hash) in revisions {
            if !crate::vault::entity_revision::entity_owns_revision_in_txn(
                &self.vault.store,
                &txn,
                &id,
                revision,
            )? {
                return Ok(ScopedReadResult {
                    value: None,
                    receipt: receipt(1),
                });
            }
            let Some(current) = self.entity_record_in(&txn, &id)?.map(|row| row.encode()) else {
                return Ok(ScopedReadResult {
                    value: None,
                    receipt: receipt(1),
                });
            };
            let Some(raw) = crate::vault::entity_revision::read_entity_revision_in_txn(
                self.vault,
                &txn,
                &id,
                ReadMode::Pinned(revision),
            )?
            else {
                return Ok(ScopedReadResult {
                    value: None,
                    receipt: receipt(1),
                });
            };
            if blake3::hash(&raw).as_bytes() != &expected_hash {
                return Err(Error::CorruptedIndex("supersession revision body hash"));
            }
            let header = EntityMetadataHeader::parse(&raw)
                .ok_or(Error::CorruptedIndex("supersession revision header"))?;
            if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM
                || !self.history_row_readable_in(&txn, &policy, &filter, &id, &current)?
                || !self.history_row_readable_in(&txn, &policy, &filter, &id, &raw)?
            {
                return Ok(ScopedReadResult {
                    value: None,
                    receipt: receipt(1),
                });
            }
            parts.push((
                header.entity_type,
                header.learned_at,
                raw[ENTITY_METADATA_HEADER_LEN..].to_vec(),
            ));
        }
        let after = parts
            .pop()
            .ok_or(Error::CorruptedIndex("supersession after parts"))?;
        let before = parts
            .pop()
            .ok_or(Error::CorruptedIndex("supersession before parts"))?;
        Ok(ScopedReadResult {
            value: Some((before, after)),
            receipt: receipt(0),
        })
    }

    fn timeline_anchor_allowed_in(
        &self,
        txn: &heed::RoTxn<'_>,
        policy: &PolicyManifestResolution,
        filter: &ResolvedRetrievalFilter,
        id: &EntityId,
    ) -> Result<bool> {
        if let Some(raw) = self.entity_record_in(txn, id)?.map(|row| row.encode())
            && self.history_row_readable_in(txn, policy, filter, id, &raw)?
        {
            return Ok(true);
        }
        // A timeline reports deletion metadata, unlike a content search.
        // Erased claims and relationship content cannot prove their read scope.
        let Some(raw) = self.entity_record_in(txn, id)?.map(|row| row.encode()) else {
            return Ok(false);
        };
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        Ok(!filter.deny_all
            && self.audience_readable_in(txn, id)?
            && self
                .vault
                .store
                .validate_entity_type(header.entity_type)
                .is_ok()
            && filter
                .entity_types
                .as_ref()
                .is_none_or(|types| types.contains(&header.entity_type))
            && !matches!(
                header.entity_type,
                crate::registry::ENTITY_TYPE_CLAIM | crate::registry::ENTITY_TYPE_NOTE
            )
            && !(self.actor_key.enforce_access_grants
                && matches!(
                    header.entity_type,
                    crate::registry::ENTITY_TYPE_MESSAGE | crate::registry::ENTITY_TYPE_SUMMARY
                ))
            && raw.len() == ENTITY_METADATA_HEADER_LEN
            && self
                .vault
                .store
                .entity_deletion_present_in_txn(txn, id, header.learned_at)?)
    }

    fn timeline_record_allowed_in(
        &self,
        txn: &heed::RoTxn<'_>,
        policy: &PolicyManifestResolution,
        filter: &ResolvedRetrievalFilter,
        record: &MemoryTimelineRecord,
    ) -> Result<bool> {
        let Some(raw) = self
            .entity_record_in(txn, &record.id)?
            .map(|row| row.encode())
        else {
            return Ok(false);
        };
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        // Never combine metadata captured before a rewrite with later authority.
        if filter.deny_all
            || !self.audience_readable_in(txn, &record.id)?
            || record.entity_type != Some(header.entity_type)
            || record.occurred_start != Some(header.occurred_start)
            || record.occurred_end != Some(header.occurred_end)
            || record.learned_at != Some(header.learned_at)
            || record.body_bytes != Some(raw.len() - ENTITY_METADATA_HEADER_LEN)
            || self
                .vault
                .store
                .validate_entity_type(header.entity_type)
                .is_err()
            || filter
                .entity_types
                .as_ref()
                .is_some_and(|types| !types.contains(&header.entity_type))
        {
            return Ok(false);
        }
        if record.state == MemoryTimelineRecordState::Deleted {
            // Claim history remains private. Relationship-scoped content cannot
            // prove its grant from an erased body. Other deletion metadata obeys
            // the same type ceiling as the short-reference hydrate door.
            let scope_erased = matches!(
                header.entity_type,
                crate::registry::ENTITY_TYPE_CLAIM | crate::registry::ENTITY_TYPE_NOTE
            ) || (self.actor_key.enforce_access_grants
                && matches!(
                    header.entity_type,
                    crate::registry::ENTITY_TYPE_MESSAGE | crate::registry::ENTITY_TYPE_SUMMARY
                ));
            return Ok(!scope_erased
                && raw.len() == ENTITY_METADATA_HEADER_LEN
                && self.vault.store.entity_deletion_present_in_txn(
                    txn,
                    &record.id,
                    header.learned_at,
                )?);
        }
        if record.state == MemoryTimelineRecordState::Missing {
            return Ok(false);
        }
        self.history_row_readable_in(txn, policy, filter, &record.id, &raw)
    }
}
