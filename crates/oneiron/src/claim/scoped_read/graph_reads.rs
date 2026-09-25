//! Receipted graph and timeline reads under the resolved actor floor.
use super::{ScopedRead, ScopedReadResult};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::deletion::{MemoryTimeline, MemoryTimelineRecord, MemoryTimelineRecordState};
use crate::gate::{PolicyManifestResolution, ResolvedRetrievalFilter};
use crate::{EdgeInfo, EntityId, Error, Result};
use std::collections::HashSet;

impl ScopedRead<'_> {
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

    fn timeline_anchor_allowed_in(
        &self,
        txn: &heed::RoTxn<'_>,
        policy: &PolicyManifestResolution,
        filter: &ResolvedRetrievalFilter,
        id: &EntityId,
    ) -> Result<bool> {
        if self.is_entity_retrievable_with_policy_in(txn, policy, filter, id)? {
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
        self.is_entity_retrievable_with_policy_in(txn, policy, filter, &record.id)
    }
}
