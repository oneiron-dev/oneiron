//! Claim adapter preserves the history door; current-state queries exclude stale claims.
use super::*;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{ClaimBody, ClaimLifecycleStatus, decode_claim_body};
use crate::context_pack::source_ranking::{SourceRankingPolicy, question_key, source_outranks};
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::scan_check::{EngineScan, ScanCount};
use crate::write_envelope::{ClaimCandidate, WriteEnvelope};
use crate::{EdgeKind, EntityId, TimeRange, Vault};
use heed::{RoTxn, RwTxn};
use std::collections::BTreeSet;
#[cfg(test)]
pub(crate) const MAX_PREDICATE_LIST_ROWS: usize = 64;

impl Vault {
    /// Hands each stored CLAIM carrying `predicate` to `visit`, one at a time
    /// in type-index order, reserved predicates included. Nothing is held
    /// between claims, so the walk has no count past which it refuses: the
    /// claim type-index rows it reads only feed the advisory
    /// [`EngineScan::TypeIndexRows`] check (FIX 8656). This walk is raw, for
    /// checkpoint and maintenance passes; a door that serves claim bodies
    /// walks [`Self::for_each_readable_claim_with_predicate_in_txn`].
    pub(crate) fn for_each_claim_with_predicate_in_txn(
        &self,
        rtxn: &RoTxn<'_>,
        predicate: &str,
        visit: impl FnMut(EntityId, ClaimBody) -> Result<()>,
    ) -> Result<()> {
        self.walk_claims_with_predicate_in_txn(rtxn, predicate, false, visit)
    }

    /// [`Self::for_each_claim_with_predicate_in_txn`] for a door that serves
    /// claim bodies: a claim whose words are withdrawn, or whose recorded
    /// sources no longer stand, is skipped before it is decoded. Every
    /// lifecycle and Recorded status stays, as `port_claim_get` keeps it.
    pub(crate) fn for_each_readable_claim_with_predicate_in_txn(
        &self,
        rtxn: &RoTxn<'_>,
        predicate: &str,
        visit: impl FnMut(EntityId, ClaimBody) -> Result<()>,
    ) -> Result<()> {
        self.walk_claims_with_predicate_in_txn(rtxn, predicate, true, visit)
    }

    /// [`Self::for_each_readable_claim_with_predicate_in_txn`] for a reader
    /// that judges a readable claim whose body does not decode itself (FIX
    /// 10793): its id, stored body and decode error go to `undecoded`, and
    /// the walk goes on. A store or index failure still fails the walk.
    pub(crate) fn for_each_readable_claim_with_predicate_or_undecoded_in_txn(
        &self,
        rtxn: &RoTxn<'_>,
        predicate: &str,
        mut visit: impl FnMut(EntityId, ClaimBody) -> Result<()>,
        mut undecoded: impl FnMut(EntityId, &[u8], Error) -> Result<()>,
    ) -> Result<()> {
        for entry in self
            .store
            .type_index
            .prefix_iter(rtxn, &[ENTITY_TYPE_CLAIM])?
        {
            let (key, _) = entry?;
            let id = crate::vault::entity_id_from_type_index_key(&key)?;
            let raw = self
                .store
                .entities
                .get(rtxn, id.as_bytes())?
                .ok_or(Error::CorruptedIndex("claim type index"))?;
            let header =
                EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
            if header.entity_type != ENTITY_TYPE_CLAIM {
                return Err(Error::CorruptedIndex("claim type index"));
            }
            let body = &raw[ENTITY_METADATA_HEADER_LEN..];
            if !super::safe_read::body_readable_in_txn(
                &self.store,
                rtxn,
                &id,
                body,
                super::safe_read::BodyStale::ClaimStatus,
            )? {
                continue;
            }
            match decode_claim_body(body, true) {
                Ok(decoded) if decoded.predicate == predicate => visit(id, decoded)?,
                Ok(_) => {}
                Err(error) => undecoded(id, body, error)?,
            }
        }
        Ok(())
    }

    fn walk_claims_with_predicate_in_txn(
        &self,
        rtxn: &RoTxn<'_>,
        predicate: &str,
        readable: bool,
        mut visit: impl FnMut(EntityId, ClaimBody) -> Result<()>,
    ) -> Result<()> {
        let mut count = ScanCount::start(
            &self.store,
            rtxn,
            EngineScan::TypeIndexRows,
            &[ENTITY_TYPE_CLAIM],
        )?;
        for entry in self
            .store
            .type_index
            .prefix_iter(rtxn, &[ENTITY_TYPE_CLAIM])?
        {
            count.row();
            let (key, _) = entry?;
            let id = crate::vault::entity_id_from_type_index_key(&key)?;
            let raw = self
                .store
                .entities
                .get(rtxn, id.as_bytes())?
                .ok_or(Error::CorruptedIndex("claim type index"))?;
            let header =
                EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
            if header.entity_type != ENTITY_TYPE_CLAIM {
                return Err(Error::CorruptedIndex("claim type index"));
            }
            let body = &raw[ENTITY_METADATA_HEADER_LEN..];
            let skip = if readable {
                !super::safe_read::body_readable_in_txn(
                    &self.store,
                    rtxn,
                    &id,
                    body,
                    super::safe_read::BodyStale::ClaimStatus,
                )?
            } else {
                // A soft-deleted claim keeps its header alone, and no predicate.
                body.is_empty() && TombstoneStoreRead::port_deletion_state(self, rtxn, &id)?.deleted
            };
            if skip {
                continue;
            }
            let body = decode_claim_body(body, true)?;
            if body.predicate == predicate {
                visit(id, body)?;
            }
        }
        count.defer(&self.store);
        Ok(())
    }
}

impl ClaimStore for Vault {
    fn port_claim_get(&self, rtxn: &RoTxn<'_>, id: &EntityId) -> Result<Option<ClaimBody>> {
        let Some(raw) = self.store.entities.get(rtxn, id.as_bytes())? else {
            return Ok(None);
        };
        // History keeps every lifecycle status, never words a deletion withdrew
        // or a source that no longer stands.
        if !super::safe_read::raw_readable_in_txn(&self.store, rtxn, id, &raw)? {
            return Ok(None);
        }
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_CLAIM {
            return Err(Error::InvalidClaimBody("entity is not a type-0 CLAIM"));
        }
        crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true).map(Some)
    }
    fn port_claim_put(
        &self,
        txn: &mut RwTxn<'_>,
        id: &EntityId,
        candidate: ClaimCandidate,
        envelope: &WriteEnvelope,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<()> {
        self.batch_in()
            .claim_candidate(id, candidate, envelope, occurred, learned_at)
            .apply(txn)
    }
    fn port_claim_list(&self, rtxn: &RoTxn<'_>, subject: &EntityId) -> Result<Vec<EntityId>> {
        self.filtered_edge_peers(
            rtxn,
            crate::ports::EdgeDirection::In,
            subject,
            EdgeKind::ClaimOf,
            Some(ENTITY_TYPE_CLAIM),
        )
    }
    fn port_claim_list_by_predicate(
        &self,
        rtxn: &RoTxn<'_>,
        predicate: &str,
    ) -> Result<Vec<(EntityId, ClaimBody)>> {
        let mut rows = Vec::new();
        self.for_each_readable_claim_with_predicate_in_txn(rtxn, predicate, |id, body| {
            rows.push((id, body));
            Ok(())
        })?;
        Ok(rows)
    }
    fn port_claim_get_active(
        &self,
        txn: &RoTxn<'_>,
        subject: &EntityId,
        predicate: &str,
    ) -> Result<Option<(EntityId, ClaimBody)>> {
        let mut rows = self.port_claim_predicate_history(txn, subject, predicate)?;
        let mut heads = Vec::new();
        while let Some((id, body)) = rows.pop() {
            if body.lifecycle == ClaimLifecycleStatus::Active
                && !body.stale
                && !stale_in_txn(&self.store, txn, &id)?
                && !self.port_tombstone_is_deleted(txn, &id)?
            {
                heads.push((id, body));
            }
        }
        Ok(current_claim_head(heads))
    }
    /// Every claim of `id`'s supersede chain, however long (FIX 10042): a
    /// cycle or a fork is a typed error, and each link only feeds the
    /// advisory [`EngineScan::TimelineRecords`] check of `id`'s chain.
    fn port_claim_supersede_chain(&self, txn: &RoTxn<'_>, id: &EntityId) -> Result<Vec<EntityId>> {
        let scope = id.as_bytes();
        let mut count = ScanCount::start(&self.store, txn, EngineScan::TimelineRecords, scope)?;
        let mut result = Vec::new();
        let mut current = *id;
        let mut seen = std::collections::BTreeSet::new();
        loop {
            if !seen.insert(current) {
                return Err(Error::CorruptedIndex("claim supersede cycle"));
            }
            count.row();
            result.push(current);
            let next =
                self.port_edge_list_by_dst(txn, &current, Some(EdgeKind::Supersedes), None, 2)?;
            match next.as_slice() {
                [] => break,
                [id] => current = *id,
                _ => return Err(Error::CorruptedIndex("forked supersede chain")),
            }
        }
        count.defer(&self.store);
        Ok(result)
    }
    fn port_claim_predicate_history(
        &self,
        txn: &RoTxn<'_>,
        subject: &EntityId,
        predicate: &str,
    ) -> Result<Vec<(EntityId, ClaimBody)>> {
        let mut rows = Vec::new();
        for id in self.port_claim_list(txn, subject)? {
            if let Some(body) = self.port_claim_get(txn, &id)?
                && body.predicate == predicate
            {
                let raw = self
                    .store
                    .entities
                    .get(txn, id.as_bytes())?
                    .ok_or(Error::CorruptedIndex("claim history row"))?;
                let h = EntityMetadataHeader::parse(&raw)
                    .ok_or(Error::CorruptedIndex("claim history header"))?;
                rows.push((h.learned_at, id, body));
            }
        }
        rows.sort_by_key(|(time, id, _)| (*time, *id));
        Ok(rows.into_iter().map(|(_, id, body)| (id, body)).collect())
    }
    fn port_claim_find_conflicting(
        &self,
        txn: &RoTxn<'_>,
        subject: &EntityId,
        predicate: &str,
    ) -> Result<Option<(EntityId, ClaimBody)>> {
        // A single-cardinality caller identifies its conflict set by subject and predicate.
        // Never filter by candidate value: a changed value must find the prior head.
        self.port_claim_get_active(txn, subject, predicate)
    }
}

/// The current value among one subject and predicate's eligible heads, given
/// newest first: the newest head no other eligible head outranks (OF-023). An
/// observed head held beside a stated one on the same question (the clamp's
/// [`question_key`]) never takes the current value from it, however new; a
/// stated head of another world, facet or topic does not hold it back, and
/// recency decides among the rest. Some head always wins when any is
/// eligible, so a conflicting head is found whenever one exists.
pub(super) fn current_claim_head(
    heads: Vec<(EntityId, ClaimBody)>,
) -> Option<(EntityId, ClaimBody)> {
    let policy = SourceRankingPolicy::default();
    let sources: BTreeSet<_> = heads
        .iter()
        .map(|(_, body)| (question_key(body), body.source))
        .collect();
    let outranked = |held: &ClaimBody| {
        let question = question_key(held);
        sources
            .iter()
            .any(|&(at, a)| at == question && source_outranks(&policy, a, held.source))
    };
    heads.into_iter().find(|(_, body)| !outranked(body))
}
