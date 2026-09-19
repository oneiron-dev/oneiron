//! Claim adapter preserves the history door; current-state queries exclude stale claims.
use super::*;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{ClaimBody, ClaimLifecycleStatus, decode_claim_body};
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::write_envelope::{ClaimCandidate, WriteEnvelope};
use crate::{EdgeKind, EntityId, TimeRange, Vault};
use heed::{RoTxn, RwTxn};
impl ClaimStore for Vault {
    fn port_claim_get(&self, rtxn: &RoTxn<'_>, id: &EntityId) -> Result<Option<ClaimBody>> {
        let Some(raw) = self.store.entities.get(rtxn, id.as_bytes())? else {
            return Ok(None);
        };
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
            "claims for subject",
        )
    }
    fn port_claim_list_by_predicate(
        &self,
        rtxn: &RoTxn<'_>,
        predicate: &str,
    ) -> Result<Vec<(EntityId, ClaimBody)>> {
        let mut rows = Vec::new();
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
            let body = decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
            if body.predicate == predicate {
                if rows.len() >= 100_000 {
                    return Err(Error::IndexOverflow("claim predicate"));
                }
                rows.push((id, body));
            }
        }
        Ok(rows)
    }
    fn port_claim_get_active(
        &self,
        txn: &RoTxn<'_>,
        subject: &EntityId,
        predicate: &str,
    ) -> Result<Option<(EntityId, ClaimBody)>> {
        let mut rows = self.port_claim_predicate_history(txn, subject, predicate)?;
        while let Some((id, body)) = rows.pop() {
            if body.lifecycle == ClaimLifecycleStatus::Active
                && !body.stale
                && !stale_in_txn(&self.store, txn, &id)?
                && !self.port_tombstone_is_deleted(txn, &id)?
            {
                return Ok(Some((id, body)));
            }
        }
        Ok(None)
    }
    fn port_claim_supersede_chain(&self, txn: &RoTxn<'_>, id: &EntityId) -> Result<Vec<EntityId>> {
        let mut result = Vec::new();
        let mut current = *id;
        let mut seen = std::collections::BTreeSet::new();
        loop {
            if !seen.insert(current) {
                return Err(Error::CorruptedIndex("claim supersede cycle"));
            }
            if result.len() >= 10_000 {
                return Err(Error::IndexOverflow("claim supersede chain"));
            }
            result.push(current);
            let next =
                self.port_edge_list_by_dst(txn, &current, Some(EdgeKind::Supersedes), None, 2)?;
            match next.as_slice() {
                [] => break,
                [id] => current = *id,
                _ => return Err(Error::CorruptedIndex("forked supersede chain")),
            }
        }
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
