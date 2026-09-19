//! The twelve ARCH-0005a ports, with backend-neutral caller-owned transactions.
use super::{ChangeLogRecord, EdgeDirection, EntityRecord, SourceSpan};
use crate::attempt_queue::{
    ClaimAttempt, ClaimOutcome, CompleteAttempt, CompleteOutcome, EnqueueAttempt, EnqueueOutcome,
    FailAttempt, FailOutcome,
};
use crate::claim::ClaimBody;
use crate::deletion::{DeleteReason, TombstoneValueV2};
use crate::edge::EdgeInfo;
use crate::error::Result;
use crate::pipeline::ScoredEntity;
use crate::write_envelope::{ClaimCandidate, WriteEnvelope};
use crate::{EdgeKind, EntityId, HydratedShortId, TimeRange, Vault};
use std::ops::Deref;

pub trait Transactions {
    type Read<'a>;
    type Write<'a>: Deref<Target = Self::Read<'a>>;
}
impl Transactions for Vault {
    type Read<'a> = heed::RoTxn<'a>;
    type Write<'a> = heed::RwTxn<'a>;
}

pub trait EntityStore: Transactions {
    fn port_entity_get(&self, txn: &Self::Read<'_>, id: &EntityId) -> Result<Option<EntityRecord>>;
    fn port_entity_put(
        &self,
        txn: &mut Self::Write<'_>,
        id: &EntityId,
        row: &EntityRecord,
    ) -> Result<()>;
    /// Active-store deletion. Remote publication and sweep orchestration remain above this port.
    fn port_entity_delete(&self, txn: &mut Self::Write<'_>, id: &EntityId) -> Result<bool>;
    fn port_entity_batch_get(
        &self,
        txn: &Self::Read<'_>,
        ids: &[EntityId],
    ) -> Result<Vec<Option<EntityRecord>>> {
        if ids.len() > 100_000 {
            return Err(crate::Error::IndexOverflow("entity batch get"));
        }
        ids.iter().map(|id| self.port_entity_get(txn, id)).collect()
    }
    fn port_list_turns_by_session(
        &self,
        txn: &Self::Read<'_>,
        session: &EntityId,
    ) -> Result<Vec<EntityId>>;
    fn port_list_sessions_by_relationship(
        &self,
        txn: &Self::Read<'_>,
        relationship: &EntityId,
    ) -> Result<Vec<EntityId>>;
    fn port_list_summaries_by_level(
        &self,
        txn: &Self::Read<'_>,
        level: u64,
    ) -> Result<Vec<EntityId>>;
    fn port_list_assets_by_relationship(
        &self,
        txn: &Self::Read<'_>,
        relationship: &EntityId,
    ) -> Result<Vec<EntityId>>;
}
pub trait ClaimStore: Transactions {
    fn port_claim_get(&self, txn: &Self::Read<'_>, id: &EntityId) -> Result<Option<ClaimBody>>;
    fn port_claim_put(
        &self,
        txn: &mut Self::Write<'_>,
        id: &EntityId,
        candidate: ClaimCandidate,
        envelope: &WriteEnvelope,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<()>;
    fn port_claim_list(&self, txn: &Self::Read<'_>, subject: &EntityId) -> Result<Vec<EntityId>>;
    fn port_claim_list_by_predicate(
        &self,
        txn: &Self::Read<'_>,
        predicate: &str,
    ) -> Result<Vec<(EntityId, ClaimBody)>>;
    fn port_claim_get_active(
        &self,
        txn: &Self::Read<'_>,
        subject: &EntityId,
        predicate: &str,
    ) -> Result<Option<(EntityId, ClaimBody)>>;
    fn port_claim_supersede_chain(
        &self,
        txn: &Self::Read<'_>,
        id: &EntityId,
    ) -> Result<Vec<EntityId>>;
    fn port_claim_predicate_history(
        &self,
        txn: &Self::Read<'_>,
        subject: &EntityId,
        predicate: &str,
    ) -> Result<Vec<(EntityId, ClaimBody)>>;
    fn port_claim_find_conflicting(
        &self,
        txn: &Self::Read<'_>,
        subject: &EntityId,
        predicate: &str,
    ) -> Result<Option<(EntityId, ClaimBody)>>;
}
pub trait EdgeStore: Transactions {
    fn port_edge_upsert(
        &self,
        txn: &mut Self::Write<'_>,
        src: &EntityId,
        kind: EdgeKind,
        dst: &EntityId,
        weight: f32,
    ) -> Result<()>;
    fn port_edge_mark_stale(
        &self,
        txn: &mut Self::Write<'_>,
        src: &EntityId,
        kind: EdgeKind,
        dst: &EntityId,
    ) -> Result<bool>;
    fn port_edge_delete(
        &self,
        txn: &mut Self::Write<'_>,
        src: &EntityId,
        kind: EdgeKind,
        dst: &EntityId,
    ) -> Result<bool>;
    fn port_edge_neighbors(
        &self,
        txn: &Self::Read<'_>,
        id: &EntityId,
        direction: EdgeDirection,
        kind: Option<EdgeKind>,
        limit: usize,
    ) -> Result<Vec<EdgeInfo>>;
    fn port_edge_list_by_dst(
        &self,
        txn: &Self::Read<'_>,
        id: &EntityId,
        kind: Option<EdgeKind>,
        after: Option<&EntityId>,
        limit: usize,
    ) -> Result<Vec<EntityId>>;
}
pub trait PlaceStore: Transactions {
    fn port_place_get(&self, txn: &Self::Read<'_>, id: &EntityId) -> Result<Option<EntityRecord>>;
    fn port_place_put(
        &self,
        txn: &mut Self::Write<'_>,
        id: &EntityId,
        row: &EntityRecord,
    ) -> Result<()>;
    fn port_place_find_by_provider_id(
        &self,
        txn: &Self::Read<'_>,
        provider: &str,
        provider_id: &str,
    ) -> Result<Vec<EntityId>>;
    fn port_place_find_by_name(&self, txn: &Self::Read<'_>, name: &str) -> Result<Vec<EntityId>>;
    fn port_place_list_children(
        &self,
        txn: &Self::Read<'_>,
        id: &EntityId,
    ) -> Result<Vec<EntityId>>;
}
pub trait RetrievalIndex: Transactions {
    fn port_retrieval_upsert(
        &self,
        txn: &mut Self::Write<'_>,
        id: &EntityId,
        vector: Option<&[f32]>,
        text: Option<&[(&str, &str)]>,
    ) -> Result<()>;
    fn port_retrieval_mark_stale(&self, txn: &mut Self::Write<'_>, id: &EntityId) -> Result<()>;
    fn port_retrieval_vector_search(
        &self,
        txn: &Self::Read<'_>,
        query: &[f32],
        limit: usize,
    ) -> Result<Vec<ScoredEntity>>;
    fn port_retrieval_text_search(
        &self,
        txn: &Self::Read<'_>,
        query: &str,
        limit: usize,
    ) -> Result<Vec<ScoredEntity>>;
}
pub trait ShortIdStore: Transactions {
    fn port_short_id_get_or_create(
        &self,
        txn: &mut Self::Write<'_>,
        id: &EntityId,
    ) -> Result<String>;
    fn port_short_id_resolve(
        &self,
        txn: &Self::Read<'_>,
        short_id: &str,
        content_hash: u8,
    ) -> Result<Option<HydratedShortId>>;
    fn port_short_id_resolve_batch(
        &self,
        txn: &Self::Read<'_>,
        refs: &[(&str, u8)],
    ) -> Result<Vec<Option<HydratedShortId>>> {
        if refs.len() > 100_000 {
            return Err(crate::Error::IndexOverflow("short id batch"));
        }
        refs.iter()
            .map(|(id, hash)| self.port_short_id_resolve(txn, id, *hash))
            .collect()
    }
}
pub trait TombstoneStore: Transactions {
    fn port_tombstone_create(
        &self,
        txn: &mut Self::Write<'_>,
        id: &EntityId,
        value: TombstoneValueV2,
    ) -> Result<()>;
    fn port_tombstone_is_deleted(&self, txn: &Self::Read<'_>, id: &EntityId) -> Result<bool>;
    /// No wall-clock TTL is authorized. Only completed regeneration receipts may retire a row.
    fn port_tombstone_clean_expired(
        &self,
        txn: &mut Self::Write<'_>,
        now: u64,
        limit: usize,
    ) -> Result<u64>;
}
pub trait DependencyIndex: Transactions {
    fn port_dependency_put(
        &self,
        txn: &mut Self::Write<'_>,
        source: SourceSpan,
        dependent: &EntityId,
    ) -> Result<()>;
    fn port_dependency_list_by_source(
        &self,
        txn: &Self::Read<'_>,
        source: SourceSpan,
    ) -> Result<Vec<EntityId>>;
}
pub trait ChangeLogStore: Transactions {
    fn port_changelog_append(
        &self,
        txn: &mut Self::Write<'_>,
        record: &ChangeLogRecord,
    ) -> Result<()>;
    fn port_changelog_list_by_entity(
        &self,
        txn: &Self::Read<'_>,
        entity: &EntityId,
        limit: usize,
    ) -> Result<Vec<ChangeLogRecord>>;
    fn port_changelog_list_by_actor(
        &self,
        txn: &Self::Read<'_>,
        actor: &EntityId,
        limit: usize,
    ) -> Result<Vec<ChangeLogRecord>>;
}
pub trait BlobStore: Transactions {
    /// References are stable first-class ids, not anonymous refcount increments.
    fn port_blob_put(
        &self,
        txn: &mut Self::Write<'_>,
        reference: &EntityId,
        bytes: &[u8],
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<[u8; 32]>;
    fn port_blob_get(&self, txn: &Self::Read<'_>, hash: &[u8; 32]) -> Result<Option<Vec<u8>>>;
    fn port_blob_delete(
        &self,
        txn: &mut Self::Write<'_>,
        reference: &EntityId,
        hash: &[u8; 32],
        reason: DeleteReason,
    ) -> Result<bool>;
    fn port_blob_sign_upload_url(&self, _hash: &[u8; 32], _ttl: u64) -> Result<Option<String>> {
        Ok(None)
    }
    fn port_blob_sign_download_url(&self, _hash: &[u8; 32], _ttl: u64) -> Result<Option<String>> {
        Ok(None)
    }
}
pub trait JobQueue: Transactions {
    fn port_job_enqueue(
        &self,
        txn: &mut Self::Write<'_>,
        input: EnqueueAttempt,
    ) -> Result<EnqueueOutcome>;
    fn port_job_claim(
        &self,
        txn: &mut Self::Write<'_>,
        kind: Option<&str>,
        input: ClaimAttempt,
    ) -> Result<ClaimOutcome>;
    fn port_job_complete(
        &self,
        txn: &mut Self::Write<'_>,
        input: CompleteAttempt,
    ) -> Result<CompleteOutcome>;
    fn port_job_fail(&self, txn: &mut Self::Write<'_>, input: FailAttempt) -> Result<FailOutcome>;
}
