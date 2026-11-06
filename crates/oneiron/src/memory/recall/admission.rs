use super::super::structural::*;
use super::super::*;
use super::conversation;
use super::home;
use super::presentation::{
    hedge_bucket_for, hedge_bucket_for_band, parse_pack_format, truncate_text, value_text_of,
};
use super::render_budget;
use super::render_budget::execution_render_budget;
use super::selection::RecallPin;
use super::*;
use crate::claim::retrieval_scope::FacetMode;
use crate::claim::{ClaimReadStatus, PointRead, ScopedRead, ScopedReadReceipt, claim_surfaceable};
use crate::context_pack::{DEFAULT_MAX_FIELD_CHARS, FieldProfile, PackFormat};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::memory::retrieval_defaults::DEFAULT_RECENCY_HALF_LIFE_DAYS;
use crate::ports::EntityStoreRead;
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_MESSAGE, ENTITY_TYPE_TURN};
use crate::rerank::RerankOptions;
use crate::retrieval_depth::RecallExecution;
use crate::retrieval_quality::{ConfidenceAdjustment, RetrievalDegradation, RetrievalQuality};
use crate::serialize::{SerializeConfig, serialize_pack};
use oneiron_model::llm::BudgetLease;
use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

impl Memory<'_> {
    /// Minimal recall for an exact-world view, with kind/predicate narrowing
    /// BEFORE lexical top-k. Uses the same recall assembly and ranking as
    /// [`Self::recall`]; no authority is inferred from these relevance filters.
    pub fn recall_view(
        &self,
        query: &str,
        scope: &RecallScope,
        kind: Option<&str>,
        predicate: Option<&str>,
        limit: usize,
    ) -> MemoryResult<MemoryPack> {
        if limit == 0 {
            return Err(MemoryError::bad_request("view limit must be at least 1"));
        }
        let world = scope
            .world_ref
            .as_deref()
            .map(|reference| self.resolve_ref(reference))
            .transpose()?;
        let filter = |store: &crate::store::StoreRead<'_>,
                      txn: &heed::RoTxn<'_>,
                      id: &EntityId|
         -> crate::Result<bool> {
            let Some(raw) = store.port_entity_record(txn, id)?.map(|row| row.encode()) else {
                return Ok(false);
            };
            let Some(header) = crate::batch::EntityMetadataHeader::parse(&raw) else {
                return Ok(false);
            };
            match kind {
                Some(kind) if kind_string_for_type(header.entity_type) != kind => return Ok(false),
                // A view that names no kind takes the scope's kinds, which
                // recall applies, or else the default kinds.
                None if scope.kinds.is_none() && CONTAINER_KINDS.contains(&header.entity_type) => {
                    return Ok(false);
                }
                _ => {}
            }
            if header.entity_type != ENTITY_TYPE_CLAIM {
                return Ok(world.is_none() && predicate.is_none());
            }
            let Some(body) = raw
                .get(crate::batch::ENTITY_METADATA_HEADER_LEN..)
                .and_then(|body| crate::claim::decode_claim_body(body, true).ok())
            else {
                return Ok(false);
            };
            Ok(claim_surfaceable(&body)
                && crate::claim::has_live_support_in_txn(store, txn, &body)?
                && body.world == world
                && predicate.is_none_or(|predicate| body.predicate == predicate))
        };
        let mut pack = self.recall_routed(
            None,
            query,
            Effort::Light,
            scope,
            limit,
            None,
            None,
            Some(&filter),
            &RecallExecution::default(),
            None,
        )?;
        let world_hex = world.map(|id| id.to_hex());
        pack.items.retain(|item| {
            item.world == world_hex
                && kind.is_none_or(|kind| item.kind == kind)
                && predicate.is_none_or(|predicate| item.predicate.as_deref() == Some(predicate))
        });
        Ok(pack)
    }

    /// Effort-dialed retrieval into an S6 `MemoryPack`.
    ///
    /// High, xhigh and max require a lease and a prepared reranker; use
    /// [`Self::recall_with_execution`] to supply execution inputs. The ordinary
    /// door refuses unsupported paid work instead of returning a fake success.
    /// Dense and phonetic inputs are optional, explicit host inputs.
    pub fn recall(
        &self,
        query: &str,
        effort: Effort,
        scope: &RecallScope,
        limit: usize,
        format: Option<&str>,
        lease: Option<&BudgetLease>,
    ) -> MemoryResult<MemoryPack> {
        self.recall_routed(
            None,
            query,
            effort,
            scope,
            limit,
            format,
            lease,
            None,
            &RecallExecution::default(),
            None,
        )
    }

    /// Runs the same recall body with dense input, prepared scoring and/or a deadline.
    #[expect(
        clippy::too_many_arguments,
        reason = "adds per-request execution inputs to recall"
    )]
    pub fn recall_with_execution(
        &self,
        query: &str,
        effort: Effort,
        scope: &RecallScope,
        limit: usize,
        format: Option<&str>,
        lease: Option<&BudgetLease>,
        execution: &RecallExecution<'_>,
    ) -> MemoryResult<MemoryPack> {
        self.recall_routed(
            None, query, effort, scope, limit, format, lease, None, execution, None,
        )
    }

    /// Recalls inside a session. Retrieval reads the room's overlay ∪ base
    /// under the same scope and gates (ARCH-0052 §2); every telemetry write
    /// (including the seed search and pack finalization) rides the one
    /// session route captured for this call. Off-record rows therefore
    /// evaporate with the room, never leaking into the base retrieval ledger.
    #[expect(
        clippy::too_many_arguments,
        reason = "recall's public parameter list plus the session it runs inside; the two \
                  doors must stay call-compatible, so neither may regroup its parameters"
    )]
    pub fn recall_in_session(
        &self,
        session: &crate::off_record::OffRecordSession<'_>,
        query: &str,
        effort: Effort,
        scope: &RecallScope,
        limit: usize,
        format: Option<&str>,
        lease: Option<&BudgetLease>,
    ) -> MemoryResult<MemoryPack> {
        self.recall_routed(
            Some(session),
            query,
            effort,
            scope,
            limit,
            format,
            lease,
            None,
            &RecallExecution::default(),
            None,
        )
    }

    /// Recall with explicit execution inputs, keeping all telemetry on the room route.
    #[expect(
        clippy::too_many_arguments,
        reason = "session sibling of recall_with_execution"
    )]
    pub fn recall_in_session_with_execution(
        &self,
        session: &crate::off_record::OffRecordSession<'_>,
        query: &str,
        effort: Effort,
        scope: &RecallScope,
        limit: usize,
        format: Option<&str>,
        lease: Option<&BudgetLease>,
        execution: &RecallExecution<'_>,
    ) -> MemoryResult<MemoryPack> {
        self.recall_routed(
            Some(session),
            query,
            effort,
            scope,
            limit,
            format,
            lease,
            None,
            execution,
            None,
        )
    }
}
