//! The in-process adapter: scoped reads against a live vault plus retrieval-budget control.

use crate::claim::{ScopedRead, ScopedReadActorKey};
use crate::context_pack::{
    ContextPack, ContextPackBuilder, ContextPackRetrievalBudget, DEFAULT_MAX_NEIGHBORS,
    EmptyContext, EmptyReason, FieldProfile, TokenAllocation,
};
use crate::pipeline::ScoredEntity;
use crate::registry::{
    ENTITY_TYPE_CLAIM, ENTITY_TYPE_FACET, ENTITY_TYPE_SUMMARY, ENTITY_TYPE_TURN,
};
use crate::vault::{HydratedShortId, Vault};

use super::context_pack::{
    ContextPackBudgetControls, ContextPackRetrievalBudgetControls, CoreContextPackRequest,
    CoreContextPackResponse,
};
use super::contract::{VaultReadMethod, VaultReadRequest, VaultReadResponse};
use super::error::{VaultReadError, VaultReadResult, engine_absent, engine_failure};
use super::projection::{
    batch_item_from_result, entity_record_from_parts, project_context_pack,
    project_memory_timeline, timeline_is_absent,
};
use super::sealed;
use super::types::{
    CoreBatchShortIdHydrateItem, CoreBatchShortIdHydrateRequest, CoreBatchShortIdHydrateResponse,
    CoreHydrateRequest, CoreHydrateResponse, CoreHydrateStatus, CoreMemoryTimelineRequest,
    CoreMemoryTimelineResponse, CoreQueryMeta, CoreQueryRequest, CoreQueryResponse,
    CoreShortIdHydrateOutcome, View, search_fetch_limit, search_total,
};
use super::validate::{
    non_empty_query, parse_short_ref, parse_short_ref_request, parse_timeline_anchor,
};

/// Embedded-host adapter. It stores an actor-keyed [`ScopedRead`] binding,
/// never a naked vault convenience client: proximity to `Vault` is never
/// authority. Each dispatch opens a fresh reader so its policy memo lasts only
/// for that request, not for the lifetime of the adapter.
pub struct InProcessVaultReadAdapter<'v> {
    scoped_read: ScopedRead<'v>,
}

impl<'v> InProcessVaultReadAdapter<'v> {
    /// The ONLY constructor: an actor key is mandatory, so no unkeyed bulk read
    /// handle can be built from this type.
    #[must_use]
    pub fn new(vault: &'v Vault, actor_key: ScopedReadActorKey) -> Self {
        Self {
            scoped_read: vault.scoped_read(actor_key),
        }
    }

    fn run_query(
        &self,
        query: Option<&str>,
        vector: Option<&[f32]>,
        limit: usize,
    ) -> VaultReadResult<Vec<ScoredEntity>> {
        let results = match (query, vector) {
            (Some(query), Some(vector)) => self.scoped_read.search(query, vector, limit, None),
            (Some(query), None) => self.scoped_read.search_text(query, limit, None),
            (None, Some(vector)) => self.scoped_read.search_vector(vector, limit, None),
            (None, None) => Ok(Vec::new()),
        };
        results.map_err(|error| engine_failure(VaultReadMethod::Query, &error))
    }

    fn query_op(&self, request: &CoreQueryRequest) -> VaultReadResult<CoreQueryResponse> {
        const METHOD: VaultReadMethod = VaultReadMethod::Query;

        let view = request.view.unwrap_or(View::Summary);
        let count_mode = request.count_mode.for_search_response();
        let fetch_limit = search_fetch_limit(count_mode, request.limit);
        let admitted = self.run_query(
            non_empty_query(request.query.as_deref()),
            request.query_vector.as_deref(),
            fetch_limit,
        )?;
        let total = admitted.len();
        let mut items = Vec::with_capacity(total.min(request.limit));
        for result in admitted {
            if items.len() >= request.limit {
                break;
            }
            let parts = self
                .scoped_read
                .get_entity_parts(&result.id)
                .map_err(|error| engine_failure(METHOD, &error))?;
            let Some((entity_type, learned_at, body)) = parts else {
                continue;
            };
            items.push(entity_record_from_parts(
                &result.id,
                entity_type,
                learned_at,
                Some(result.score),
                &body,
                view,
            ));
        }
        Ok(CoreQueryResponse {
            items,
            next_cursor: None,
            meta: CoreQueryMeta {
                total: search_total(count_mode, total),
                count_mode,
            },
        })
    }

    fn context_pack_op(
        &self,
        request: &CoreContextPackRequest,
    ) -> VaultReadResult<CoreContextPackResponse> {
        const METHOD: VaultReadMethod = VaultReadMethod::ContextPack;

        let query = non_empty_query(request.query.as_deref());
        let vector = request.query_vector.as_deref();
        let depth = request.resolved_depth();
        let edge_hop = depth.edge_hop.unwrap_or(0);
        let max_neighbors = depth.max_neighbors.unwrap_or(DEFAULT_MAX_NEIGHBORS);
        let candidate_limit = self
            .scoped_read
            .search_candidate_limit(request.limit, query.is_some(), vector.is_some())
            .map_err(|error| engine_failure(METHOD, &error))?;
        let mut builder = self
            .scoped_read
            .vault()
            .context_pack()
            .limit(candidate_limit)
            .hydrate(true)
            .include_edges(false)
            .include_vectors(false)
            .edge_hop(edge_hop)
            .max_neighbors(max_neighbors)
            .field_profile(FieldProfile::Standard);
        if let Some(query) = query {
            builder = builder.search_text(query, candidate_limit);
        }
        if let Some(vector) = vector {
            builder = builder.search_vector(vector, candidate_limit);
        }
        let (builder, response_budget) = apply_budget_controls(
            builder,
            request.budget.as_ref(),
            candidate_limit,
            request.limit,
            max_neighbors,
        );

        // UNFINALIZED on purpose (ONE-1433 X1): the assembly registers only a
        // PROVISIONAL retrieval-run row here and publishes nothing until every
        // filter below has run. Finalizing first — what `run()` does — would
        // commit the PRE-filter result ids, score components and trace
        // candidacy of entities this actor may not see into the durable
        // telemetry ledger, where `Vault::retrieval_runs` publishes them. This
        // mirrors the accepted route's `run_context_pack_builder`.
        let mut pack = builder
            .run_unfinalized_with_telemetry()
            .map_err(|error| engine_failure(METHOD, &error))?;
        // Re-clamp immediately: the builder was entered through the accepted
        // door, and nothing leaves this method unfiltered. A failed filter
        // discards the provisional row before the error returns, so a refused
        // read leaves no residue behind it.
        self.scoped_read
            .filter_context_pack(&mut pack.value)
            .map_err(|error| {
                pack.discard_telemetry();
                engine_failure(METHOD, &error)
            })?;
        // The widened budget only ever fed retrieval, so the answered pack is
        // bound by the UNWIDENED response budget after filtering, exactly like
        // the accepted route's `apply_context_pack_response_limits`.
        apply_context_pack_response_retrieval_budget(&mut pack.value, response_budget);
        pack.value.results.truncate(request.limit);
        pack.value.neighbors.truncate(max_neighbors);
        scrub_context_pack_visible_stats(&mut pack.value);
        // Publish LAST, off the post-filter, post-truncate pack: the durable
        // run row then carries exactly the ids this actor received, so a
        // denied entity is as absent from telemetry as it is from the
        // response. Finalize failure still fails the read, as it did through
        // `run()`.
        let pack = pack
            .finish_post_filter()
            .map_err(|error| engine_failure(METHOD, &error))?;
        Ok(CoreContextPackResponse(project_context_pack(&pack.value)))
    }

    /// Hydrates ONE short ref for `method` — the CALLING method, which is the
    /// identity every error this helper mints must carry. A batch item is
    /// served by the same code as a single hydrate, but an error that aborts
    /// the batch is an error of `HydrateMany`, so the identity is a parameter
    /// rather than a constant pinned to the single-ref method.
    fn hydrate_ref(
        &self,
        method: VaultReadMethod,
        short_id: String,
        content_hash: u8,
        view: View,
    ) -> VaultReadResult<CoreHydrateResponse> {
        let hydrated = self
            .scoped_read
            .hydrate_short_id(&short_id, content_hash)
            .map_err(|error| engine_failure(method, &error))?;
        // A missing row and a clamp-denied claim are the SAME answer here. The
        // adapter never probes the naked vault to tell them apart.
        let Some(HydratedShortId {
            id,
            entity_type,
            learned_at,
            deletion,
            body,
        }) = hydrated
        else {
            return Err(engine_absent(method, "short_id"));
        };
        let content_hash = format!("{content_hash:02x}");
        let Some(body) = body else {
            return Ok(CoreHydrateResponse {
                status: CoreHydrateStatus::Deleted,
                short_id,
                content_hash,
                id: Some(id.to_hex()),
                entity_type: (entity_type != 0).then_some(entity_type),
                deletion,
                item: None,
            });
        };
        let item = entity_record_from_parts(&id, entity_type, learned_at, None, &body, view);
        Ok(CoreHydrateResponse {
            status: CoreHydrateStatus::Live,
            short_id,
            content_hash,
            id: Some(id.to_hex()),
            entity_type: Some(entity_type),
            deletion: None,
            item: Some(item),
        })
    }

    fn hydrate_op(&self, request: &CoreHydrateRequest) -> VaultReadResult<CoreHydrateResponse> {
        let (short_id, content_hash) = parse_short_ref_request(request)?;
        self.hydrate_ref(
            VaultReadMethod::Hydrate,
            short_id,
            content_hash,
            request.view.unwrap_or(View::Full),
        )
    }

    fn hydrate_batch_item(
        &self,
        reference: &str,
        view: View,
    ) -> VaultReadResult<CoreBatchShortIdHydrateItem> {
        const METHOD: VaultReadMethod = VaultReadMethod::HydrateMany;

        let Ok((short_id, content_hash)) = parse_short_ref(METHOD, reference) else {
            return Ok(CoreBatchShortIdHydrateItem {
                reference: reference.to_owned(),
                outcome: CoreShortIdHydrateOutcome::MalformedShortId,
                result: None,
            });
        };
        batch_item_from_result(
            reference.to_owned(),
            self.hydrate_ref(METHOD, short_id, content_hash, view),
        )
    }

    fn hydrate_many_op(
        &self,
        request: &CoreBatchShortIdHydrateRequest,
    ) -> VaultReadResult<CoreBatchShortIdHydrateResponse> {
        let view = request.view.unwrap_or(View::Full);
        let mut results = Vec::with_capacity(request.refs.len());
        for reference in &request.refs {
            results.push(self.hydrate_batch_item(reference, view)?);
        }
        Ok(CoreBatchShortIdHydrateResponse { results })
    }

    fn memory_timeline_op(
        &self,
        request: &CoreMemoryTimelineRequest,
    ) -> VaultReadResult<CoreMemoryTimelineResponse> {
        const METHOD: VaultReadMethod = VaultReadMethod::MemoryTimeline;

        let anchor = parse_timeline_anchor(request)?;
        let timeline = self
            .scoped_read
            .memory_timeline(&anchor)
            .map_err(|error| engine_failure(METHOD, &error))?;
        if timeline_is_absent(&timeline) {
            return Err(engine_absent(METHOD, "entity"));
        }
        Ok(project_memory_timeline(&timeline))
    }
}

/// Mirrors the accepted route's budget application: the WIDENED internal
/// retrieval budget goes on the builder so it survives scoped-read clamping,
/// and the UNWIDENED response budget is returned to bind the answered pack.
fn apply_budget_controls<'a>(
    mut builder: ContextPackBuilder<'a>,
    budget: Option<&ContextPackBudgetControls>,
    candidate_limit: usize,
    result_limit: usize,
    default_selected_edges: usize,
) -> (ContextPackBuilder<'a>, ContextPackRetrievalBudget) {
    if let Some(controls) = budget {
        if let Some(max_item_tokens) = controls.max_item_tokens
            && max_item_tokens > 0
        {
            builder = builder.max_item_tokens(max_item_tokens);
        }
        if let Some(token_budget) = controls.token_budget {
            builder = builder.token_budget(token_budget);
        }
        if let Some(max_field_chars) = controls.max_field_chars {
            builder = builder.max_field_chars(max_field_chars);
        }
    }
    let retrieval = budget.and_then(|controls| controls.retrieval.as_ref());
    let response_budget = resolve_retrieval_budget(retrieval, result_limit, default_selected_edges);
    let builder =
        builder.retrieval_budget(widen_retrieval_budget(response_budget, candidate_limit));
    (builder, response_budget)
}

/// Accepted per-kind response budget, copied from the accepted route's
/// `apply_context_pack_response_retrieval_budget`: each retrieval kind keeps at
/// most its own unwidened item budget, in pack order.
fn apply_context_pack_response_retrieval_budget(
    pack: &mut ContextPack,
    budget: ContextPackRetrievalBudget,
) {
    let mut claims = 0_usize;
    let mut turns = 0_usize;
    let mut summaries = 0_usize;
    let mut facets = 0_usize;
    let mut other = 0_usize;
    pack.results.retain(|entity| {
        let (count, limit) = match entity.entity_type {
            ENTITY_TYPE_CLAIM => (&mut claims, budget.claims),
            ENTITY_TYPE_TURN => (&mut turns, budget.turns),
            ENTITY_TYPE_SUMMARY => (&mut summaries, budget.summaries),
            ENTITY_TYPE_FACET => (&mut facets, budget.facets),
            _ => (&mut other, budget.other),
        };
        if *count >= limit {
            return false;
        }
        *count += 1;
        true
    });
}

/// Accepted visible-stat scrub, copied from the accepted route's
/// `scrub_context_pack_visible_stats`: the counters a caller can see describe
/// the pack it actually received, never the wider internal retrieval.
pub(super) fn scrub_context_pack_visible_stats(pack: &mut ContextPack) {
    pack.stats.candidates_considered = pack.results.len();
    pack.stats.entities_hydrated = pack.results.len();
    pack.stats.neighbors_hydrated = pack.neighbors.len();

    if pack.results.is_empty() && pack.neighbors.is_empty() {
        if let Some(empty) = pack.empty.as_mut() {
            empty.total_in_scope = 0;
        } else {
            pack.empty = Some(EmptyContext {
                retrieval_quality: pack.retrieval_quality.clone(),
                reason: EmptyReason::FilterMatchedNone,
                total_in_scope: 0,
                hint: "Try removing filters or widening the world, type, or time scope".to_owned(),
            });
        }
    } else {
        pack.empty = None;
    }
}

fn resolve_retrieval_budget(
    retrieval: Option<&ContextPackRetrievalBudgetControls>,
    result_limit: usize,
    default_selected_edges: usize,
) -> ContextPackRetrievalBudget {
    let selected_edges = retrieval
        .and_then(|retrieval| retrieval.selected_edges)
        .unwrap_or(default_selected_edges);
    let mut budget = ContextPackRetrievalBudget::from_limit(
        result_limit,
        TokenAllocation::default(),
        selected_edges,
    );
    if let Some(retrieval) = retrieval {
        budget.claims = retrieval.claims.unwrap_or(budget.claims);
        budget.turns = retrieval.turns.unwrap_or(budget.turns);
        budget.summaries = retrieval.summaries.unwrap_or(budget.summaries);
        budget.facets = retrieval.facets.unwrap_or(budget.facets);
        budget.other = retrieval.other.unwrap_or(budget.other);
    }
    budget
}

fn widen_retrieval_budget(
    budget: ContextPackRetrievalBudget,
    candidate_limit: usize,
) -> ContextPackRetrievalBudget {
    let widen = |bucket: usize| {
        if bucket == 0 {
            0
        } else {
            bucket.max(candidate_limit)
        }
    };
    ContextPackRetrievalBudget::new(
        widen(budget.claims),
        widen(budget.turns),
        widen(budget.summaries),
        widen(budget.facets),
        widen(budget.other),
        budget.selected_edges,
    )
}

impl sealed::Backend for InProcessVaultReadAdapter<'_> {
    fn dispatch_validated(
        &self,
        request: sealed::ValidatedVaultReadRequest,
    ) -> VaultReadResult<VaultReadResponse> {
        // Policy is memoized by ScopedRead. Never execute through the retained
        // binding: a grant may have been revoked or narrowed since the last call.
        let reader = Self::new(
            self.scoped_read.vault(),
            self.scoped_read.actor_key().clone(),
        );
        match request.into_inner() {
            VaultReadRequest::Query(request) => {
                reader.query_op(&request).map(VaultReadResponse::Query)
            }
            VaultReadRequest::ContextPack(request) => reader
                .context_pack_op(&request)
                .map(VaultReadResponse::ContextPack),
            VaultReadRequest::Hydrate(request) => {
                reader.hydrate_op(&request).map(VaultReadResponse::Hydrate)
            }
            VaultReadRequest::HydrateMany(request) => reader
                .hydrate_many_op(&request)
                .map(VaultReadResponse::HydrateMany),
            VaultReadRequest::MemoryTimeline(request) => reader
                .memory_timeline_op(&request)
                .map(VaultReadResponse::MemoryTimeline),
            // Unreachable through the generated wrappers, which refuse runtime
            // peers before validation; kept total and identical anyway.
            runtime => Err(VaultReadError::RuntimeUnavailable {
                method: runtime.method(),
            }),
        }
    }
}
