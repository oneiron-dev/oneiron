//! Route handler plus depth/policy/time/budget resolution for context-pack assembly.

use super::super::{
    MemoriesRequest, core_engine_error, json_payload, non_empty_query, scoped_read_for_core_auth,
    validate_core_query_seeds,
};
use super::controls::{
    ContextPackBudgetControls, ContextPackDepthControls, ContextPackPolicyControls,
    ContextPackRetrievalBudgetControls, ContextPackTimeControls, CoreContextPackRequest,
};
use super::resolve_core_interlocutor_set;
use super::response::{
    CoreContextPackResponse, context_pack_json_projection_config, run_context_pack_builder,
};
use crate::auth::CoreAuth;
use crate::auth::CoreScope;
use crate::error::ApiError;
use crate::error::ApiErrorEnvelope;
use crate::error::EnvelopedApiError;
use crate::projection::View;
use crate::server::SyncServer;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::response::Json;
use std::sync::Arc;

/// Assemble a context pack from existing retrieval and hydration APIs.
#[utoipa::path(
    post,
    path = "/v1/core/context-pack",
    request_body(content = CoreContextPackRequest, content_type = "application/json"),
    responses(
        (status = 200, description = "Context pack assembled.", body = CoreContextPackResponse, content_type = "application/json"),
        (status = 400, description = "Malformed context-pack request.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 401, description = "Missing or invalid core auth.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 403, description = "Core token lacks core:read.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 500, description = "Context-pack assembly failed.", body = ApiErrorEnvelope, content_type = "application/json")
    )
)]
pub(crate) async fn core_context_pack(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<CoreContextPackRequest>, JsonRejection>,
) -> Result<Json<CoreContextPackResponse>, EnvelopedApiError> {
    auth.require(CoreScope::Read)?;
    let req = json_payload(payload)?;
    let (response, _, _) = run_context_pack(&server, &auth, req, None).await?;
    Ok(Json(response))
}

/// The shared context-pack pipeline behind `/v1/core/context-pack` and the
/// context board: validation, scoped retrieval, projection, and evidence.
///
/// When a memories request rides along, the MEMORIES section is projected
/// over the finished pack and the caller's cursor is advanced; both come back
/// beside the response. The caller has already required `CoreScope::Read`.
pub(crate) async fn run_context_pack(
    server: &SyncServer,
    auth: &CoreAuth,
    req: CoreContextPackRequest,
    memories: Option<MemoriesRequest>,
) -> Result<
    (
        CoreContextPackResponse,
        Option<oneiron::MemoriesSection>,
        Option<oneiron::MemoriesCursor>,
    ),
    ApiError,
> {
    let interlocutors =
        resolve_core_interlocutor_set(&server.vault, auth, req.interlocutors.as_ref())?;
    let query = non_empty_query(req.query.as_deref());
    validate_core_query_seeds(query, req.query_vector.as_deref())?;
    let (edge_hop, edge_hop_field, max_neighbors, max_neighbors_field) =
        resolved_context_pack_depth(req.depth.as_ref(), req.edge_hop, req.max_neighbors);
    validate_context_pack_depth(edge_hop, edge_hop_field, max_neighbors, max_neighbors_field)?;
    let hydrate = req
        .policy
        .as_ref()
        .and_then(|policy| policy.hydrate)
        .unwrap_or(req.hydrate);
    let include_edges = req
        .policy
        .as_ref()
        .and_then(|policy| policy.include_edges)
        .unwrap_or(req.include_edges);
    let include_vectors = req
        .policy
        .as_ref()
        .and_then(|policy| policy.include_vectors)
        .unwrap_or(req.include_vectors);
    let view = req
        .policy
        .as_ref()
        .and_then(|policy| policy.view)
        .or(req.view)
        .unwrap_or(View::Standard);
    let projection = context_pack_json_projection_config(view, req.budget.as_ref());
    let scoped_read = scoped_read_for_core_auth(&server.vault, auth)?;
    let candidate_limit = scoped_read
        .search_candidate_limit(req.limit, query.is_some(), req.query_vector.is_some())
        .map_err(|error| {
            tracing::error!(error = %error, "core context-pack scoped read setup failed");
            core_engine_error("core context-pack scoped read setup failed", error)
        })?;
    // OF-365 ILD-2: one DisclosureContext value feeds builder, board, and
    // response, so the response can never describe a different clamp than
    // the one applied (design §11 rule 6).
    let disclosure = interlocutors
        .as_ref()
        .map(|set| oneiron::DisclosureContext::resolve(&server.vault, set.clone()))
        .transpose()
        .map_err(|error| {
            tracing::error!(error = %error, "core context-pack disclosure resolution failed");
            core_engine_error("core context-pack disclosure resolution failed", error)
        })?;

    let mut builder = server
        .vault
        .context_pack()
        .limit(candidate_limit)
        .hydrate(hydrate)
        .include_edges(include_edges)
        .edge_hop(edge_hop)
        .max_neighbors(max_neighbors)
        .include_vectors(include_vectors)
        .field_profile(projection.profile);
    if let Some(query) = query {
        builder = builder.search_text(query, candidate_limit);
    }
    if let Some(vector) = req.query_vector.as_deref() {
        builder = builder.search_vector(vector, candidate_limit);
    }
    builder = apply_context_pack_policy(builder, req.policy.as_ref())?;
    builder = apply_context_pack_time(builder, req.time.as_ref())?;
    let (mut builder, retrieval_budget) = apply_context_pack_budget(
        builder,
        req.budget.as_ref(),
        candidate_limit,
        req.limit,
        max_neighbors,
    )?;
    if let Some(ctx) = disclosure.as_ref() {
        builder = builder.disclosure_context(ctx.clone());
    }

    let (mut response, memories, cursor) = run_context_pack_builder(
        &server.vault,
        &scoped_read,
        builder,
        projection,
        ContextPackResponseLimits {
            results: req.limit,
            neighbors: max_neighbors,
            retrieval: retrieval_budget,
        },
        memories,
        disclosure,
    )
    .await?;
    response.interlocutors = interlocutors.as_ref().map(oneiron::InterlocutorSet::stamps);
    Ok((response, memories, cursor))
}

pub(crate) fn resolved_context_pack_depth(
    depth: Option<&ContextPackDepthControls>,
    edge_hop: u32,
    max_neighbors: usize,
) -> (u32, &'static str, usize, &'static str) {
    let depth_edge_hop = depth.and_then(|depth| depth.edge_hop);
    let depth_max_neighbors = depth.and_then(|depth| depth.max_neighbors);
    (
        depth_edge_hop.unwrap_or(edge_hop),
        if depth_edge_hop.is_some() {
            "depth.edge_hop"
        } else {
            "edge_hop"
        },
        depth_max_neighbors.unwrap_or(max_neighbors),
        if depth_max_neighbors.is_some() {
            "depth.max_neighbors"
        } else {
            "max_neighbors"
        },
    )
}

pub(crate) fn validate_context_pack_depth(
    edge_hop: u32,
    edge_hop_field: &'static str,
    max_neighbors: usize,
    max_neighbors_field: &'static str,
) -> Result<(), ApiError> {
    if edge_hop > oneiron::context_pack::MAX_EDGE_HOP {
        return Err(ApiError::bad_request(
            format!(
                "edge_hop must be less than or equal to {}",
                oneiron::context_pack::MAX_EDGE_HOP
            ),
            Some(edge_hop_field),
        ));
    }
    if max_neighbors > oneiron::context_pack::MAX_CONTEXT_NEIGHBORS {
        return Err(ApiError::bad_request(
            format!(
                "max_neighbors must be less than or equal to {}",
                oneiron::context_pack::MAX_CONTEXT_NEIGHBORS
            ),
            Some(max_neighbors_field),
        ));
    }
    Ok(())
}

pub(crate) fn default_true() -> bool {
    true
}

pub(crate) fn default_context_neighbors() -> usize {
    50
}

pub(crate) fn apply_context_pack_policy<'a>(
    mut builder: oneiron::ContextPackBuilder<'a>,
    policy: Option<&ContextPackPolicyControls>,
) -> Result<oneiron::ContextPackBuilder<'a>, ApiError> {
    let Some(policy) = policy else {
        return Ok(builder);
    };
    if let Some(half_life_days) = policy.boost_recency_days {
        if !half_life_days.is_finite() || half_life_days <= 0.0 {
            return Err(ApiError::bad_request(
                "boost_recency_days must be finite and positive",
                Some("policy.boost_recency_days"),
            ));
        }
        builder = builder.boost_recency(half_life_days);
    }
    if policy.boost_salience.unwrap_or(false) {
        builder = builder.boost_salience();
    }
    if policy.boost_confidence.unwrap_or(false) {
        builder = builder.boost_confidence();
    }
    if policy.boost_contiguity.unwrap_or(false) {
        builder = builder.boost_contiguity();
    }
    Ok(builder)
}

pub(crate) fn apply_context_pack_time<'a>(
    mut builder: oneiron::ContextPackBuilder<'a>,
    time: Option<&ContextPackTimeControls>,
) -> Result<oneiron::ContextPackBuilder<'a>, ApiError> {
    let Some(time) = time else {
        return Ok(builder);
    };
    let occurred_range = match (time.occurred_start, time.occurred_end) {
        (Some(start), Some(end)) if start <= end => Some((start, end)),
        (Some(_), Some(_)) => {
            return Err(ApiError::bad_request(
                "occurred_start must be less than or equal to occurred_end",
                Some("time.occurred_start"),
            ));
        }
        (Some(_), None) | (None, Some(_)) => {
            return Err(ApiError::bad_request(
                "occurred_start and occurred_end must be supplied together",
                Some("time"),
            ));
        }
        (None, None) => None,
    };
    let learned_range = match (time.learned_start, time.learned_end) {
        (Some(start), Some(end)) if start <= end => Some((start, end)),
        (Some(_), Some(_)) => {
            return Err(ApiError::bad_request(
                "learned_start must be less than or equal to learned_end",
                Some("time.learned_start"),
            ));
        }
        (Some(_), None) | (None, Some(_)) => {
            return Err(ApiError::bad_request(
                "learned_start and learned_end must be supplied together",
                Some("time"),
            ));
        }
        (None, None) => None,
    };
    if let (Some(since), Some((_, learned_end))) = (time.since, learned_range)
        && since > learned_end
    {
        return Err(ApiError::bad_request(
            "since must be less than or equal to learned_end",
            Some("time.since"),
        ));
    }
    if let Some(since) = time.since {
        builder = builder.filter_since(since);
    }
    if let Some((start, end)) = occurred_range {
        builder = builder.filter_occurred_range(start, end);
    }
    if let Some((start, end)) = learned_range {
        builder = builder.filter_learned_range(start, end);
    }
    Ok(builder)
}

pub(crate) fn apply_context_pack_budget<'a>(
    mut builder: oneiron::ContextPackBuilder<'a>,
    budget: Option<&ContextPackBudgetControls>,
    scoped_candidate_limit: usize,
    result_limit: usize,
    default_selected_edges: usize,
) -> Result<
    (
        oneiron::ContextPackBuilder<'a>,
        oneiron::ContextPackRetrievalBudget,
    ),
    ApiError,
> {
    if let Some(max_item_tokens) = budget.and_then(|budget| budget.max_item_tokens)
        && max_item_tokens > 0
    {
        builder = builder.max_item_tokens(max_item_tokens);
    }
    if let Some(budget) = budget {
        if let Some(token_budget) = budget.token_budget {
            builder = builder.token_budget(token_budget);
        }
        if let Some(max_field_chars) = budget.max_field_chars {
            builder = builder.max_field_chars(max_field_chars);
        }
    }
    let retrieval = budget.and_then(|budget| budget.retrieval.as_ref());
    if let Some(retrieval) = retrieval
        && retrieval.selected_edges.is_some_and(|selected_edges| {
            selected_edges > oneiron::context_pack::MAX_CONTEXT_NEIGHBORS
        })
    {
        return Err(ApiError::bad_request(
            format!(
                "selected_edges must be less than or equal to {}",
                oneiron::context_pack::MAX_CONTEXT_NEIGHBORS
            ),
            Some("budget.retrieval.selected_edges"),
        ));
    }
    let (response_budget, internal_budget) = resolve_context_pack_retrieval_budgets(
        retrieval,
        result_limit,
        scoped_candidate_limit,
        default_selected_edges,
    );
    builder = builder.retrieval_budget(internal_budget);
    Ok((builder, response_budget))
}

pub(crate) fn resolve_context_pack_retrieval_budgets(
    retrieval: Option<&ContextPackRetrievalBudgetControls>,
    result_limit: usize,
    scoped_candidate_limit: usize,
    default_selected_edges: usize,
) -> (
    oneiron::ContextPackRetrievalBudget,
    oneiron::ContextPackRetrievalBudget,
) {
    let selected_edges = retrieval
        .and_then(|retrieval| retrieval.selected_edges)
        .unwrap_or(default_selected_edges);
    let mut response_budget = oneiron::ContextPackRetrievalBudget::from_limit(
        result_limit,
        oneiron::TokenAllocation::default(),
        selected_edges,
    );
    if let Some(retrieval) = retrieval {
        if let Some(claims) = retrieval.claims {
            response_budget.claims = claims;
        }
        if let Some(turns) = retrieval.turns {
            response_budget.turns = turns;
        }
        if let Some(summaries) = retrieval.summaries {
            response_budget.summaries = summaries;
        }
        if let Some(facets) = retrieval.facets {
            response_budget.facets = facets;
        }
        if let Some(other) = retrieval.other {
            response_budget.other = other;
        }
    }
    let internal_budget =
        widen_context_pack_retrieval_budget(response_budget, scoped_candidate_limit);
    (response_budget, internal_budget)
}

pub(crate) fn widen_context_pack_retrieval_budget(
    budget: oneiron::ContextPackRetrievalBudget,
    scoped_candidate_limit: usize,
) -> oneiron::ContextPackRetrievalBudget {
    let widen = |bucket: usize| {
        if bucket == 0 {
            0
        } else {
            bucket.max(scoped_candidate_limit)
        }
    };
    oneiron::ContextPackRetrievalBudget::new(
        widen(budget.claims),
        widen(budget.turns),
        widen(budget.summaries),
        widen(budget.facets),
        widen(budget.other),
        budget.selected_edges,
    )
}

#[derive(Clone, Copy)]
pub(crate) struct ContextPackResponseLimits {
    pub(crate) results: usize,
    pub(crate) neighbors: usize,
    pub(crate) retrieval: oneiron::ContextPackRetrievalBudget,
}

pub(crate) fn apply_context_pack_response_limits(
    pack: &mut oneiron::ContextPack,
    limits: ContextPackResponseLimits,
) {
    apply_context_pack_response_retrieval_budget(pack, limits.retrieval);
    pack.results.truncate(limits.results);
    pack.neighbors.truncate(limits.neighbors);
    scrub_context_pack_visible_stats(pack);
}

pub(crate) fn apply_context_pack_response_retrieval_budget(
    pack: &mut oneiron::ContextPack,
    budget: oneiron::ContextPackRetrievalBudget,
) {
    let mut claims = 0_usize;
    let mut turns = 0_usize;
    let mut summaries = 0_usize;
    let mut facets = 0_usize;
    let mut other = 0_usize;
    pack.results.retain(|entity| {
        let (count, limit) = match entity.entity_type {
            oneiron::registry::ENTITY_TYPE_CLAIM => (&mut claims, budget.claims),
            oneiron::registry::ENTITY_TYPE_TURN => (&mut turns, budget.turns),
            oneiron::registry::ENTITY_TYPE_SUMMARY => (&mut summaries, budget.summaries),
            oneiron::registry::ENTITY_TYPE_FACET => (&mut facets, budget.facets),
            _ => (&mut other, budget.other),
        };
        if *count >= limit {
            return false;
        }
        *count += 1;
        true
    });
}

pub(crate) fn scrub_context_pack_visible_stats(pack: &mut oneiron::ContextPack) {
    pack.stats.candidates_considered = pack.results.len();
    pack.stats.entities_hydrated = pack.results.len();
    pack.stats.neighbors_hydrated = pack.neighbors.len();

    if pack.results.is_empty() && pack.neighbors.is_empty() {
        if let Some(empty) = pack.empty.as_mut() {
            empty.total_in_scope = 0;
        } else {
            pack.empty = Some(oneiron::EmptyContext {
                retrieval_quality: pack.retrieval_quality.clone(),
                reason: oneiron::EmptyReason::FilterMatchedNone,
                total_in_scope: 0,
                hint: "Try removing filters or widening the world, type, or time scope".to_owned(),
            });
        }
    } else {
        pack.empty = None;
    }
}
