//! Route handler plus depth/policy/time/budget resolution for context-pack assembly.

use super::super::{
    MemoriesRequest, core_engine_error, json_payload, non_empty_query, scoped_read_for_core_auth,
    validate_core_query_seeds,
};
use super::controls::{
    ContextPackBudgetControls, ContextPackDepthControls, ContextPackPolicyControls,
    ContextPackRetrievalBudgetControls, ContextPackTimeControls, CoreContextPackRequest,
};
use super::media_query::embed_media_seeds;
use super::response::{
    CoreContextPackResponse, CoreReactionSignal, context_pack_json_projection_config,
    run_context_pack_builder,
};
use super::{
    RoomAudience, narrow_to_reader, reader_optional_memory, resolve_core_disclosure_with_once,
    resolve_core_interlocutor_set, spend_core_once_disclosures,
};
use crate::auth::CoreAuth;
use crate::auth::CoreScope;
use crate::error::ApiError;
use crate::error::ApiErrorEnvelope;
use crate::error::EnvelopedApiError;
use crate::projection::View;
use crate::server::{QueryDoor, SyncServer};
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
        (status = 403, description = "Core token lacks core:read, or the vault's inference policy refuses a media query's ai.embed call.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 500, description = "Context-pack assembly failed.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 503, description = "No ai.embed rung serves a media query's space (or, on the one-space preset, the text slot's space), or the rung's call failed.", body = ApiErrorEnvelope, content_type = "application/json")
    )
)]
pub(crate) async fn core_context_pack(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<CoreContextPackRequest>, JsonRejection>,
) -> Result<Json<CoreContextPackResponse>, EnvelopedApiError> {
    auth.require(CoreScope::Read)?;
    // The pack echoes the room's roster and its pre-filter counts, which no
    // lane judges, so a facet narrowing is refused rather than half kept.
    auth.require_unnarrowed_facets()?;
    let req = json_payload(payload)?;
    req.check_query_bytes(&server, &auth, QueryDoor::ContextPack, "query")?;
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
    mut req: CoreContextPackRequest,
    memories: Option<MemoriesRequest>,
) -> Result<
    (
        CoreContextPackResponse,
        Option<oneiron::MemoriesSection>,
        Option<oneiron::MemoriesCursor>,
    ),
    ApiError,
> {
    // An over-large limit is served at the ceiling, before anything sizes
    // work from it.
    req.clamp_limits();
    // Every ref the request names resolves under the caller's own read: a
    // room or contact it cannot read is one that does not exist. A room's
    // members read its roster by membership, as their room turns do.
    let scoped_read = scoped_read_for_core_auth(&server.vault, auth)?;
    let optional_memory = reader_optional_memory(&scoped_read, req.reader.as_ref())?;
    let principal = auth
        .principal_ref()
        .and_then(|id| oneiron::EntityId::from_hex(id).ok());
    let room_id = req
        .conversation_id
        .as_deref()
        .map(|room| super::super::parse_entity_id_param(room, "conversation_id"))
        .transpose()?;
    let room_members = room_id
        .map(|room| {
            server
                .vault
                .room_audience_members_under(&scoped_read, room, principal)
                .map_err(|error| core_engine_error("room audience failed", error))
        })
        .transpose()?;
    let room = room_members
        .as_deref()
        .map(|members| RoomAudience::resolve(&server.vault, auth, members))
        .transpose()?;
    let interlocutors = resolve_core_interlocutor_set(
        &server.vault,
        auth,
        &scoped_read,
        req.interlocutors.as_ref(),
        room.as_ref(),
    )?;
    let query = non_empty_query(req.query.as_deref());
    // A media query seeds the pack on its own; a vector beside it is still
    // checked.
    validate_core_query_seeds(
        query.or(req.media.as_ref().map(|_| "media")),
        req.query_vector.as_deref(),
    )?;
    let media = req
        .media
        .as_ref()
        .map(|media| media.decode(server.config.limits.retrieval_query_bytes))
        .transpose()?;
    let skill_reliability = req.skill_reliability_query(&server.vault)?;
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
    let mut view = req
        .policy
        .as_ref()
        .and_then(|policy| policy.view)
        .or(req.view)
        .unwrap_or(View::Standard);
    let skip_optional_recall =
        optional_memory.is_some_and(|choice| narrow_to_reader(&mut req.budget, &mut view, choice));
    let projection = context_pack_json_projection_config(view, req.budget.as_ref());
    let scoped_read = if let (Some(members), Some(room)) = (room_members.as_deref(), &room) {
        // Every row a room reads lies in its members' met world set, as a
        // room turn's ceiling holds it (ARCH-0067 §8).
        let scoped_read = match server
            .vault
            .room_world_set(members)
            .map_err(|e| core_engine_error("room world set failed", e))?
        {
            Some(worlds) => scoped_read.within_worlds(worlds),
            None => scoped_read,
        };
        scoped_read
            .for_audience(members)
            .with_peer_reads(room.agent_reads())
    } else if let Some(set) = interlocutors.as_ref().filter(|set| set.has_non_owner()) {
        // Contact records are not PERSON identities. Only a unique explicit
        // person link may resolve one; unresolved participants fail closed.
        let mut audience = Vec::new();
        let mut unresolved = false;
        if let Some(actor) = auth.principal_ref() {
            audience.push(super::super::parse_entity_id_param(actor, "principal_ref")?);
        }
        for party in set.non_owner() {
            let Some(contact) = party
                .contact_ref()
                .and_then(|id| oneiron::EntityId::from_hex(id).ok())
            else {
                unresolved = true;
                break;
            };
            let people = server
                .vault
                .targets(
                    &contact,
                    oneiron::EdgeKind::About,
                    Some(oneiron::registry::ENTITY_TYPE_PERSON),
                )
                .map_err(|e| core_engine_error("audience person resolution failed", e))?;
            if people.len() != 1 {
                unresolved = true;
                break;
            }
            audience.push(people[0]);
        }
        if unresolved {
            audience.clear();
        }
        scoped_read.for_audience(&audience)
    } else {
        scoped_read
    };
    let candidate_limit = scoped_read
        .search_candidate_limit(req.limit)
        .map_err(|error| {
            tracing::error!(kind = ?error.kind(), "core context-pack scoped read setup failed");
            core_engine_error("core context-pack scoped read setup failed", error)
        })?;
    // Embedded once everything free is checked: it is a paid call. On the
    // one-space preset the text query is embedded into the text slot's space.
    let media = embed_media_seeds(server, media, query).await?;

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
    if let Some(model) = req.executor_model.as_deref() {
        builder = builder
            .skill_executor(model)
            .map_err(|error| core_engine_error("invalid context-pack executor model", error))?;
    }
    if let Some(query) = skill_reliability {
        builder = builder
            .skill_reliability_context(query)
            .map_err(|error| core_engine_error("invalid context-pack skill type", error))?;
    }
    if let Some(query) = query {
        builder = builder.search_text(query, candidate_limit);
    }
    if let Some(vector) = req.query_vector.as_deref() {
        builder = builder.search_vector(vector, candidate_limit);
    }
    for seed in &media {
        builder = builder.search_media(
            &seed.space,
            seed.kind,
            &seed.vector,
            &seed.kinds,
            candidate_limit,
        );
    }
    if let Some(affect) = req.query_affect {
        builder = builder.query_affect(affect.vad()?);
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
    // OF-365: the owner's once answers for a contact present are spent here,
    // after every request check, and reach this assembly alone.
    let once = spend_core_once_disclosures(
        &server.vault,
        interlocutors.as_ref(),
        room_id,
        req.interlocutors
            .as_ref()
            .and_then(|controls| controls.voice_session_ref.as_deref()),
    )?;
    // OF-365 ILD-2: one DisclosureContext value feeds builder, board, and
    // response, so the response can never describe a different clamp than
    // the one applied (design §11 rule 6).
    let disclosure = resolve_core_disclosure_with_once(
        &server.vault,
        interlocutors.as_ref(),
        room.as_ref().map(|room| room.reader.is_some()),
        &once,
    )?;
    if let Some(ctx) = disclosure.as_ref() {
        builder = builder.disclosure_context(ctx.clone());
    }
    if skip_optional_recall {
        builder = builder.skip_optional_recall();
    }
    // Reaction signals ride the same clamp as the pack they come with.
    let signal_disclosure = disclosure.clone();

    let track_plain_pack = memories.is_none();
    let (mut response, memories, cursor) = run_context_pack_builder(
        server,
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
    if track_plain_pack {
        let caller = auth.principal_ref().unwrap_or(auth.principal()).trim();
        if let Some(mut observed) =
            super::super::session_read_set(server, caller, req.session_id.as_deref()).await?
        {
            let mut staged = observed.clone();
            response
                .observe_rows(&scoped_read, &mut staged)
                .map_err(|error| core_engine_error("context-pack observations failed", error))?;
            *observed = staged;
        }
    }
    read_reaction_signals(
        server,
        auth,
        &req,
        &scoped_read,
        signal_disclosure.as_ref(),
        &mut response,
    )?;
    // OF-365: what went out under a contact's standing clearance gets the
    // owner's quiet post-hoc receipt (DEC-0006), one per contact.
    let mut delivered = response
        .served_rows()
        .map_err(|error| core_engine_error("delivery ids failed", error))?;
    for row in memories.iter().flat_map(|section| &section.rows) {
        delivered.push(
            oneiron::EntityId::from_hex(&row.id)
                .map_err(|error| core_engine_error("memory delivery id failed", error))?,
        );
    }
    let channels: std::collections::BTreeSet<String> = room_id
        .map(|room| oneiron::consent::contact_disclosure_room_channel(&room))
        .into_iter()
        .chain(
            req.interlocutors
                .as_ref()
                .and_then(|controls| controls.voice_session_ref.as_deref())
                .map(oneiron::consent::contact_disclosure_voice_channel),
        )
        .collect();
    let vault = Arc::clone(&server.vault);
    let parties = interlocutors.clone();
    let once_terms = once.clone();
    tokio::task::spawn_blocking(move || {
        vault.record_standing_disclosure_uses(&delivered, parties.as_ref(), &once_terms, &channels)
    })
    .await
    .map_err(|_| ApiError::internal_server_error("disclosure receipt task failed"))?
    .map_err(|error| core_engine_error("disclosure receipt failed", error))?;
    response.interlocutors = interlocutors.as_ref().map(oneiron::InterlocutorSet::stamps);
    response.limit_clamped = req.limit_clamped;
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

/// Every empty pack reads alike, whoever reads it: no key reads every row
/// (another principal's claims stay private even to the owner's key), so a
/// reason would tell a match its reader cannot read from no match (F19).
pub(crate) fn scrub_context_pack_visible_stats(pack: &mut oneiron::ContextPack) {
    // How many claims the scope withheld is a count of rows the caller may
    // not read: it never leaves as a stat (F19).
    pack.stats.claims_suppressed = 0;
    pack.stats.candidates_considered = pack.results.len();
    pack.stats.entities_hydrated = pack.results.len();
    pack.stats.neighbors_hydrated = pack.neighbors.len();

    if pack.results.is_empty() && pack.neighbors.is_empty() && pack.l2_base.is_none() {
        // A reader profile's skip is decided before any row is read, so
        // naming it tells nothing about rows.
        if pack
            .empty
            .as_ref()
            .is_some_and(|empty| empty.reason == oneiron::EmptyReason::SkippedByProfile)
        {
            return;
        }
        pack.empty = Some(oneiron::EmptyContext {
            retrieval_quality: pack.retrieval_quality.clone(),
            reason: oneiron::EmptyReason::FilterMatchedNone,
            total_in_scope: 0,
            hint: "Try removing filters or widening the world, type, or time scope".to_owned(),
        });
    } else {
        pack.empty = None;
    }
}

/// The agent signal feed rides the context pack of the agent's next turn:
/// reactions to the reader's own messages since `signals_since`, paged, each
/// admitted by the same scoped read as the pack.
fn read_reaction_signals(
    server: &SyncServer,
    auth: &CoreAuth,
    req: &CoreContextPackRequest,
    scoped_read: &oneiron::claim::ScopedRead<'_>,
    disclosure: Option<&oneiron::disclosure::DisclosureContext>,
    response: &mut CoreContextPackResponse,
) -> Result<(), ApiError> {
    let Some(since) = req.signals_since else {
        if req.signals_after.is_some()
            || req.signals_limit.is_some()
            || req.signals_person.is_some()
        {
            return Err(ApiError::bad_request(
                "signals_since is required for reaction signals",
                Some("signals_since"),
            ));
        }
        return Ok(());
    };
    let person = req
        .signals_person
        .as_deref()
        .or_else(|| auth.principal_ref())
        .ok_or_else(|| {
            ApiError::bad_request("signals_person is required", Some("signals_person"))
        })?;
    if !auth.is_owner_grade() && auth.principal_ref() != Some(person) {
        return Err(ApiError::forbidden_scope("signals_person"));
    }
    let person = super::super::parse_entity_id_param(person, "signals_person")?;
    let room = req
        .conversation_id
        .as_deref()
        .map(|id| super::super::parse_entity_id_param(id, "conversation_id"))
        .transpose()?;
    let signals = server
        .vault
        .reactions_since(person, since)
        .map_err(|e| core_engine_error("reaction signal read failed", e))?;
    // A credential reads each signal under its own key, as the pack does, so
    // a full-scope slip that is not the owner's hears of nothing its key
    // withholds. Only an owner-grade caller with no slip keeps the raw feed
    // of one person's messages; a delegated, room-scoped or
    // interlocutor-scoped read is filtered by the same scoped read and
    // disclosure clamp as the pack. Paging follows the filter, so a cursor
    // never names a signal this caller was not shown.
    let scoped = auth.verified_slip().is_some()
        || !auth.is_owner_grade()
        || req.conversation_id.is_some()
        || req.interlocutors.is_some();
    let mut kept = Vec::new();
    for signal in signals {
        if scoped
            && !scoped_read
                .is_reaction_signal_readable_under(&signal, disclosure)
                .map_err(|e| core_engine_error("reaction signal scope failed", e))?
        {
            continue;
        }
        if let Some(room) = room {
            let mut owners = server
                .vault
                .targets(&signal.message, oneiron::EdgeKind::BelongsTo, None)
                .map_err(|e| core_engine_error("reaction signal room failed", e))?;
            owners.extend(
                server
                    .vault
                    .targets(&signal.message, oneiron::EdgeKind::ChildOf, None)
                    .map_err(|e| core_engine_error("reaction signal room failed", e))?,
            );
            if !owners.contains(&room) {
                continue;
            }
        }
        kept.push(signal);
    }
    let page = oneiron::reaction::page_reaction_signals(
        kept,
        req.signals_after.as_deref(),
        req.signals_limit
            .unwrap_or(oneiron::reaction::MAX_REACTION_SIGNAL_PAGE),
    )
    .map_err(|e| core_engine_error("reaction signal page failed", e))?;
    response.signals_next = page.next;
    response.signals = page
        .signals
        .into_iter()
        .map(|signal| CoreReactionSignal {
            event: signal.event(),
            reaction: signal.reaction.to_hex(),
            message: signal.message.to_hex(),
            by: signal.by.to_hex(),
            glyph: signal.glyph,
            occurred_at: signal.occurred_at,
            recorded_at: signal.recorded_at,
        })
        .collect();
    Ok(())
}
