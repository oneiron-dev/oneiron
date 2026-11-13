//! Route handler and shared pipeline for context-pack assembly.

use super::super::{MemoriesRequest, core_engine_error, json_payload, non_empty_query};
pub(crate) use super::builder_controls::*;
use super::controls::CoreContextPackRequest;
use super::media_query::embed_media_seeds;
use super::response::{
    CoreContextPackResponse, CoreReactionSignal, context_pack_json_projection_config,
    run_context_pack_builder,
};
use super::response_limits::ContextPackResponseLimits;
use super::validate::{
    ContextPackSignalRequest, ValidatedContextPack, validate_context_pack,
    validate_rewritten_context_pack,
};
use super::{narrow_to_reader, resolve_core_disclosure_with_once, spend_core_once_disclosures};
use crate::api::FacadeCall;
use crate::api::native_read_hooks::{
    NativeReadAnswer, NativeReadBody, NativeReadError, decoded, encoded, native_read_hooked,
};
use crate::auth::CoreAuth;
use crate::auth::CoreScope;
use crate::error::ApiError;
use crate::error::ApiErrorEnvelope;
use crate::projection::View;
use crate::server::{QueryDoor, SyncServer};
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::http::{Extensions, HeaderMap};
use axum::response::Json;
use oneiron::code_run::vault_read::VaultReadMethod;
use serde_json::Value;
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
        (status = 408, description = "The explicit signals_deadline_ms expired; no signal page or advanced cursor was published.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 500, description = "Context-pack assembly failed.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 503, description = "No ai.embed rung serves a media query's space (or, on the one-space preset, the text slot's space), or the rung's call failed.", body = ApiErrorEnvelope, content_type = "application/json")
    )
)]
pub(crate) async fn core_context_pack(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    headers: HeaderMap,
    extensions: Extensions,
    payload: Result<Json<Value>, JsonRejection>,
) -> Result<Json<Value>, NativeReadError> {
    auth.require(CoreScope::Read)?;
    // A facet-narrowed credential reads a facet-narrowed pack (FIX 646): every
    // row, count and handle the pack echoes passes the admitted read, the
    // room's signed facets met in (FIX 643).
    let body = json_payload(payload)?;
    let call = FacadeCall::http(&server, &auth, &headers, &extensions);
    let answer = core_context_pack_hooked(&server, &call, body).await?;
    Ok(Json(answer.value))
}

/// The members of a context pack request that its route reads and the
/// native `memory.context_pack` contract does not carry: its room, session,
/// reaction signals, affect, assembly policy, time window, projection,
/// interlocutors and reader.
const CONTEXT_PACK_ROUTE_CONTROLS: &[&str] = &[
    "conversation_id",
    "session_id",
    "signals_since",
    "signals_after",
    "signals_limit",
    "signals_deadline_ms",
    "signals_person",
    "query_affect",
    "queryAffect",
    "hydrate",
    "include_edges",
    "includeEdges",
    "include_vectors",
    "includeVectors",
    "view",
    "policy",
    "time",
    "interlocutors",
    "reader",
];

/// `POST /v1/core/context-pack` on `body`, for `call`'s caller, through its
/// verb-hook boundary as `memory.context_pack` (FIX 1435). Every request
/// check runs first, under the caller's own read, before the pre chain:
/// `admit_context_pack`. A hook's rewrite meets the same checks on the
/// chain's blocking thread, beside the caller's own route controls and
/// under the caller's own credential. The pack runs on the request the
/// chain left, as that request was validated; that pipeline runs no hook
/// itself.
pub(crate) async fn core_context_pack_hooked(
    server: &Arc<SyncServer>,
    call: &FacadeCall<'_>,
    body: Value,
) -> Result<NativeReadAnswer, NativeReadError> {
    let auth = call.auth();
    let pack = admit_context_pack(server, auth, &body).await?;
    let admit = {
        let (server, auth) = (Arc::clone(server), auth.clone());
        move |body: &Value| admit_rewritten_context_pack(&server, &auth, body)
    };
    let body = NativeReadBody::split(body, CONTEXT_PACK_ROUTE_CONTROLS);
    native_read_hooked(
        server,
        call,
        VaultReadMethod::ContextPack,
        body,
        pack,
        admit,
        |pack| read_context_pack(server, auth, pack),
    )
    .await
}

/// The context pack `body` decoded, and its query checked against
/// `[limits].retrieval_query_bytes`.
fn decoded_context_pack(
    server: &SyncServer,
    auth: &CoreAuth,
    body: &Value,
) -> Result<CoreContextPackRequest, ApiError> {
    let req: CoreContextPackRequest = decoded(body)?;
    req.check_query_bytes(server, auth, QueryDoor::ContextPack, "query")?;
    Ok(req)
}

/// The route's own admission of the context pack `body` for `auth`, before
/// any hook runs (FIX 1435): decoded, its query bytes checked, then
/// validated, its reader, room and contacts on the request's context-input
/// worker.
async fn admit_context_pack(
    server: &SyncServer,
    auth: &CoreAuth,
    body: &Value,
) -> Result<ValidatedContextPack, ApiError> {
    let req = decoded_context_pack(server, auth, body)?;
    validate_context_pack(server, auth, req).await
}

/// [`admit_context_pack`] of a hook's rewritten `body`, on the hook chain's
/// blocking thread (FIX 1435).
fn admit_rewritten_context_pack(
    server: &SyncServer,
    auth: &CoreAuth,
    body: &Value,
) -> Result<ValidatedContextPack, ApiError> {
    let req = decoded_context_pack(server, auth, body)?;
    validate_rewritten_context_pack(server, auth, req)
}

/// A validated context pack, assembled for `auth` through the shared
/// pipeline, as the JSON the route answers. The answer goes beside the rows
/// the final response lists it was derived from
/// (`CoreContextPackResponse::producer_rows`, FIX 1435). A response whose
/// rows are not all known lists none.
async fn read_context_pack(
    server: &SyncServer,
    auth: &CoreAuth,
    pack: ValidatedContextPack,
) -> Result<NativeReadAnswer, NativeReadError> {
    let (response, _, _) = execute_context_pack(server, auth, pack, None).await?;
    let rows = response
        .producer_rows()
        .map_err(|error| core_engine_error("producer ids failed", error))?;
    let value = encoded(&response)?;
    Ok(match rows {
        Some(rows) => NativeReadAnswer::listed(value, rows),
        None => NativeReadAnswer::unlisted(value),
    })
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
    let pack = validate_context_pack(server, auth, req).await?;
    execute_context_pack(server, auth, pack, memories).await
}

/// [`run_context_pack`] on `pack`, a request already validated (FIX 1435):
/// scoped retrieval, projection and evidence. The paid embedding, the once
/// answers, the retrieval, the observations, the signal read and the
/// disclosure receipts all run here, in that order.
pub(crate) async fn execute_context_pack(
    server: &SyncServer,
    auth: &CoreAuth,
    pack: ValidatedContextPack,
    memories: Option<MemoriesRequest>,
) -> Result<
    (
        CoreContextPackResponse,
        Option<oneiron::MemoriesSection>,
        Option<oneiron::MemoriesCursor>,
    ),
    ApiError,
> {
    let ValidatedContextPack {
        read,
        mut req,
        optional_memory,
        room_id,
        room,
        interlocutors,
        media,
        skill_reliability,
        candidate_limit,
        query_affect,
        ranking,
        time,
        signals,
    } = pack;
    // ARCH-0052 #e5-read-union-open (ONE-1729): a pack whose request names a
    // live stretch reads it beside base, as a turn taken there sees it. The
    // view borrows the stretch, so it is made here, after the verb hooks.
    let stretch = context_pack_room(server, auth)?;
    let stretch_read = stretch
        .as_ref()
        .map(oneiron::off_record::RoomPackSession::read)
        .transpose()
        .map_err(|error| core_engine_error("context-pack stretch read failed", error))?;
    let scoped_read = match stretch_read.as_ref() {
        Some(stretch_read) => read.into_borrowed_in_room(&server.vault, stretch_read),
        None => read.into_borrowed(&server.vault),
    }
    .map_err(|_| ApiError::internal_server_error("context-pack reader return failed"))?;
    let query = non_empty_query(req.query.as_deref());
    let (edge_hop, _, max_neighbors, _) =
        resolved_context_pack_depth(req.depth.as_ref(), req.edge_hop, req.max_neighbors);
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
    // Embedded once everything free is checked: it is a paid call. On the
    // one-space preset the text query is embedded into the text slot's space.
    // A reader whose optional memory is `none` embeds nothing (FIX 8151);
    // its pins, disclosure, signals and cursor still run below.
    let media = if skip_optional_recall {
        Vec::new()
    } else {
        embed_media_seeds(server, media, query).await?
    };
    let (mut media_memory, media) = (server.memory.empty_lease(), media);
    media_memory.materialized(
        0,
        media.iter().fold(
            (media.capacity() as u64)
                .saturating_mul(std::mem::size_of::<crate::api::MediaSeed>() as u64),
            |bytes, seed| {
                let vector_bytes = (seed.vector.capacity() as u64)
                    .saturating_mul(std::mem::size_of::<f32>() as u64);
                let kind_bytes = (seed.kinds.capacity() as u64)
                    .saturating_mul(std::mem::size_of::<oneiron::embed::InputKind>() as u64);
                bytes
                    .saturating_add(seed.space.capacity() as u64)
                    .saturating_add(vector_bytes)
                    .saturating_add(kind_bytes)
            },
        ),
    );

    // Every channel and neighbor takes the reader's row gate, its bound
    // caller filter included, before its cut (FIX 3977); the pack is still
    // filtered under the reader once it runs.
    let plan = scoped_read.context_pack_plan().map_err(|error| {
        tracing::error!(kind = ?error.kind(), "core context-pack scoped plan failed");
        core_engine_error("core context-pack scoped read setup failed", error)
    })?;
    let admitted = match stretch_read.as_ref() {
        Some(stretch_read) => plan
            .admit_in_room(server.vault.context_pack(), stretch_read)
            .map_err(|error| core_engine_error("context-pack stretch admission failed", error))?,
        None => plan.admit(server.vault.context_pack()),
    };
    let mut builder = admitted
        .media_query_memory(&server.memory)
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
        builder = builder.model_window(model);
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
    if let Some(vad) = query_affect {
        builder = builder.query_affect(vad);
    }
    builder = ranking.applied(builder);
    builder = time.applied(builder);
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
        signals,
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

/// The live stretch a pack reads beside base: the one its request names
/// (`x-oneiron-session`), for the vault's owner on their proof, so the turn
/// board of a chat turn taken there reads the stretch's rows. Any other
/// caller, and a stretch the owner cannot bind now (gone, closing, closed, or
/// a room they are not in), reads base alone, as a pack did before. Whether a
/// room's rows are opaque to every non-owner reader is open (ARCH-0052
/// #e5-read-union-open; ASK L6-12-NON-OWNER).
fn context_pack_room<'v>(
    server: &'v SyncServer,
    auth: &CoreAuth,
) -> Result<Option<oneiron::off_record::RoomPackSession<'v>>, ApiError> {
    let Some(key) = auth.off_record_session() else {
        return Ok(None);
    };
    let Ok(owner) = crate::api::owner_routes::owner(auth, server) else {
        return Ok(None);
    };
    let owner = owner
        .revalidate(&server.vault)
        .map_err(|error| core_engine_error("context-pack owner proof failed", error))?;
    server
        .vault
        .off_record_session_vault()
        .bind_pack_reader(key, owner)
        .map_err(|error| core_engine_error("context-pack stretch bind failed", error))
}

/// The agent signal feed rides the context pack of the agent's next turn:
/// reactions to the reader's own messages since `signals_since`, paged, each
/// admitted by the same scoped read as the pack. `signal_request` was
/// checked with the request (FIX 1435); its deadline starts here.
fn read_reaction_signals(
    server: &SyncServer,
    auth: &CoreAuth,
    req: &CoreContextPackRequest,
    signal_request: Option<ContextPackSignalRequest>,
    scoped_read: &oneiron::claim::ScopedRead<'_>,
    disclosure: Option<&oneiron::disclosure::DisclosureContext>,
    response: &mut CoreContextPackResponse,
) -> Result<(), ApiError> {
    let Some(ContextPackSignalRequest {
        person,
        since,
        room,
        deadline_ms,
        paging,
    }) = signal_request
    else {
        return Ok(());
    };
    let deadline = deadline_ms.map(|ms| {
        oneiron::retrieval_depth::RetrievalDeadline::after(std::time::Duration::from_millis(ms))
    });
    let signal_error = |error: oneiron::Error| match &error {
        oneiron::Error::Io(error)
            if error.get_ref().is_some_and(|source| {
                source.is::<oneiron::reaction::ReactionSignalDeadlineExceeded>()
            }) =>
        {
            ApiError::deadline_exceeded("signals_deadline_ms")
        }
        _ => core_engine_error("reaction signal read failed", error),
    };
    let checkpoint = || {
        deadline.as_ref().map_or(Ok(()), |deadline| {
            oneiron::reaction::check_reaction_signal_deadline(deadline).map_err(signal_error)
        })
    };
    let signals = server
        .vault
        .reactions_since_with_deadline(person, since, deadline.as_ref())
        .map_err(signal_error)?;
    // A credential reads each signal under its own key, as the pack does, so
    // a full-scope slip that is not the owner's hears of nothing its key
    // withholds. Only an owner-grade caller with no slip keeps the raw feed
    // of one person's messages; a delegated, room-scoped or
    // interlocutor-scoped read is filtered by the same scoped read and
    // disclosure clamp as the pack, and so is a read that names its own
    // filter, which the pack's reader carries (FIX 3977). Paging follows the
    // filter, so a cursor never names a signal this caller was not shown.
    let scoped = auth.verified_slip().is_some()
        || !auth.is_owner_grade()
        || req.conversation_id.is_some()
        || req.interlocutors.is_some()
        || req.filter.is_some();
    // The raw feed meets the world judge the scoped read applies (DEC-0005:
    // a caller off this device reads nothing a withheld world keeps). An
    // owner-grade caller with no slip off this device, as a managed vault's
    // owner or a dev-hatch request a proxy marked, hears of no reaction a
    // world withheld from its destination keeps, nor of one on a message
    // such a world keeps. A caller on this device is withheld nothing.
    let raw_destination = (!scoped)
        .then(|| auth.destination())
        .filter(oneiron::settings::ReadDestination::is_off_device);
    let mut kept = Vec::new();
    for signal in signals {
        checkpoint()?;
        if scoped
            && !scoped_read
                .is_reaction_signal_readable_under(&signal, disclosure)
                .map_err(|e| core_engine_error("reaction signal scope failed", e))?
        {
            continue;
        }
        if let Some(destination) = &raw_destination
            && !server
                .vault
                .rows_may_leave_for(&[signal.reaction, signal.message], destination)
                .map_err(|e| core_engine_error("reaction signal world judge failed", e))?
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
    checkpoint()?;
    let page = paging.page(kept);
    checkpoint()?;
    let signals = page
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
    checkpoint()?;
    response.signals_next = page.next;
    response.signals = signals;
    Ok(())
}
