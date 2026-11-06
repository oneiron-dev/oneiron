//! The short-id hydrate routes: `POST /v1/core/hydrate` and
//! `POST /v1/core/batch/shortId/hydrate`, each through its verb-hook
//! boundary (FIX 1435). `core_hydrate` and `core_batch_short_id_hydrate`
//! are its call surface; the parent module keeps their DTOs and the shared
//! projection helpers, which run no hook.

use super::{
    BatchItems, CoreBatchShortIdHydrateRequest, CoreBatchShortIdHydrateResponse,
    CoreHydrateRequest, CoreHydrateResponse, frames, hydrate_pick, hydrate_reader,
    hydrate_short_id_response_with_mode, parse_revision_short_ref, parse_short_ref_request,
    project_short_id_batch, takes_images,
};
use crate::api::native_read_hooks::{
    NativeReadAnswer, NativeReadBody, NativeReadError, decoded, encoded, native_read_hooked,
};
use crate::api::{FacadeCall, core_engine_error, json_payload, scoped_read_for_core_auth};
use crate::auth::CoreAuth;
use crate::auth::CoreScope;
use crate::error::ApiError;
use crate::error::ApiErrorEnvelope;
use crate::projection::View;
use crate::server::SyncServer;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::http::{Extensions, HeaderMap};
use axum::response::Json;
use oneiron::code_run::vault_read::VaultReadMethod;
use serde_json::Value;
use std::sync::Arc;

/// The members of a hydrate request that its route reads and the native
/// hydrate contracts do not carry: the session receiving its bodies.
const HYDRATE_ROUTE_CONTROLS: &[&str] = &["session_id"];

/// Hydrate an entity by context-pack short reference.
#[utoipa::path(
    post,
    path = "/v1/core/hydrate",
    request_body(content = CoreHydrateRequest, content_type = "application/json"),
    responses(
        (status = 200, description = "Short ref resolved to a live or deleted entity.", body = CoreHydrateResponse, content_type = "application/json"),
        (status = 400, description = "Malformed short ref.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 401, description = "Missing or invalid core auth.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 403, description = "Core token lacks core:read.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 404, description = "Short ref was not found.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 409, description = "A legal order keeps the named record from use.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 500, description = "Hydrate lookup failed.", body = ApiErrorEnvelope, content_type = "application/json")
    )
)]
pub(crate) async fn core_hydrate(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    headers: HeaderMap,
    extensions: Extensions,
    payload: Result<Json<Value>, JsonRejection>,
) -> Result<Json<Value>, NativeReadError> {
    auth.require(CoreScope::Read)?;
    let body = json_payload(payload)?;
    let call = FacadeCall::http(&server, &auth, &headers, &extensions);
    Ok(Json(core_hydrate_hooked(&server, &call, body).await?.value))
}

/// `POST /v1/core/hydrate` on `body`, for `call`'s caller, through its
/// verb-hook boundary as `memory.hydrate` (FIX 1435). The short ref is
/// parsed and the caller's read admitted first; the pre chain then runs
/// before any image is picked or row read. The post chain reads the answer
/// after its observation is staged, its served forms are committed and the
/// observation is published.
pub(crate) async fn core_hydrate_hooked(
    server: &Arc<SyncServer>,
    call: &FacadeCall<'_>,
    body: Value,
) -> Result<NativeReadAnswer, NativeReadError> {
    let auth = call.auth();
    let admitted = admit_hydrate(&body)?;
    let scoped_read = scoped_read_for_core_auth(&server.vault, auth)?;
    let body = NativeReadBody::split(body, HYDRATE_ROUTE_CONTROLS);
    native_read_hooked(
        server,
        call,
        VaultReadMethod::Hydrate,
        body,
        admitted,
        admit_hydrate,
        |admitted| read_hydrate(server, auth, scoped_read, admitted),
    )
    .await
}

/// A hydrate request as its route admits it: decoded, beside its short ref
/// and the read mode its revision names.
struct AdmittedHydrate {
    req: CoreHydrateRequest,
    short_id: String,
    content_hash: u8,
    mode: oneiron::memory::ReadMode,
}

/// The route's own admission of the hydrate `body`.
fn admit_hydrate(body: &Value) -> Result<AdmittedHydrate, ApiError> {
    let req: CoreHydrateRequest = decoded(body)?;
    let (short_id, content_hash, mode) = parse_short_ref_request(&req)?;
    Ok(AdmittedHydrate {
        req,
        short_id,
        content_hash,
        mode,
    })
}

/// An admitted hydrate, read on `scoped_read`, `auth`'s own: its row
/// projected and any image picked, then its body observed into the
/// caller's session and its served forms committed. The answer goes beside
/// the rows its projection was derived from (FIX 1435).
async fn read_hydrate(
    server: &SyncServer,
    auth: &CoreAuth,
    scoped_read: oneiron::claim::ScopedRead<'_>,
    admitted: AdmittedHydrate,
) -> Result<NativeReadAnswer, NativeReadError> {
    let AdmittedHydrate {
        req,
        short_id,
        content_hash,
        mode,
    } = admitted;
    let content_hash_hex = format!("{content_hash:02x}");
    let view = req.view.unwrap_or(View::Full);
    let scope = auth.principal_ref().unwrap_or(auth.principal()).trim();
    let pick = hydrate_pick(server, auth, req.task, takes_images(req.image_input, view));
    let reader = hydrate_reader(req.image_input, view);
    let mut served = Vec::new();
    let mut producers = Vec::new();
    let mut project = || {
        hydrate_short_id_response_with_mode(
            &scoped_read,
            short_id.clone(),
            content_hash,
            view,
            &reader,
            mode,
            pick.as_ref(),
            &mut served,
            &mut producers,
        )
    };
    // A pick asks the host's models: off the async runtime.
    let (mut read, observe) = if pick.is_some() {
        crate::server::blocking(project)
    } else {
        project()
    }?;
    // Stage the observation after projection and any model pick. Publish
    // it only after its served forms commit, without replacing a concurrent
    // session update between staging and publication.
    let mut observations =
        super::super::super::session_read_set(server, scope, req.session_id.as_deref()).await?;
    let mut staged_observations = observations.as_deref().cloned();
    if let (Some(staged), Some(observe), Some(response)) =
        (staged_observations.as_mut(), observe, read.value.as_mut())
        && let Some(successor) = observe.record(staged, &scoped_read)?
    {
        response.narrowing.restrict_with(&successor);
        read.receipt.restrict_with(&successor);
    }
    scoped_read
        .commit_served_forms(&served)
        .map_err(|error| core_engine_error("core short hydrate failed", error))?;
    if let (Some(target), Some(staged)) = (observations.as_deref_mut(), staged_observations) {
        *target = staged;
    }
    drop(observations);
    let Some(response) = read.value else {
        return Err(NativeReadError::with_read_receipt(
            ApiError::not_found("short_id", Some(&format!("{short_id}:{content_hash_hex}"))),
            read.receipt,
        ));
    };

    Ok(NativeReadAnswer::listed(encoded(&response)?, producers))
}

/// Batch-hydrate entities by context-pack short references.
#[utoipa::path(
    post,
    path = "/v1/core/batch/shortId/hydrate",
    request_body(content = CoreBatchShortIdHydrateRequest, content_type = "application/json"),
    responses(
        (status = 200, description = "Short refs hydrated with per-item typed results/errors.", body = CoreBatchShortIdHydrateResponse, content_type = "application/json"),
        (status = 400, description = "Malformed batch request.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 401, description = "Missing or invalid core auth.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 403, description = "Core token lacks core:read.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 500, description = "Hydrate lookup failed.", body = ApiErrorEnvelope, content_type = "application/json")
    )
)]
pub(crate) async fn core_batch_short_id_hydrate(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    headers: HeaderMap,
    extensions: Extensions,
    payload: Result<Json<Value>, JsonRejection>,
) -> Result<Json<Value>, NativeReadError> {
    auth.require(CoreScope::Read)?;
    let body = json_payload(payload)?;
    let call = FacadeCall::http(&server, &auth, &headers, &extensions);
    let answer = core_batch_short_id_hydrate_hooked(&server, &call, body).await?;
    Ok(Json(answer.value))
}

/// `POST /v1/core/batch/shortId/hydrate` on `body`, for `call`'s caller,
/// through its verb-hook boundary as `memory.hydrate_many` (FIX 1435). The
/// batch is checked and the caller's read admitted first; the pre chain
/// then runs before any image is picked or row read. The post chain reads
/// the answer after its observations are staged, its served forms are
/// committed and the observations are published.
pub(crate) async fn core_batch_short_id_hydrate_hooked(
    server: &Arc<SyncServer>,
    call: &FacadeCall<'_>,
    body: Value,
) -> Result<NativeReadAnswer, NativeReadError> {
    let auth = call.auth();
    let req = admit_batch_hydrate(&body)?;
    let scoped_read = scoped_read_for_core_auth(&server.vault, auth)?;
    let body = NativeReadBody::split(body, HYDRATE_ROUTE_CONTROLS);
    native_read_hooked(
        server,
        call,
        VaultReadMethod::HydrateMany,
        body,
        req,
        admit_batch_hydrate,
        |req| read_batch_hydrate(server, auth, scoped_read, req),
    )
    .await
}

/// The route's own admission of the batch hydrate `body`: decoded, and
/// naming one ref or more.
fn admit_batch_hydrate(body: &Value) -> Result<CoreBatchShortIdHydrateRequest, ApiError> {
    let req: CoreBatchShortIdHydrateRequest = decoded(body)?;
    if req.refs.is_empty() {
        return Err(ApiError::bad_request(
            "refs must not be empty",
            Some("refs"),
        ));
    }
    Ok(req)
}

/// An admitted batch hydrate, read on `scoped_read`, `auth`'s own: its
/// items read frame by frame and projected in order, then their bodies
/// observed into the caller's session and their served forms committed.
/// The answer goes beside the rows its projected live and deleted items
/// were derived from (FIX 1435). A malformed ref, or a slot that is absent,
/// adds none. A slot a legal order keeps from use leaves the answer
/// unlisted: its row is not known by id.
async fn read_batch_hydrate(
    server: &SyncServer,
    auth: &CoreAuth,
    scoped_read: oneiron::claim::ScopedRead<'_>,
    req: CoreBatchShortIdHydrateRequest,
) -> Result<NativeReadAnswer, NativeReadError> {
    let view = req.view.unwrap_or(View::Full);
    let reader = hydrate_reader(req.image_input, view);
    let scope = auth.principal_ref().unwrap_or(auth.principal()).trim();
    let pick = hydrate_pick(server, auth, req.task, takes_images(req.image_input, view));
    let parsed: Vec<_> = req
        .refs
        .iter()
        .map(|reference| parse_revision_short_ref(reference))
        .collect();
    let valid_refs: Vec<_> = parsed
        .iter()
        .filter_map(|item| item.as_ref().ok())
        .map(|(id, hash, mode)| oneiron::claim::PointRead::short(id, *hash).at(*mode))
        .collect();
    // FIX 11125: a batch past one frame is read frame by frame, never refused.
    let hydrated = frames::read_named_frames(&scoped_read, &valid_refs)
        .map_err(|error| core_engine_error("batch hydrate failed", error))?;
    let narrowing = hydrated.receipt;
    // Each item starts from the bulk read's receipt; a successor an item's
    // observation reads narrows that item and the batch.
    let mut batch_narrowing = narrowing.clone();
    let mut served = Vec::new();
    let mut observed = Vec::new();
    let mut producers = Vec::new();
    let mut unlisted = false;
    let project = || {
        project_short_id_batch(
            server,
            &scoped_read,
            req.refs,
            parsed,
            hydrated.value,
            BatchItems {
                view,
                reader: &reader,
                pick: pick.as_ref(),
                narrowing: &narrowing,
                response: &mut batch_narrowing,
                served: &mut served,
                observed: &mut observed,
                producers: &mut producers,
                unlisted: &mut unlisted,
            },
        )
    };
    // A pick asks the host's models: off the async runtime.
    let mut results = if pick.is_some() {
        crate::server::blocking(project)
    } else {
        project()
    }?;
    // The session observes the batch's bodies under the server's guard,
    // taken once every item, and any pick it asked, is projected.
    let mut observations =
        super::super::super::session_read_set(server, scope, req.session_id.as_deref()).await?;
    let mut staged_observations = observations.as_deref().cloned();
    if let Some(staged) = staged_observations.as_mut() {
        for (index, observe) in observed {
            if let Some(successor) = observe.record(staged, &scoped_read)? {
                if let Some(result) = results[index].result.as_mut() {
                    result.narrowing.restrict_with(&successor);
                }
                batch_narrowing.restrict_with(&successor);
            }
        }
    }

    // A failed observation or receipt write leaves the live read set
    // unchanged. Keep the guard until the staged batch is published.
    scoped_read
        .commit_served_forms(&served)
        .map_err(|error| core_engine_error("batch hydrate failed", error))?;
    if let (Some(target), Some(staged)) = (observations.as_deref_mut(), staged_observations) {
        *target = staged;
    }
    drop(observations);
    let response = encoded(&CoreBatchShortIdHydrateResponse {
        narrowing: batch_narrowing,
        results,
    })?;
    // A use-restricted slot's row is not among the producers, so the
    // answer's rows are not all known (FIX 1435).
    Ok(if unlisted {
        NativeReadAnswer::unlisted(response)
    } else {
        NativeReadAnswer::listed(response, producers)
    })
}
