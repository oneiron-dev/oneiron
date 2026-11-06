//! The short-id hydrate routes: `POST /v1/core/hydrate` and
//! `POST /v1/core/batch/shortId/hydrate`. `core_hydrate` and
//! `core_batch_short_id_hydrate` are its call surface; the parent module
//! keeps their DTOs and the shared projection helpers.

use super::{
    BatchItems, CoreBatchShortIdHydrateRequest, CoreBatchShortIdHydrateResponse,
    CoreHydrateRequest, CoreHydrateResponse, frames, hydrate_pick, hydrate_reader,
    hydrate_short_id_response_with_mode, parse_revision_short_ref, parse_short_ref_request,
    project_short_id_batch, takes_images,
};
use crate::api::{core_engine_error, json_payload, scoped_read_for_core_auth};
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
    payload: Result<Json<CoreHydrateRequest>, JsonRejection>,
) -> Result<Json<CoreHydrateResponse>, EnvelopedApiError> {
    auth.require(CoreScope::Read)?;
    let req = json_payload(payload)?;
    let (short_id, content_hash, mode) = parse_short_ref_request(&req)?;
    let content_hash_hex = format!("{content_hash:02x}");
    let view = req.view.unwrap_or(View::Full);
    let scoped_read = scoped_read_for_core_auth(&server.vault, &auth)?;
    let scope = auth.principal_ref().unwrap_or(auth.principal()).trim();
    let pick = hydrate_pick(
        &server,
        &auth,
        req.task,
        takes_images(req.image_input, view),
    );
    let reader = hydrate_reader(req.image_input, view);
    let mut served = Vec::new();
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
        super::super::super::session_read_set(&server, scope, req.session_id.as_deref()).await?;
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
        return Err(EnvelopedApiError::from(ApiError::not_found(
            "short_id",
            Some(&format!("{short_id}:{content_hash_hex}")),
        ))
        .with_read_receipt(read.receipt));
    };

    Ok(Json(response))
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
    payload: Result<Json<CoreBatchShortIdHydrateRequest>, JsonRejection>,
) -> Result<Json<CoreBatchShortIdHydrateResponse>, EnvelopedApiError> {
    auth.require(CoreScope::Read)?;
    let req = json_payload(payload)?;
    if req.refs.is_empty() {
        return Err(ApiError::bad_request("refs must not be empty", Some("refs")).into());
    }

    let view = req.view.unwrap_or(View::Full);
    let reader = hydrate_reader(req.image_input, view);
    let scoped_read = scoped_read_for_core_auth(&server.vault, &auth)?;
    let scope = auth.principal_ref().unwrap_or(auth.principal()).trim();
    let pick = hydrate_pick(
        &server,
        &auth,
        req.task,
        takes_images(req.image_input, view),
    );
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
    let project = || {
        project_short_id_batch(
            &server,
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
        super::super::super::session_read_set(&server, scope, req.session_id.as_deref()).await?;
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
    Ok(Json(CoreBatchShortIdHydrateResponse {
        narrowing: batch_narrowing,
        results,
    }))
}
