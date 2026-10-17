//! Hydrate and short-id hydrate DTOs, routes, and mappers.

use super::super::core_engine_error;
use super::super::json_payload;
use super::super::scoped_read_for_core_auth;
use super::write_shape::CORE_MAX_BATCH_ENTITIES;
use crate::auth::CoreAuth;
use crate::auth::CoreScope;
use crate::error::ApiError;
use crate::error::ApiErrorDetails;
use crate::error::ApiErrorEnvelope;
use crate::error::EnvelopedApiError;
use crate::projection;
use crate::projection::View;
use crate::server::SyncServer;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::response::Json;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use std::sync::Arc;
use utoipa::ToSchema;

/// Short-id hydrate request.
#[derive(Debug, Deserialize, ToSchema)]
#[schema(example = json!({
    "ref": "tn1:a7",
    "view": "full"
}))]
pub(crate) struct CoreHydrateRequest {
    /// Canonical short reference in `shortId:contentHashHex[@revisionHex]` form.
    #[serde(default, rename = "ref", alias = "short_ref", alias = "shortRef")]
    #[schema(example = "tn1:a7")]
    reference: Option<String>,
    /// Short id without the content hash, accepted when `content_hash` is also supplied.
    #[serde(default, rename = "short_id", alias = "shortId")]
    #[schema(example = "tn1")]
    short_id: Option<String>,
    /// Two-hex-digit content hash, accepted when `short_id` is also supplied.
    #[serde(default, rename = "content_hash", alias = "contentHash")]
    #[schema(example = "a7")]
    content_hash: Option<String>,
    /// Projection view for live entities. Defaults to full.
    #[serde(default)]
    #[schema(example = "full")]
    view: Option<View>,
    /// Whether the reader's model takes images in: a live generated image
    /// is then served as its bytes, base64, rather than its text form.
    /// Defaults to false.
    #[serde(default, rename = "image_input", alias = "imageInput")]
    #[schema(example = true)]
    image_input: bool,
    /// The task the reader's model serves. With `image_input`, the host's
    /// per-image pick (`[models.decisions.image_pick]`) reads it beside each
    /// image's description, and an image the task needs no more of is served
    /// as its thumbnail or its text rather than in full.
    #[serde(default)]
    #[schema(example = "Find the receipt's total")]
    task: Option<String>,
    /// Session receiving this body. Defaults to the caller's current board session.
    #[serde(default)]
    session_id: Option<String>,
}

/// Short-id hydrate status.
#[derive(Debug, Clone, Copy, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CoreHydrateStatus {
    /// The short ref resolved to a live entity payload.
    Live,
    /// The short ref resolved to a deleted shell or dangling short-id row.
    Deleted,
}

/// Short-id hydrate response.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CoreHydrateResponse {
    /// Mandatory narrowing receipt.
    #[schema(value_type = super::read_receipt::ReadReceiptSchema)]
    narrowing: oneiron::claim::ScopedReadReceipt,
    /// Hydrate state for the resolved short ref.
    status: CoreHydrateStatus,
    /// Requested short id without content hash.
    #[serde(rename = "short_id")]
    #[schema(example = "tn1")]
    short_id: String,
    /// Requested content hash as two lowercase hex digits.
    #[serde(rename = "content_hash")]
    #[schema(example = "a7")]
    content_hash: String,
    /// Hex entity id when the short ref resolves.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(example = "0123456789abcdef0123456789abcdef")]
    id: Option<String>,
    /// Numeric entity type byte when the entity header is still present.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(example = 1)]
    entity_type: Option<u8>,
    /// Explicit deletion metadata for deleted refs.
    #[serde(skip_serializing_if = "Option::is_none")]
    deletion: Option<CoreHydrateDeletionMetadata>,
    /// Projected live entity. Omitted for deleted refs.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<Object>)]
    item: Option<Value>,
}

/// Deletion metadata returned for a deleted short-id hydrate result.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CoreHydrateDeletionMetadata {
    /// Storage evidence that proved deletion.
    source: CoreHydrateDeletionSource,
    /// Decoded tombstone reason, absent for legacy/malformed/dangling rows.
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<CoreHydrateDeletionReason>,
    /// Unix seconds from tombstone metadata when available.
    #[serde(skip_serializing_if = "Option::is_none", rename = "deleted_at")]
    #[schema(example = 1771027200_u64)]
    deleted_at: Option<u64>,
    /// Deletion request UUID when the v2 tombstone carried one.
    #[serde(skip_serializing_if = "Option::is_none", rename = "request_id")]
    #[schema(example = "00000000-0000-0000-0000-000000000000")]
    request_id: Option<String>,
    /// Whether the tombstone effect class is destructive/hard.
    hard: bool,
}

/// Source of deletion evidence for short-id hydrate.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CoreHydrateDeletionSource {
    Tombstone,
    PendingTombstone,
    DanglingShortId,
}

/// Decoded short-id hydrate deletion reason.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CoreHydrateDeletionReason {
    #[serde(rename = "user_delete")]
    User,
    #[serde(rename = "user_hard_delete")]
    UserHard,
    #[serde(rename = "gdpr_delete")]
    Gdpr,
    #[serde(rename = "policy_delete")]
    Policy,
}

/// Batch short-id hydrate request.
#[derive(Debug, Deserialize, ToSchema)]
#[schema(example = json!({
    "refs": ["tn1:a7", "tn2:ff"],
    "view": "full"
}))]
pub(crate) struct CoreBatchShortIdHydrateRequest {
    /// Canonical short references in `shortId:contentHashHex[@revisionHex]` form.
    #[serde(
        default,
        rename = "refs",
        alias = "short_refs",
        alias = "shortRefs",
        alias = "short_ids",
        alias = "shortIds"
    )]
    #[schema(example = json!(["tn1:a7", "tn2:ff"]))]
    refs: Vec<String>,
    /// Projection view for live entities. Defaults to full.
    #[serde(default)]
    #[schema(example = "full")]
    view: Option<View>,
    /// Whether the reader's model takes images in: a live generated image
    /// is then served as its bytes, base64, rather than its text form.
    /// Defaults to false.
    #[serde(default, rename = "image_input", alias = "imageInput")]
    #[schema(example = true)]
    image_input: bool,
    /// The task the reader's model serves. With `image_input`, the host's
    /// per-image pick (`[models.decisions.image_pick]`) reads it beside each
    /// image's description, and an image the task needs no more of is served
    /// as its thumbnail or its text rather than in full.
    #[serde(default)]
    #[schema(example = "Find the receipt's total")]
    task: Option<String>,
    /// Session receiving this body. Defaults to the caller's current board session.
    #[serde(default)]
    session_id: Option<String>,
}

/// Batch short-id hydrate response.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CoreBatchShortIdHydrateResponse {
    /// Mandatory narrowing receipt.
    #[schema(value_type = super::read_receipt::ReadReceiptSchema)]
    narrowing: oneiron::claim::ScopedReadReceipt,
    /// Per-input hydrate result or typed error.
    results: Vec<CoreBatchShortIdHydrateItem>,
}

/// One batch short-id hydrate item.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CoreBatchShortIdHydrateItem {
    /// Input short ref.
    #[serde(rename = "ref")]
    #[schema(example = "tn1:a7")]
    reference: String,
    /// Stable per-input hydrate outcome discriminator.
    outcome: CoreShortIdHydrateOutcome,
    /// Live or deleted hydrate payload when the input resolves.
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<CoreHydrateResponse>,
    /// Typed per-input error for malformed or not-found refs.
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<CoreShortIdHydrateError>,
}

/// Stable per-input short-id hydrate outcome.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CoreShortIdHydrateOutcome {
    Live,
    Deleted,
    MalformedShortId,
    NotFound,
}

/// Per-input short-id hydrate error.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct CoreShortIdHydrateError {
    /// Stable machine-readable per-item error kind.
    kind: CoreShortIdHydrateErrorKind,
    /// Human-readable error summary.
    message: String,
    /// Request field that failed validation, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    field: Option<String>,
}

/// Stable per-input short-id hydrate error kind.
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CoreShortIdHydrateErrorKind {
    MalformedShortId,
    NotFound,
}

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
    // The session observes the body under the server's guard, taken once
    // the projection, and any pick it asked, is done; release it before the
    // read waits on the write that records the form it served.
    let mut observations =
        super::super::session_read_set(&server, scope, req.session_id.as_deref()).await?;
    if let (Some(observations), Some(observe), Some(response)) =
        (observations.as_deref_mut(), observe, read.value.as_mut())
        && let Some(successor) = observe.record(observations, &scoped_read)?
    {
        response.narrowing.restrict_with(&successor);
        read.receipt.restrict_with(&successor);
    }
    drop(observations);
    scoped_read
        .commit_served_forms(&served)
        .map_err(|error| core_engine_error("core short hydrate failed", error))?;
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
    if req.refs.len() > CORE_MAX_BATCH_ENTITIES {
        return Err(ApiError::bad_request(
            format!("refs must contain at most {CORE_MAX_BATCH_ENTITIES} entries"),
            Some("refs"),
        )
        .into());
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
    let hydrated = scoped_read
        .read(&valid_refs, None)
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
        super::super::session_read_set(&server, scope, req.session_id.as_deref()).await?;
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

    if let (Some(target), Some(staged)) = (observations.as_deref_mut(), staged_observations) {
        *target = staged;
    }
    // Every form the batch served is recorded in one write, once the
    // server's observation guard is released.
    drop(observations);
    scoped_read
        .commit_served_forms(&served)
        .map_err(|error| core_engine_error("batch hydrate failed", error))?;
    Ok(Json(CoreBatchShortIdHydrateResponse {
        narrowing: batch_narrowing,
        results,
    }))
}

/// What every item of a batch hydrate shares: its view and reader, the
/// host's per-image pick, the bulk read's receipt each item starts from, the
/// response receipt, and the forms and bodies the batch records once its
/// items are projected.
struct BatchItems<'a, 'p> {
    view: View,
    reader: &'a oneiron::memory::AssetConsumer,
    pick: Option<&'a oneiron::memory::ImagePick<'p>>,
    narrowing: &'a oneiron::claim::ScopedReadReceipt,
    response: &'a mut oneiron::claim::ScopedReadReceipt,
    served: &'a mut Vec<oneiron::receipt::ServedForm>,
    /// Each observed body, by its item's index.
    observed: &'a mut Vec<(usize, Observed)>,
}

/// A batch's items projected in order under one body budget; a single
/// hydrate reads its one body whole.
fn project_short_id_batch(
    server: &SyncServer,
    scoped_read: &oneiron::claim::ScopedRead<'_>,
    refs: Vec<String>,
    parsed: Vec<Result<(String, u8, oneiron::memory::ReadMode), ApiError>>,
    rows: Vec<Option<oneiron::claim::ReadRow>>,
    items: BatchItems<'_, '_>,
) -> Result<Vec<CoreBatchShortIdHydrateItem>, ApiError> {
    let BatchItems {
        view,
        reader,
        pick,
        narrowing,
        response,
        served,
        observed,
    } = items;
    let mut bodies =
        projection::BodyBudget::new(&server.vault, server.config.limits.projection_body_bytes);
    let mut values = rows.into_iter();
    let mut results = Vec::with_capacity(refs.len());
    for (reference, parsed) in refs.into_iter().zip(parsed) {
        let item = match parsed {
            Ok((short_id, content_hash, mode)) => {
                match project_hydrated_short_id(
                    scoped_read,
                    short_id,
                    content_hash,
                    view,
                    reader,
                    mode,
                    values.next().flatten(),
                    pick,
                    ItemReceipts {
                        start: narrowing.clone(),
                        response: &mut *response,
                        served: &mut *served,
                    },
                    Some(&mut bodies),
                )? {
                    Some((result, observe)) => {
                        if let Some(observe) = observe {
                            observed.push((results.len(), observe));
                        }
                        CoreBatchShortIdHydrateItem {
                            reference,
                            outcome: match result.status {
                                CoreHydrateStatus::Live => CoreShortIdHydrateOutcome::Live,
                                CoreHydrateStatus::Deleted => CoreShortIdHydrateOutcome::Deleted,
                            },
                            result: Some(result),
                            error: None,
                        }
                    }
                    None => CoreBatchShortIdHydrateItem {
                        reference,
                        outcome: CoreShortIdHydrateOutcome::NotFound,
                        result: None,
                        error: Some(CoreShortIdHydrateError {
                            kind: CoreShortIdHydrateErrorKind::NotFound,
                            message: "short_id was not found".to_owned(),
                            field: Some("ref".to_owned()),
                        }),
                    },
                }
            }
            Err(error) => CoreBatchShortIdHydrateItem {
                reference,
                outcome: CoreShortIdHydrateOutcome::MalformedShortId,
                result: None,
                error: Some(CoreShortIdHydrateError {
                    kind: CoreShortIdHydrateErrorKind::MalformedShortId,
                    message: error.message().to_owned(),
                    field: match error.details() {
                        ApiErrorDetails::BadRequest { field } => field.clone(),
                        _ => None,
                    },
                }),
            },
        };
        results.push(item);
    }
    Ok(results)
}

/// Whether a hydrate's reader reads images: its request says so and its
/// `view` carries the body they would be served in.
fn takes_images(image_input: bool, view: View) -> bool {
    image_input && !matches!(view, View::Summary)
}

/// The reader a hydrate serves.
fn hydrate_reader(image_input: bool, view: View) -> oneiron::memory::AssetConsumer {
    oneiron::memory::AssetConsumer::hydrate_reader(takes_images(image_input, view))
}

/// The host's per-image pick (OF-329) for a hydrate whose reader takes
/// images in and whose request names its task, read for the caller by
/// `ai.verdict`'s rule: the slip's principal, or the vault's own owner for an
/// owner-grade credential that names none. None when the host words no pick
/// or no principal is known; every image then goes in full, as before.
fn hydrate_pick<'a>(
    server: &'a SyncServer,
    auth: &CoreAuth,
    task: Option<String>,
    takes_images: bool,
) -> Option<oneiron::memory::ImagePick<'a>> {
    let task = task.filter(|task| takes_images && !task.trim().is_empty())?;
    let principal = match auth.principal_ref() {
        Some(reference) => oneiron::EntityId::from_hex(reference).ok()?,
        None if auth.is_owner_grade() => server.vault.ensure_embedded_owner_actor().ok()?,
        None => return None,
    };
    server.decision_host().image_pick(principal, task)
}

/// A body one hydrated item served, observed into its session once every
/// item, and any image pick it asked, is projected: the server's observation
/// guard is never held across a model call.
pub(crate) struct Observed {
    id: oneiron::EntityId,
    entity_type: u8,
    body: Vec<u8>,
    loaded: bool,
}

impl Observed {
    /// Records the body into `observations`; the receipt of any successor
    /// the observation read, for the caller to fold into what it serves.
    fn record(
        self,
        observations: &mut oneiron::context_board::SessionReadSet,
        scoped_read: &oneiron::claim::ScopedRead<'_>,
    ) -> Result<Option<oneiron::claim::ScopedReadReceipt>, ApiError> {
        observations
            .observe_snapshot(
                scoped_read,
                self.id,
                self.entity_type,
                &self.body,
                self.loaded,
            )
            .map_err(|error| core_engine_error("session body observation failed", error))
    }
}

/// One short ref hydrated for `reader`, an image picked by `pick`. A form it
/// serves in place of an image's body joins `served`, for the caller to
/// record before it answers; the body it decoded comes back for the caller to
/// observe into its session.
#[expect(
    clippy::too_many_arguments,
    reason = "one short ref: its view, reader, mode, image pick and served forms"
)]
pub(crate) fn hydrate_short_id_response_with_mode(
    scoped_read: &oneiron::claim::ScopedRead<'_>,
    short_id: String,
    content_hash: u8,
    view: View,
    reader: &oneiron::memory::AssetConsumer,
    mode: oneiron::memory::ReadMode,
    pick: Option<&oneiron::memory::ImagePick<'_>>,
    served: &mut Vec<oneiron::receipt::ServedForm>,
) -> Result<
    (
        oneiron::claim::ScopedReadResult<Option<CoreHydrateResponse>>,
        Option<Observed>,
    ),
    ApiError,
> {
    // A live read keeps deletion metadata. A pinned read preserves the pin.
    let read = scoped_read
        .read(
            &[oneiron::claim::PointRead::short(&short_id, content_hash).at(mode)],
            None,
        )
        .map_err(|error| core_engine_error("core short hydrate failed", error))?
        .single();
    let mut receipt = read.receipt;
    let (value, observe) = project_hydrated_short_id(
        scoped_read,
        short_id,
        content_hash,
        view,
        reader,
        mode,
        read.value,
        pick,
        ItemReceipts {
            start: receipt.clone(),
            response: &mut receipt,
            served,
        },
        None,
    )?
    .map_or((None, None), |(value, observe)| (Some(value), observe));
    Ok((oneiron::claim::ScopedReadResult { value, receipt }, observe))
}

/// The receipt one hydrated item starts from, the response receipt that
/// also takes the item's image read, and the forms the response serves in
/// place of an image's body, which its door records before it answers.
pub(crate) struct ItemReceipts<'a> {
    pub(crate) start: oneiron::claim::ScopedReadReceipt,
    pub(crate) response: &'a mut oneiron::claim::ScopedReadReceipt,
    pub(crate) served: &'a mut Vec<oneiron::receipt::ServedForm>,
}

#[expect(
    clippy::too_many_arguments,
    reason = "one hydrated item: its ref, reader, mode, row, image pick and receipts, and the batch's body budget"
)]
pub(crate) fn project_hydrated_short_id(
    scoped_read: &oneiron::claim::ScopedRead<'_>,
    short_id: String,
    content_hash: u8,
    view: View,
    reader: &oneiron::memory::AssetConsumer,
    mode: oneiron::memory::ReadMode,
    hydrated: Option<oneiron::claim::ReadRow>,
    pick: Option<&oneiron::memory::ImagePick<'_>>,
    receipts: ItemReceipts<'_>,
    bodies: Option<&mut projection::BodyBudget<'_>>,
) -> Result<Option<(CoreHydrateResponse, Option<Observed>)>, ApiError> {
    let ItemReceipts {
        start: mut narrowing,
        response,
        served: served_forms,
    } = receipts;
    let content_hash_hex = format!("{content_hash:02x}");
    let Some(oneiron::claim::ReadRow {
        id,
        entity_type,
        learned_at,
        deletion,
        body,
        ..
    }) = hydrated
    else {
        return Ok(None);
    };
    let Some(body) = body else {
        return Ok(Some((
            CoreHydrateResponse {
                narrowing,
                status: CoreHydrateStatus::Deleted,
                short_id,
                content_hash: content_hash_hex,
                id: Some(id.to_hex()),
                entity_type: (entity_type != 0).then_some(entity_type),
                deletion: deletion.map(core_hydrate_deletion_metadata),
                item: None,
            },
            None,
        )));
    };
    // One of a batch decodes its body, to project it or to observe it, only
    // while the batch's budget holds it.
    let (decoded, mut bodies) = match bodies {
        Some(bodies) => (bodies.admits(body.len()), Some(bodies)),
        None => (true, None),
    };
    // A live generated image is served down its ladder for `reader` (OF-329):
    // its bytes, its thumbnail beside its ASSET_TEXT, or the text, read
    // through this lane, each body charged to the same budget; with nothing
    // left that fits, the body is omitted and the vault asks. The host's
    // pick, when the request names its task, steps an image the task needs
    // no more of down from full.
    let served = if decoded
        && matches!(mode, oneiron::memory::ReadMode::Live)
        && entity_type == oneiron::registry::ENTITY_TYPE_ASSET
    {
        let mut admits = |len: usize| bodies.as_mut().is_none_or(|bodies| bodies.admits(len));
        let asset = oneiron::memory::hydrated_asset(scoped_read, id, reader, pick, &mut admits)
            .map_err(|_| ApiError::internal_server_error("core asset hydrate failed"))?;
        narrowing.restrict_with(&asset.receipt);
        response.restrict_with(&asset.receipt);
        asset.value
    } else {
        oneiron::memory::HydratedAsset::Stored
    };
    let decoded = decoded && !matches!(served, oneiron::memory::HydratedAsset::Omitted { .. });
    let item = match bodies {
        Some(bodies) if !decoded => bodies.omitted(&id, entity_type, learned_at, &body, view, mode),
        _ => projection::project_entity_parts(
            &id,
            entity_type,
            learned_at,
            match &served {
                oneiron::memory::HydratedAsset::Served { body: form, .. } => form,
                _ => &body,
            },
            view,
        ),
    };
    // A Summary item carries the image's label alone, so it serves no form.
    if !matches!(view, View::Summary)
        && let Some(form) = served.served_form()
    {
        served_forms.push(form);
    }
    // The caller observes a decoded body into its session.
    let observe = decoded.then(|| Observed {
        id,
        entity_type,
        body,
        loaded: matches!(view, View::Full),
    });
    Ok(Some((
        CoreHydrateResponse {
            narrowing,
            status: CoreHydrateStatus::Live,
            short_id,
            content_hash: content_hash_hex,
            id: Some(id.to_hex()),
            entity_type: Some(entity_type),
            deletion: None,
            item: Some(item),
        },
        observe,
    )))
}

pub(crate) fn core_hydrate_deletion_metadata(
    deletion: oneiron::HydratedShortIdDeletion,
) -> CoreHydrateDeletionMetadata {
    CoreHydrateDeletionMetadata {
        source: match deletion.source {
            oneiron::HydratedShortIdDeletionSource::Tombstone => {
                CoreHydrateDeletionSource::Tombstone
            }
            oneiron::HydratedShortIdDeletionSource::PendingTombstone => {
                CoreHydrateDeletionSource::PendingTombstone
            }
            oneiron::HydratedShortIdDeletionSource::DanglingShortId => {
                CoreHydrateDeletionSource::DanglingShortId
            }
        },
        reason: deletion.reason.map(|reason| match reason {
            oneiron::HydratedShortIdDeletionReason::UserDelete => CoreHydrateDeletionReason::User,
            oneiron::HydratedShortIdDeletionReason::UserHardDelete => {
                CoreHydrateDeletionReason::UserHard
            }
            oneiron::HydratedShortIdDeletionReason::GdprDelete => CoreHydrateDeletionReason::Gdpr,
            oneiron::HydratedShortIdDeletionReason::PolicyDelete => {
                CoreHydrateDeletionReason::Policy
            }
        }),
        deleted_at: deletion.deleted_at,
        request_id: deletion.request_id,
        hard: deletion.hard,
    }
}

pub(crate) fn parse_short_ref_request(
    req: &CoreHydrateRequest,
) -> Result<(String, u8, oneiron::memory::ReadMode), ApiError> {
    if let Some(reference) = req.reference.as_deref() {
        return parse_revision_short_ref(reference);
    }
    let Some(short_id) = req.short_id.as_deref() else {
        return Err(ApiError::bad_request(
            "ref or short_id/content_hash is required",
            Some("ref"),
        ));
    };
    let Some(content_hash) = req.content_hash.as_deref() else {
        return Err(ApiError::bad_request(
            "ref or short_id/content_hash is required",
            Some("content_hash"),
        ));
    };
    let (short, hash) = parse_short_ref_parts(short_id, content_hash)?;
    Ok((short, hash, oneiron::memory::ReadMode::Live))
}

pub(crate) fn parse_revision_short_ref(
    reference: &str,
) -> Result<(String, u8, oneiron::memory::ReadMode), ApiError> {
    let (reference, mode) = if let Some((reference, revision)) = reference.rsplit_once('@') {
        let revision = oneiron::memory::RevisionRef::from_hex(revision)
            .map_err(|_| ApiError::bad_request("invalid content revision", Some("ref")))?;
        (reference, oneiron::memory::ReadMode::Pinned(revision))
    } else {
        (reference, oneiron::memory::ReadMode::Live)
    };
    let (short, hash) = parse_short_ref(reference)?;
    Ok((short, hash, mode))
}

pub(crate) fn parse_short_ref(reference: &str) -> Result<(String, u8), ApiError> {
    let Some((short_id, content_hash)) = reference.split_once(':') else {
        return Err(ApiError::bad_request(
            "ref must be in shortId:contentHashHex form",
            Some("ref"),
        ));
    };
    parse_short_ref_parts(short_id, content_hash)
}

/// Validates the two halves of a short ref against the engine's presentation-id
/// grammar (`oneiron::parse_presentation_id`).
///
/// The grammar is SYNTAX ONLY and deliberately does not know the registry: a
/// prefix nothing declares still parses here and fails later at resolution,
/// which is what lets a retired prefix resolve through its alias row. The old
/// hand-rolled "exactly two lowercase letters" slice is gone with it — prefix
/// LENGTH is a registry fact, not a grammar fact.
pub(crate) fn parse_short_ref_parts(
    short_id: &str,
    content_hash: &str,
) -> Result<(String, u8), ApiError> {
    if oneiron::parse_presentation_id(short_id).is_err() {
        return Err(ApiError::bad_request(
            "short_id must be at least two lowercase letters followed by decimal digits",
            Some("short_id"),
        ));
    }
    if content_hash.len() != 2 || !content_hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ApiError::bad_request(
            "content_hash must be exactly two hex digits",
            Some("content_hash"),
        ));
    }
    let content_hash = u8::from_str_radix(content_hash, 16)
        .map_err(|_| ApiError::bad_request("content_hash must be hex", Some("content_hash")))?;
    Ok((short_id.to_owned(), content_hash))
}
