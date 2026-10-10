//! `/v1/owner`: the vault owner's own actions over HTTP.
//!
//! One door admits every route: a verified, unattenuated owner-grade slip
//! whose holder is a live human owner of this vault — the server's existing
//! owner check plus `Vault::authenticate_owner`. The proof it hands each
//! action stays bound to that slip (`Vault::bind_owner_credential`), so the
//! engine rechecks the slip and the ownership in the transaction that
//! commits: a request queued behind a revocation changes nothing. Nothing
//! here prompts a second time; the engine writes each act's receipt. Managed
//! vaults are owned through their supervisor, so these routes refuse there.
//!
//! Approvals stay off the idempotency layer: a consumed approval must never
//! replay a cached 200.

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::Json;
use axum::routing::{get, post};
use oneiron::consent::AuthenticatedOwner;
use oneiron::run_tree::GateConsentBundleAction;
use oneiron::store::GateDecisionId;
use serde::Deserialize;

use super::error_map::core_engine_error;
use super::{has_json_content_type, json_payload, query_params};
use crate::auth::CoreAuth;
use crate::error::{ApiError, ApiErrorDetails, EnvelopedApiError};
use crate::owner::schedule::OwnerHost;
use crate::owner::{
    OwnerError, backup, cleanup, feedback, graph_fs, healer, imports, location, off_record,
    pack_drift, persona, runs, secrets,
};
use crate::server::SyncServer;

type OwnerReply<T> = Result<Json<T>, EnvelopedApiError>;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/status", get(status))
        .route("/backups", get(list_backups).post(take_backup))
        .route("/backups/rehearse", post(rehearse_backup))
        .route("/secret-scan", get(secret_scan).post(set_secret_scan))
        .route("/secrets/rotate", post(rotate_secret))
        .route("/healer/oversight", get(healer_oversight))
        .route("/healer/failures", get(healer_failures))
        .route("/healer/failures/drill", get(drill_failure))
        .route("/imports/preview", post(preview_import))
        .route("/imports/approve", post(approve_import))
        .route("/imports/decline", post(decline_import))
        .route("/runs", get(pending_runs))
        .route("/runs/review", get(review_run))
        .route("/runs/approve", post(approve_run))
        .route("/runs/decline", post(decline_run))
        .route("/cleanup", get(cleanup_review).post(configure_cleanup))
        .route("/cleanup/accept", post(accept_cleanup))
        .route("/cleanup/reject", post(reject_cleanup))
        .route("/cleanup/restore", post(restore_archived))
        .route("/persona", get(preview_persona))
        .route("/persona/export", post(export_persona))
        .route(
            "/off-record",
            get(off_record_session).post(enter_off_record),
        )
        .route("/off-record/mode", post(flip_off_record))
        .route("/off-record/witness", post(witness_off_record))
        .route("/off-record/promote", post(promote_off_record))
        .route("/off-record/save", post(save_off_record))
        .route("/off-record/close", post(close_off_record))
        .route("/graph-fs", get(read_graph_fs))
        .route("/feedback/preview", post(preview_feedback))
        .route("/feedback/send", post(send_feedback))
        .route("/pack-drift", get(pack_drift_repairs))
}

/// The owner door. Every refusal is the same 403, so a caller learns nothing
/// about which check failed. The proof it returns carries the verified slip.
pub(super) fn owner(auth: &CoreAuth, server: &SyncServer) -> Result<AuthenticatedOwner, ApiError> {
    let refused = || ApiError::forbidden_scope("owner");
    if server.managed_issuer.is_some() || !auth.is_owner_grade() {
        return Err(refused());
    }
    let slip = auth
        .verified_slip()
        .filter(|_| auth.actor_class() == Some("human"))
        .ok_or_else(refused)?;
    let principal = auth.principal_ref().ok_or_else(refused)?;
    let actor = oneiron::EntityId::from_hex(principal).map_err(|_| refused())?;
    let owner = server
        .vault()
        .authenticate_owner(actor, principal, true, GateDecisionId::now())
        .map_err(|_| refused())?;
    // Binding checks the slip is the owner's own full slip, still live, and
    // that the actor owns this vault now.
    server
        .vault()
        .bind_owner_credential(owner, slip.clone())
        .map_err(|_| refused())
}

fn host(server: &SyncServer) -> Result<Arc<OwnerHost>, ApiError> {
    server.owner_host.clone().ok_or_else(|| {
        ApiError::new(
            "this server was started without a vault path, so it keeps no backups",
            ApiErrorDetails::InvalidState {
                state: Some("owner_host_unset".to_owned()),
            },
            ["Run `oneiron serve`, or use the `oneiron backup` command on a stopped vault."],
        )
    })
}

fn feedback_host(
    server: &SyncServer,
) -> Result<Arc<crate::feedback_delivery::FeedbackHost>, ApiError> {
    server.feedback.clone().ok_or_else(|| {
        ApiError::new(
            "this server has no feedback destination",
            ApiErrorDetails::InvalidState {
                state: Some("feedback_destination_unset".to_owned()),
            },
            ["Set [feedback] destination and endpoint in the config, then restart `oneiron serve`."],
        )
    })
}

fn owner_error(error: OwnerError) -> ApiError {
    match error {
        OwnerError::Invalid(message) => ApiError::bad_request(message, None),
        OwnerError::Changed(message) => ApiError::new(
            message,
            ApiErrorDetails::InvalidState {
                state: Some("changed_since_review".to_owned()),
            },
            ["Review it again and act on what you reviewed."],
        ),
        OwnerError::Refused(message) => ApiError::new(
            message,
            ApiErrorDetails::InvalidState {
                state: Some("refused".to_owned()),
            },
            std::iter::empty::<String>(),
        ),
        OwnerError::NotFound(what, which) => ApiError::not_found(what, Some(&which)),
        OwnerError::Engine(error) => match error.kind() {
            oneiron::ErrorKind::ConsentOwnerNotAuthenticated => ApiError::forbidden_scope("owner"),
            oneiron::ErrorKind::ConsentApproveOnceSpent => {
                ApiError::invalid_state(Some("already_decided"))
            }
            oneiron::ErrorKind::SecretRefNotFound => ApiError::not_found("secret", None),
            oneiron::ErrorKind::SecretCustodyNotActive => {
                ApiError::invalid_state(Some("secret_not_active"))
            }
            oneiron::ErrorKind::ManifestWidensFloor => {
                ApiError::invalid_state(Some("secret_wider_than_floor"))
            }
            _ => core_engine_error("owner action failed", *error),
        },
        OwnerError::Host(error) => {
            tracing::error!(error = %format!("{error:#}"), "owner action failed");
            ApiError::internal_server_error("owner action failed")
        }
    }
}

/// Runs blocking vault work (snapshots, restores) off the runtime.
async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> Result<T, OwnerError> + Send + 'static,
) -> Result<T, ApiError> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|_| ApiError::internal_server_error("owner action task failed"))?
        .map_err(owner_error)
}

async fn status(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
) -> OwnerReply<location::Location> {
    owner(&auth, &server)?;
    let host = host(&server)?;
    let report = blocking(move || {
        location::locate(
            &host.vault_path,
            Some(server.vault()),
            &host.backups,
            host.every.map(|every| every.as_secs() / 3_600),
        )
        .map_err(OwnerError::from)
    })
    .await?;
    Ok(Json(report))
}

async fn list_backups(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
) -> OwnerReply<Vec<backup::BackupRecord>> {
    owner(&auth, &server)?;
    let host = host(&server)?;
    Ok(Json(
        blocking(move || Ok(backup::list(&host.backups)?)).await?,
    ))
}

async fn take_backup(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
) -> OwnerReply<backup::BackupOutcome> {
    let owner = owner(&auth, &server)?;
    let host = host(&server)?;
    Ok(Json(
        blocking(move || host.take(server.vault(), Some(&owner))).await?,
    ))
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RehearseRequest {
    /// A backup file name from `GET /v1/owner/backups`; the newest by default.
    #[serde(default)]
    file: Option<String>,
}

async fn rehearse_backup(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<RehearseRequest>, JsonRejection>,
) -> OwnerReply<backup::Rehearsal> {
    owner(&auth, &server)?;
    let host = host(&server)?;
    let request = json_payload(payload)?;
    let rehearsal =
        blocking(move || host.rehearse(server.vault(), request.file.as_deref())).await?;
    Ok(Json(rehearsal))
}

#[derive(Debug, serde::Serialize)]
struct SecretScanState {
    mode: oneiron::policy_model::SecretScanMode,
    changes: Vec<oneiron::policy_model::SecretScanReceipt>,
}

async fn secret_scan(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
) -> OwnerReply<SecretScanState> {
    owner(&auth, &server)?;
    let state = blocking(move || {
        let vault = server.vault();
        Ok(SecretScanState {
            mode: vault.secret_scan_mode()?,
            changes: vault.secret_scan_change_log()?,
        })
    })
    .await?;
    Ok(Json(state))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SetSecretScan {
    mode: oneiron::policy_model::SecretScanMode,
}

async fn set_secret_scan(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<SetSecretScan>, JsonRejection>,
) -> OwnerReply<oneiron::policy_model::SecretScanReceipt> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let receipt = blocking(move || {
        let vault = server.vault();
        Ok(vault.set_secret_scan_mode(&owner, request.mode, vault.now_recorded_at())?)
    })
    .await?;
    Ok(Json(receipt))
}

/// The body is read by `RotateSecret::read`, not `Json`: the extractor's
/// body copy and parser scratch would outlive the request unwiped.
async fn rotate_secret(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    headers: HeaderMap,
    body: Body,
) -> OwnerReply<secrets::Rotated> {
    let owner = owner(&auth, &server)?;
    if !has_json_content_type(&headers) {
        return Err(ApiError::bad_request("invalid JSON request body", None).into());
    }
    let request = secrets::RotateSecret::read(body)
        .await
        .map_err(owner_error)?;
    let rotated = blocking(move || secrets::rotate(server.vault(), &owner, &request)).await?;
    Ok(Json(rotated))
}

async fn healer_oversight(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
) -> OwnerReply<Vec<healer::OversightRead>> {
    owner(&auth, &server)?;
    Ok(Json(
        blocking(move || healer::oversight(server.vault())).await?,
    ))
}

async fn healer_failures(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
) -> OwnerReply<Vec<healer::FailureGroup>> {
    owner(&auth, &server)?;
    Ok(Json(
        blocking(move || healer::failure_groups(server.vault())).await?,
    ))
}

async fn drill_failure(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<healer::DrillQuery>, QueryRejection>,
) -> OwnerReply<healer::FailureDrill> {
    let owner = owner(&auth, &server)?;
    let query = query_params(query)?;
    let drill = blocking(move || healer::drill(server.vault(), &owner, query)).await?;
    Ok(Json(drill))
}

async fn preview_import(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<imports::ImportBatch>, JsonRejection>,
) -> OwnerReply<imports::ImportPreview> {
    let owner = owner(&auth, &server)?;
    let batch = json_payload(payload)?;
    let preview = blocking(move || imports::preview(server.vault(), &owner, batch)).await?;
    Ok(Json(preview))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DecideImport {
    batch: imports::ImportBatch,
    /// The digest preview returned for exactly this batch.
    digest: String,
}

async fn approve_import(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<DecideImport>, JsonRejection>,
) -> OwnerReply<imports::ImportApproved> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let approved =
        blocking(move || imports::approve(server.vault(), &owner, &request.batch, &request.digest))
            .await?;
    Ok(Json(approved))
}

async fn decline_import(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<DecideImport>, JsonRejection>,
) -> OwnerReply<imports::ImportDeclined> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let declined =
        blocking(move || imports::decline(server.vault(), &owner, &request.batch, &request.digest))
            .await?;
    Ok(Json(declined))
}

async fn pending_runs(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
) -> OwnerReply<Vec<runs::PendingRun>> {
    owner(&auth, &server)?;
    Ok(Json(blocking(move || runs::pending(server.vault())).await?))
}

/// A run, named by its id or by its `run_ref`, never one field read as both.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RunQuery {
    run_id: Option<String>,
    run_ref: Option<String>,
}

async fn review_run(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<RunQuery>, QueryRejection>,
) -> OwnerReply<runs::RunReview> {
    let owner = owner(&auth, &server)?;
    let query = query_params(query)?;
    let review = blocking(move || {
        let run = runs::RunName::from_fields(query.run_id.as_deref(), query.run_ref.as_deref())?;
        runs::review(server.vault(), &owner, run)
    })
    .await?;
    Ok(Json(review))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DecideRun {
    run_id: Option<String>,
    run_ref: Option<String>,
    /// The bundle id review returned for exactly these proposals.
    bundle_id: String,
}

async fn approve_run(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<DecideRun>, JsonRejection>,
) -> OwnerReply<runs::RunResolved> {
    decide_run(auth, server, payload, GateConsentBundleAction::Approve).await
}

async fn decline_run(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<DecideRun>, JsonRejection>,
) -> OwnerReply<runs::RunResolved> {
    decide_run(auth, server, payload, GateConsentBundleAction::Decline).await
}

async fn decide_run(
    auth: CoreAuth,
    server: Arc<SyncServer>,
    payload: Result<Json<DecideRun>, JsonRejection>,
    action: GateConsentBundleAction,
) -> OwnerReply<runs::RunResolved> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let resolved = blocking(move || {
        let run =
            runs::RunName::from_fields(request.run_id.as_deref(), request.run_ref.as_deref())?;
        runs::resolve(server.vault(), &owner, run, &request.bundle_id, action)
    })
    .await?;
    Ok(Json(resolved))
}

async fn cleanup_review(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
) -> OwnerReply<cleanup::CleanupReview> {
    owner(&auth, &server)?;
    Ok(Json(
        blocking(move || cleanup::review(server.vault())).await?,
    ))
}

async fn configure_cleanup(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<cleanup::CleanupSettings>, JsonRejection>,
) -> OwnerReply<cleanup::CleanupReview> {
    let owner = owner(&auth, &server)?;
    let settings = json_payload(payload)?;
    let review = blocking(move || cleanup::configure(server.vault(), &owner, &settings)).await?;
    Ok(Json(review))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DecideCleanup {
    /// A proposal id from `GET /v1/owner/cleanup`.
    proposal: String,
}

async fn accept_cleanup(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<DecideCleanup>, JsonRejection>,
) -> OwnerReply<cleanup::Accepted> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let accepted =
        blocking(move || cleanup::accept(server.vault(), &owner, &request.proposal)).await?;
    Ok(Json(accepted))
}

async fn reject_cleanup(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<DecideCleanup>, JsonRejection>,
) -> OwnerReply<cleanup::CleanupReview> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let review = blocking(move || {
        cleanup::reject(server.vault(), &owner, &request.proposal)?;
        cleanup::review(server.vault())
    })
    .await?;
    Ok(Json(review))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RestoreArchived {
    /// An id from the `archived` list of `GET /v1/owner/cleanup`.
    entity: String,
    /// That entry's `kind`: `record` (the default) or `completed_attempt`.
    #[serde(default)]
    kind: Option<String>,
}

async fn restore_archived(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<RestoreArchived>, JsonRejection>,
) -> OwnerReply<cleanup::CleanupReview> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let review = blocking(move || {
        cleanup::restore(
            server.vault(),
            &owner,
            &request.entity,
            request.kind.as_deref(),
        )?;
        cleanup::review(server.vault())
    })
    .await?;
    Ok(Json(review))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersonaQuery {
    /// The person the card is about.
    subject: String,
}

async fn preview_persona(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<PersonaQuery>, QueryRejection>,
) -> OwnerReply<persona::Preview> {
    owner(&auth, &server)?;
    let query = query_params(query)?;
    let preview = blocking(move || persona::preview(server.vault(), &query.subject)).await?;
    Ok(Json(preview))
}

async fn export_persona(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<persona::ExportRequest>, JsonRejection>,
) -> OwnerReply<persona::Exported> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let exported = blocking(move || persona::export(server.vault(), &owner, &request)).await?;
    Ok(Json(exported))
}

async fn enter_off_record(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<off_record::Enter>, JsonRejection>,
) -> OwnerReply<off_record::Session> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let session = blocking(move || off_record::enter(server.vault(), &owner, &request)).await?;
    Ok(Json(session))
}

async fn off_record_session(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<off_record::SessionName>, QueryRejection>,
) -> OwnerReply<off_record::Session> {
    let owner = owner(&auth, &server)?;
    let query = query_params(query)?;
    let session =
        blocking(move || off_record::record(server.vault(), &owner, &query.session_ref)).await?;
    Ok(Json(session))
}

async fn flip_off_record(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<off_record::Flip>, JsonRejection>,
) -> OwnerReply<off_record::Session> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let session = blocking(move || off_record::flip(server.vault(), &owner, &request)).await?;
    Ok(Json(session))
}

async fn witness_off_record(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<off_record::Witness>, JsonRejection>,
) -> OwnerReply<oneiron::memory::WitnessReceipt> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let receipt = blocking(move || off_record::witness(server.vault(), &owner, &request)).await?;
    Ok(Json(receipt))
}

async fn promote_off_record(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<off_record::Promote>, JsonRejection>,
) -> OwnerReply<off_record::Promoted> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let promoted = blocking(move || off_record::promote(server.vault(), &owner, &request)).await?;
    Ok(Json(promoted))
}

async fn save_off_record(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<off_record::SessionName>, JsonRejection>,
) -> OwnerReply<off_record::Saved> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let saved = blocking(move || off_record::save(server.vault(), &owner, &request)).await?;
    Ok(Json(saved))
}

async fn close_off_record(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<off_record::SessionName>, JsonRejection>,
) -> OwnerReply<off_record::Closed> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let closed =
        blocking(move || off_record::close(server.vault(), &owner, &request.session_ref)).await?;
    Ok(Json(closed))
}

async fn read_graph_fs(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<graph_fs::GraphFsQuery>, QueryRejection>,
) -> OwnerReply<graph_fs::GraphFsReply> {
    owner(&auth, &server)?;
    // The owner's own scoped read: the tree is what the owner's slip reads.
    let reader = auth
        .verified_slip()
        .and_then(oneiron::claim::ScopedReadActorKey::from_verified_slip)
        .ok_or_else(|| ApiError::forbidden_scope("owner"))?;
    let query = query_params(query)?;
    let reply = blocking(move || graph_fs::run(server.vault(), reader, &query)).await?;
    Ok(Json(reply))
}

async fn preview_feedback(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<feedback::FeedbackRequest>, JsonRejection>,
) -> OwnerReply<feedback::Preview> {
    let owner = owner(&auth, &server)?;
    let host = feedback_host(&server)?;
    let request = json_payload(payload)?;
    Ok(Json(
        blocking(move || feedback::preview(server.vault(), &host, &owner, &request)).await?,
    ))
}

async fn send_feedback(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<feedback::SendRequest>, JsonRejection>,
) -> OwnerReply<feedback::Sent> {
    let owner = owner(&auth, &server)?;
    let host = feedback_host(&server)?;
    let request = json_payload(payload)?;
    let sent = blocking(move || feedback::send(server.vault(), &host, &owner, &request)).await?;
    Ok(Json(sent))
}

async fn pack_drift_repairs(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
) -> OwnerReply<Vec<pack_drift::Repair>> {
    owner(&auth, &server)?;
    Ok(Json(
        blocking(move || pack_drift::repairs(server.vault())).await?,
    ))
}
