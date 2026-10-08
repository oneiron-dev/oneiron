//! `/v1/owner`: the vault owner's own actions over HTTP.
//!
//! One door admits every route: a verified, unattenuated owner-grade slip
//! whose holder is a live human owner of this vault — the server's existing
//! owner check plus `Vault::authenticate_owner`. Nothing here prompts a second
//! time; the engine writes each act's receipt. Managed vaults are owned
//! through their supervisor, so these routes refuse there.
//!
//! Approvals stay off the idempotency layer: a consumed approval must never
//! replay a cached 200.

use std::sync::Arc;

use axum::Router;
use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::extract::{Query, State};
use axum::response::Json;
use axum::routing::{get, post};
use oneiron::consent::AuthenticatedOwner;
use oneiron::run_tree::GateConsentBundleAction;
use oneiron::store::GateDecisionId;
use serde::Deserialize;

use super::error_map::core_engine_error;
use super::{json_payload, query_params};
use crate::auth::CoreAuth;
use crate::error::{ApiError, ApiErrorDetails, EnvelopedApiError};
use crate::owner::schedule::OwnerHost;
use crate::owner::{OwnerError, backup, imports, location, runs};
use crate::server::SyncServer;

type OwnerReply<T> = Result<Json<T>, EnvelopedApiError>;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/status", get(status))
        .route("/backups", get(list_backups).post(take_backup))
        .route("/backups/rehearse", post(rehearse_backup))
        .route("/secret-scan", get(secret_scan).post(set_secret_scan))
        .route("/imports/preview", post(preview_import))
        .route("/imports/approve", post(approve_import))
        .route("/imports/decline", post(decline_import))
        .route("/runs", get(pending_runs))
        .route("/runs/review", get(review_run))
        .route("/runs/approve", post(approve_run))
        .route("/runs/decline", post(decline_run))
}

/// The owner door. Every refusal is the same 403, so a caller learns nothing
/// about which check failed.
fn owner(auth: &CoreAuth, server: &SyncServer) -> Result<AuthenticatedOwner, ApiError> {
    let refused = || ApiError::forbidden_scope("owner");
    if server.managed_issuer.is_some() || !auth.is_owner_grade() {
        return Err(refused());
    }
    auth.verified_slip()
        .filter(|_| auth.actor_class() == Some("human"))
        .ok_or_else(refused)?;
    let principal = auth.principal_ref().ok_or_else(refused)?;
    let actor = oneiron::EntityId::from_hex(principal).map_err(|_| refused())?;
    let owner = server
        .vault()
        .authenticate_owner(actor, principal, true, GateDecisionId::now())
        .map_err(|_| refused())?;
    if server
        .vault()
        .is_live_vault_owner(&owner)
        .map_err(|_| refused())?
    {
        Ok(owner)
    } else {
        Err(refused())
    }
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
        OwnerError::Engine(error) => match error.kind() {
            oneiron::ErrorKind::ConsentOwnerNotAuthenticated => ApiError::forbidden_scope("owner"),
            oneiron::ErrorKind::ConsentApproveOnceSpent => {
                ApiError::invalid_state(Some("already_decided"))
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
    owner(&auth, &server)?;
    let host = host(&server)?;
    Ok(Json(
        blocking(move || Ok(host.take(server.vault())?)).await?,
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
    let rehearsal = blocking(move || {
        let backups = backup::list(&host.backups)?;
        // Only a file this vault's listing names: never a caller-built path.
        let chosen = match request.file.as_deref() {
            Some(file) => backups.into_iter().find(|record| record.file == file),
            None => backups.into_iter().last(),
        }
        .ok_or_else(|| OwnerError::Invalid("no such backup for this vault".into()))?;
        Ok(backup::rehearse(
            &chosen.path,
            host.vault_config.clone(),
            None,
        )?)
    })
    .await?;
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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RunQuery {
    run_id: String,
}

async fn review_run(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<RunQuery>, QueryRejection>,
) -> OwnerReply<runs::RunReview> {
    let owner = owner(&auth, &server)?;
    let query = query_params(query)?;
    let review = blocking(move || runs::review(server.vault(), &owner, &query.run_id)).await?;
    Ok(Json(review))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DecideRun {
    run_id: String,
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
        runs::resolve(
            server.vault(),
            &owner,
            &request.run_id,
            &request.bundle_id,
            action,
        )
    })
    .await?;
    Ok(Json(resolved))
}
