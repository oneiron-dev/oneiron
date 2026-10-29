//! `/v1/owner`: the vault owner's own actions over HTTP.
//!
//! One door admits every route: a verified, unattenuated owner-grade slip
//! whose holder is a live human owner of this vault — the server's existing
//! owner check plus `Vault::authenticate_owner`. The proof it hands each
//! action stays bound to that slip (`Vault::bind_owner_credential`), so the
//! engine rechecks the slip and the ownership in the transaction that
//! commits: a request queued behind a revocation changes nothing. Nothing
//! here prompts a second time; the engine writes each act's receipt. On a
//! managed vault the owner arrives through his supervisor's
//! `ManagedOwnerAction`, or with his own human device slip like anywhere
//! else (the mesh ruling, 10-19); a hosted operator's root never acts as him
//! (FIX 2222).
//!
//! Approvals stay off the idempotency layer: a consumed approval must never
//! replay a cached 200.

use std::sync::Arc;

use axum::Router;
use axum::extract::rejection::QueryRejection;
use axum::extract::{Query, State};
use axum::response::Json;
use axum::routing::{get, post};
use oneiron::consent::AuthenticatedOwner;
use oneiron::housekeeping::HousekeepingReport;
use oneiron::run_tree::GateConsentBundleAction;
use oneiron::store::GateDecisionId;
use serde::Deserialize;

use super::error_map::core_engine_error;
use super::query_params;
use crate::api::body_spool::OwnerJsonBody;
use crate::auth::CoreAuth;
use crate::error::{ApiError, ApiErrorDetails, EnvelopedApiError};
use crate::owner::schedule::OwnerHost;
use crate::owner::{
    OwnerError, backup, cleanup, feedback, graph_fs, healer, imports, location, note_tombstones,
    off_record, pack_drift, persona, runs,
};
use crate::server::SyncServer;
mod account_routes;
mod agent_grant_routes;
mod authority_clock_routes;
mod backup_setting_routes;
mod browser_takeover_routes;
mod budget_hold_routes;
mod checkpoint_policy_routes;
mod cleanup_decide;
mod commitment_routes;
mod concern_routes;
mod conflict_routes;
pub(crate) mod connector_admission_routes;
mod connector_consent_routes;
pub(crate) mod connector_slate_routes;
mod connector_subscription_routes;
mod conversation_learning_routes;
pub(super) mod courtesy_delete_routes;
mod craft_candidate_routes;
mod decision_ask_routes;
mod desktop_takeover_routes;
mod diary_routes;
mod disclosure_routes;
mod dreamer_maintenance_routes;
mod dreamer_routes;
mod embedding_space_routes;
mod export_audit_routes;
mod federation_connect_routes;
mod feedback_triage_routes;
mod free_time_routes;
mod guest_routes;
mod handoff_alarm_routes;
mod history_routes;
mod house_routes;
mod inbox_routes;
mod intent_routes;
mod learning_setting_routes;
mod legal_hold_routes;
pub(super) mod machine_routes;
mod model_setting_routes;
mod owner_key_enrollment_routes;
pub(super) mod owner_work_routes;
mod pack_preview_routes;
mod pack_routes;
mod pad_routes;
mod peer_confidence_routes;
mod proactivity_routes;
mod recovery_kit_routes;
mod recovery_kit_target_routes;
mod room_thread_setting_routes;
mod root_routes;
mod secret_control_routes;
mod secret_found_routes;
mod secret_lift_routes;
mod secret_reveal_routes;
mod secret_use_routes;
mod shared_training_setup_routes;
mod skill_judge_routes;
mod space_posting_routes;
mod steer_routes;
mod support_grant_routes;
mod training_swap_routes;
mod usage_repair_routes;
mod vault_key_routes;
mod weave_routes;
mod widen_proposal_routes;
mod wire_health_routes;
mod world_privacy_routes;
mod world_privacy_work_routes;

type OwnerReply<T> = Result<Json<T>, EnvelopedApiError>;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/status", get(status))
        .route("/backups", get(list_backups).post(take_backup))
        .route("/backups/rehearse", post(rehearse_backup))
        .route("/maintain", post(run_housekeeping))
        .route("/secret-scan", get(secret_scan).post(set_secret_scan))
        .route("/healer/oversight", get(healer_oversight))
        .route("/healer/failures", get(healer_failures))
        .route("/healer/failures/drill", get(drill_failure))
        .route("/healer/residue", get(healer_residue))
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
        .route("/cleanup/revert-run", post(revert_cleanup_run))
        .route("/cleanup/review", post(cleanup_decide::review_proposal))
        .route("/cleanup/decide", post(cleanup_decide::decide_proposal))
        .route("/notes/tombstones", get(note_tombstone_review))
        .route("/notes/tombstones/accept", post(accept_note_tombstone))
        .route("/notes/tombstones/decline", post(decline_note_tombstone))
        .route("/persona", get(preview_persona))
        .route("/persona/export", post(export_persona))
        .route("/graph-fs", get(read_graph_fs))
        .route("/feedback/preview", post(preview_feedback))
        .route("/feedback/send", post(send_feedback))
        .route("/feedback/inbox", get(feedback_inbox))
        .route("/pack-drift", get(pack_drift_repairs))
        .route("/model-catalog", get(model_catalog).put(set_model_catalog))
        .route("/model-catalog/sync", post(sync_model_catalog))
        .merge(account_routes::routes())
        .merge(authority_clock_routes::routes())
        .merge(budget_hold_routes::routes())
        .merge(checkpoint_policy_routes::routes())
        .merge(commitment_routes::routes())
        .merge(conflict_routes::routes())
        .merge(connector_admission_routes::routes())
        .merge(connector_consent_routes::routes())
        .merge(connector_slate_routes::routes())
        .merge(connector_subscription_routes::routes())
        .merge(diary_routes::routes())
        .merge(disclosure_routes::routes())
        .merge(dreamer_maintenance_routes::routes())
        .merge(dreamer_routes::routes())
        .merge(free_time_routes::routes())
        .merge(embedding_space_routes::routes())
        .merge(export_audit_routes::routes())
        .merge(history_routes::routes())
        .merge(house_routes::routes())
        .merge(inbox_routes::routes())
        .merge(intent_routes::routes())
        .merge(concern_routes::routes())
        .merge(learning_setting_routes::routes())
        .merge(machine_routes::routes())
        .merge(model_setting_routes::routes())
        .merge(room_thread_setting_routes::routes())
        .merge(backup_setting_routes::routes())
        .merge(widen_proposal_routes::routes())
        .merge(craft_candidate_routes::routes())
        .merge(pad_routes::routes())
        .merge(legal_hold_routes::routes())
        .merge(guest_routes::routes())
        .merge(support_grant_routes::routes())
        .merge(agent_grant_routes::routes())
        .merge(proactivity_routes::routes())
        .merge(weave_routes::routes())
        .merge(pack_routes::routes())
        .merge(pack_preview_routes::routes())
        .merge(courtesy_delete_routes::routes())
        .merge(federation_connect_routes::routes())
        .merge(feedback_triage_routes::routes())
        .merge(decision_ask_routes::routes())
        .merge(desktop_takeover_routes::routes())
        .merge(browser_takeover_routes::routes())
        .merge(peer_confidence_routes::routes())
        .merge(skill_judge_routes::routes())
        .merge(wire_health_routes::routes())
        .merge(handoff_alarm_routes::routes())
        .merge(space_posting_routes::routes())
        .merge(vault_key_routes::routes())
        .merge(recovery_kit_routes::routes())
        .merge(secret_control_routes::routes())
        .merge(secret_use_routes::routes())
        .merge(secret_reveal_routes::routes())
        .merge(secret_found_routes::routes())
        .merge(secret_lift_routes::routes())
        .merge(steer_routes::routes())
        .merge(training_swap_routes::routes())
        .merge(usage_repair_routes::routes())
        .merge(conversation_learning_routes::routes())
        .merge(shared_training_setup_routes::routes())
        .merge(world_privacy_routes::routes())
        .merge(world_privacy_work_routes::routes())
        .merge(owner_key_enrollment_routes::routes())
        .merge(owner_work_routes::routes())
        .merge(root_routes::routes())
        .merge(recovery_kit_target_routes::routes())
        .merge(super::owner_origin::routes())
        .merge(super::packs::routes())
}

/// The owner's off-record routes, nested apart from [`routes`]: like the
/// participant routes, they stay out of the wire receipts, which keep who
/// called which route in the vault (ARCH-0052: no durable session trace).
pub(super) fn off_record_routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route(
            "/off-record",
            get(off_record_session).post(enter_off_record),
        )
        .route("/off-record/mode", post(flip_off_record))
        .route("/off-record/witness", post(witness_off_record))
        .route("/off-record/promote", post(promote_off_record))
        .route("/off-record/save", post(save_off_record))
        .route("/off-record/close", post(close_off_record))
}

/// The owner door. Every refusal is the same 403, so a caller learns nothing
/// about which check failed. The proof it returns carries the verified slip,
/// except a managed vault's owner's, whom its supervisor attested for this
/// one request (`ManagedOwnerAction`): that proof holds only while the
/// person is the vault's live recorded owner ([`managed_owner_proof`]); one
/// it no longer records so is told to sign in again (FIX 5327).
pub(crate) fn owner(auth: &CoreAuth, server: &SyncServer) -> Result<AuthenticatedOwner, ApiError> {
    let refused = || ApiError::forbidden_scope("owner");
    if let Some(holder) = auth.managed_owner() {
        return managed_owner_proof(server, holder)?.ok_or_else(ApiError::managed_owner_not_live);
    }
    // A self-hosted root, or the dev mode, acts as the owner its host action
    // names, and its proof carries that action into every acting
    // transaction; a hosted operator's root gets the typed refusal, the
    // support grant being its path (FIX 2222).
    if let Some(action) = super::host_action::host_action_of(server.vault(), auth) {
        let action = action.map_err(super::host_action::host_action_refusal)?;
        // A typed refusal the recheck carries keeps its code (FIX 6032).
        return server
            .vault()
            .authenticate_host_action_owner(&action, GateDecisionId::now())
            .map_err(|error| super::error_map::carried_refusal(&error).unwrap_or_else(refused));
    }
    if !auth.is_owner_grade() {
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

/// A managed vault's attested owner's proof: the recorded owner `holder`
/// names, while that owner is live; `None` for anyone else. There is no
/// slip to bind, so the proof is this request's alone.
pub(crate) fn managed_owner_proof(
    server: &SyncServer,
    holder: oneiron::EntityId,
) -> Result<Option<AuthenticatedOwner>, ApiError> {
    let refused = || ApiError::forbidden_scope("owner");
    let Some(owner) = server
        .vault()
        .authenticate_recorded_owner(holder, &holder.to_hex(), GateDecisionId::now())
        .map_err(|_| refused())?
    else {
        return Ok(None);
    };
    Ok(server
        .vault()
        .is_live_vault_owner(&owner)
        .map_err(|_| refused())?
        .then_some(owner))
}

/// The owner door for a route that runs one SDK row: the proof, and the
/// owner's actor its verb hooks run as (`crate::owner::hooked_row`).
pub(crate) fn hooked_owner(
    auth: &CoreAuth,
    server: &SyncServer,
) -> Result<(AuthenticatedOwner, oneiron::EntityId), ApiError> {
    let proof = owner(auth, server)?;
    // The proof's own person: the credential's principal, or the owner a
    // host credential acts as (FIX 2222).
    let actor = proof
        .actor_for_read(server.vault())
        .map_err(|_| ApiError::forbidden_scope("owner"))?;
    Ok((proof, actor))
}

fn host(server: &SyncServer) -> Result<Arc<OwnerHost>, ApiError> {
    server.owner_host.clone().ok_or_else(|| {
        ApiError::new(
            "this server was started without its vault's backup storage, so it serves no owner status or backups",
            ApiErrorDetails::InvalidState {
                state: Some("owner_host_unset".to_owned()),
            },
            ["`oneiron serve` and a managed vault start with it; on a stopped vault, use the `oneiron backup` command."],
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

pub(super) fn owner_error(error: OwnerError) -> ApiError {
    // FIX 5479, FIX 5615: a backup or a rehearsal stopped at the disk's floor
    // or by a full disk names capacity, never a fault of its own.
    if let Some(capacity) = backup::write_budget::Capacity::of_owner(&error) {
        return ApiError::new(
            capacity.refusal(),
            ApiErrorDetails::InvalidState {
                state: Some(backup::write_budget::CAPACITY_STATE.to_owned()),
            },
            [backup::write_budget::CAPACITY_REMEDY],
        );
    }
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
            // FIX 5147: a stale seen revision (or a write that lost its race)
            // is the same conflict `OwnerError::Changed` answers, with the
            // engine's words, on every owner route, not a 500.
            oneiron::ErrorKind::ConcurrentWrite => {
                owner_error(OwnerError::Changed(error.to_string()))
            }
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
            oneiron::ErrorKind::SecretWiderThanManifest => {
                ApiError::invalid_state(Some("secret_wider_than_manifest"))
            }
            oneiron::ErrorKind::SecretNameInUse => {
                ApiError::invalid_state(Some("secret_name_in_use"))
            }
            oneiron::ErrorKind::SecretManifestNotFound => {
                ApiError::not_found("secret_manifest", None)
            }
            oneiron::ErrorKind::GitHttpRepoNotFound => ApiError::not_found("repo", None),
            // FIX 4955: the root a kit's pieces rebuild, for its confirmation.
            oneiron::ErrorKind::UnverifiedKitRestore | oneiron::ErrorKind::KitConfirmationStale => {
                recovery_kit_target_routes::kit_root_refusal(&error)
                    .unwrap_or_else(|| core_engine_error("owner action failed", *error))
            }
            // Each reason is a fixed sentence about the request's shape; none
            // carries a value.
            oneiron::ErrorKind::InvalidSecretCustodyBody => {
                ApiError::bad_request(error.to_string(), None)
            }
            _ => core_engine_error("owner action failed", *error),
        },
        OwnerError::Host(error) => {
            tracing::error!(
                kind = ?crate::logging::engine_kind(&error),
                "owner action failed"
            );
            ApiError::internal_server_error("owner action failed")
        }
    }
}

/// Runs blocking vault work (snapshots, restores) off the runtime.
pub(super) async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> Result<T, OwnerError> + Send + 'static,
) -> Result<T, ApiError> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|_| ApiError::internal_server_error("owner action task failed"))?
        .map_err(owner_error)
}

/// `GET /v1/owner/status`: where the data lives, the embedder as this
/// server serves it, where feedback goes, the bytes this process's sync
/// links moved, and how its browser stands.
#[derive(serde::Serialize)]
struct OwnerStatus {
    #[serde(flatten)]
    location: location::Location,
    embedder: crate::owner::embedder::EmbedderReport,
    feedback: feedback::FeedbackStatus,
    /// Every sync link since this process started, summed per inner frame
    /// tag: raw bytes against the bytes on the wire, each way (OF-604).
    link_bytes: Vec<oneiron::sync::transport::TagBytesRow>,
    /// The browser readiness a managed `Ping` carries, read from the same
    /// value: its section, its binding and its last guest start (FIX 7670).
    browser: oneiron_vault_contract::BrowserReadiness,
}

/// The admission of a ROOT ADMIN command here (FIX 2222): status, backups,
/// a restore rehearsal and plain upkeep. The host's own live root runs it on
/// any vault no supervisor manages, self-hosted or hosted, as no person:
/// `None`, no owner proof is made up for it. Any other caller runs it as the
/// owner, through [`owner`], and so does every caller on a managed vault,
/// whose host's root acts as nobody (FIX 2222, FIX 5255).
fn root_admin(
    auth: &CoreAuth,
    server: &SyncServer,
) -> Result<Option<AuthenticatedOwner>, ApiError> {
    if server.managed_issuer.is_none() && auth.host_root().is_some() {
        if !auth.credential_is_live(server.vault()) {
            return Err(ApiError::forbidden_scope("owner"));
        }
        return Ok(None);
    }
    owner(auth, server).map(Some)
}

async fn status(auth: CoreAuth, State(server): State<Arc<SyncServer>>) -> OwnerReply<OwnerStatus> {
    root_admin(&auth, &server)?;
    let host = host(&server)?;
    let report = blocking(move || {
        Ok::<_, OwnerError>(OwnerStatus {
            location: host.locate(server.vault())?,
            embedder: server.embedder_report()?,
            feedback: feedback::status(server.feedback.as_deref(), &server.config.feedback_inbox),
            link_bytes: oneiron::sync::transport::process_link_bytes(),
            browser: server.browser_readiness().snapshot(),
        })
    })
    .await?;
    Ok(Json(report))
}

async fn list_backups(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
) -> OwnerReply<Vec<backup::BackupRecord>> {
    root_admin(&auth, &server)?;
    let host = host(&server)?;
    Ok(Json(
        blocking(move || Ok(backup::list(&host.backups)?)).await?,
    ))
}

async fn take_backup(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
) -> OwnerReply<backup::BackupOutcome> {
    let owner = root_admin(&auth, &server)?;
    let host = host(&server)?;
    Ok(Json(
        blocking(move || host.take(server.vault(), owner.as_ref())).await?,
    ))
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct MaintainQuery {
    /// Queue a historical secret lift run before the pass, as
    /// `oneiron maintain --lift-secrets` does (OF-067).
    #[serde(default)]
    lift_secrets: bool,
}

/// `POST /v1/owner/maintain`: every housekeeping sweep now, due or not, as
/// `oneiron maintain` runs them on a stopped vault. A sweep left past the
/// budget is reported and runs on a later tick. `?lift_secrets=true` queues a
/// historical secret lift run first; the pass works it, and a run left
/// unfinished goes on at the next tick. Plain upkeep is a root admin
/// command; lifting secrets is an owner act (FIX 2222).
async fn run_housekeeping(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<MaintainQuery>, QueryRejection>,
) -> OwnerReply<HousekeepingReport> {
    root_admin(&auth, &server)?;
    let query = query_params(query)?;
    if query.lift_secrets {
        let owner = owner(&auth, &server)?;
        let lifting = Arc::clone(&server);
        blocking(move || {
            let vault = lifting.vault();
            vault.start_secret_lift(&owner, vault.now_recorded_at())?;
            Ok(())
        })
        .await?;
    }
    let report = server
        .housekeeping_now()
        .await
        .ok_or_else(|| ApiError::internal_server_error("owner action task failed"))?
        .map_err(|error| owner_error(error.into()))?;
    Ok(Json(report))
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
    payload: OwnerJsonBody<RehearseRequest>,
) -> OwnerReply<backup::Rehearsal> {
    root_admin(&auth, &server)?;
    let host = host(&server)?;
    let request = payload.read(&server).await?;
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
    payload: OwnerJsonBody<SetSecretScan>,
) -> OwnerReply<oneiron::policy_model::SecretScanReceipt> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let receipt = blocking(move || {
        let vault = server.vault();
        Ok(vault.set_secret_scan_mode(&owner, request.mode, vault.now_recorded_at())?)
    })
    .await?;
    Ok(Json(receipt))
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

async fn healer_residue(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
) -> OwnerReply<Vec<healer::HealResidueRead>> {
    owner(&auth, &server)?;
    Ok(Json(
        blocking(move || healer::residue(server.vault())).await?,
    ))
}

async fn preview_import(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<imports::ImportBatch>,
) -> OwnerReply<imports::ImportPreview> {
    let owner = owner(&auth, &server)?;
    let batch = payload.read(&server).await?;
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
    payload: OwnerJsonBody<DecideImport>,
) -> OwnerReply<imports::ImportApproved> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let approved =
        blocking(move || imports::approve(server.vault(), &owner, &request.batch, &request.digest))
            .await?;
    Ok(Json(approved))
}

async fn decline_import(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<DecideImport>,
) -> OwnerReply<imports::ImportDeclined> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
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
    let destination = auth.destination();
    Ok(Json(
        blocking(move || runs::pending(server.vault(), destination)).await?,
    ))
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
    let destination = auth.destination();
    let review = blocking(move || {
        let run = runs::RunName::from_fields(query.run_id.as_deref(), query.run_ref.as_deref())?;
        runs::review(server.vault(), &owner, run, destination)
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
    payload: OwnerJsonBody<DecideRun>,
) -> OwnerReply<runs::RunResolved> {
    decide_run(auth, server, payload, GateConsentBundleAction::Approve).await
}

async fn decline_run(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<DecideRun>,
) -> OwnerReply<runs::RunResolved> {
    decide_run(auth, server, payload, GateConsentBundleAction::Decline).await
}

async fn decide_run(
    auth: CoreAuth,
    server: Arc<SyncServer>,
    payload: OwnerJsonBody<DecideRun>,
    action: GateConsentBundleAction,
) -> OwnerReply<runs::RunResolved> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let destination = auth.destination();
    let resolved = blocking(move || {
        let run =
            runs::RunName::from_fields(request.run_id.as_deref(), request.run_ref.as_deref())?;
        runs::resolve(
            server.vault(),
            &owner,
            run,
            &request.bundle_id,
            action,
            destination,
        )
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
    payload: OwnerJsonBody<cleanup::CleanupSettings>,
) -> OwnerReply<cleanup::CleanupReview> {
    let owner = owner(&auth, &server)?;
    let settings = payload.read(&server).await?;
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
    payload: OwnerJsonBody<DecideCleanup>,
) -> OwnerReply<cleanup::Accepted> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let accepted =
        blocking(move || cleanup::accept(server.vault(), &owner, &request.proposal)).await?;
    Ok(Json(accepted))
}

async fn reject_cleanup(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<DecideCleanup>,
) -> OwnerReply<cleanup::CleanupReview> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let review = blocking(move || {
        cleanup::reject(server.vault(), &owner, &request.proposal)?;
        cleanup::review(server.vault())
    })
    .await?;
    Ok(Json(review))
}

async fn note_tombstone_review(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
) -> OwnerReply<note_tombstones::TombstoneReview> {
    let owner = owner(&auth, &server)?;
    let review = blocking(move || note_tombstones::review(server.vault(), &owner)).await?;
    Ok(Json(review))
}

async fn accept_note_tombstone(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<note_tombstones::Decide>,
) -> OwnerReply<note_tombstones::Tombstoned> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let tombstoned =
        blocking(move || note_tombstones::accept(server.vault(), &owner, &request)).await?;
    Ok(Json(tombstoned))
}

async fn decline_note_tombstone(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<note_tombstones::Decide>,
) -> OwnerReply<note_tombstones::TombstoneReview> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let review =
        blocking(move || note_tombstones::decline(server.vault(), &owner, &request)).await?;
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
    payload: OwnerJsonBody<RestoreArchived>,
) -> OwnerReply<cleanup::CleanupReview> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
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
struct RevertCleanupRun {
    /// A run's `attempt` from the `runs` list of `GET /v1/owner/cleanup`.
    attempt: String,
}

async fn revert_cleanup_run(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<RevertCleanupRun>,
) -> OwnerReply<cleanup::RunReverted> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let reverted =
        blocking(move || cleanup::revert_run(server.vault(), &owner, &request.attempt)).await?;
    Ok(Json(reverted))
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
    let destination = auth.destination();
    let preview =
        blocking(move || persona::preview(server.vault(), &query.subject, destination)).await?;
    Ok(Json(preview))
}

async fn export_persona(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<persona::ExportRequest>,
) -> OwnerReply<persona::Exported> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let destination = auth.destination();
    let exported =
        blocking(move || persona::export(server.vault(), &owner, &request, destination)).await?;
    Ok(Json(exported))
}

async fn enter_off_record(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<off_record::Enter>,
) -> OwnerReply<off_record::Session> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
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
    payload: OwnerJsonBody<off_record::Flip>,
) -> OwnerReply<off_record::Session> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let session = blocking(move || off_record::flip(server.vault(), &owner, &request)).await?;
    Ok(Json(session))
}

async fn witness_off_record(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<off_record::Witness>,
) -> OwnerReply<oneiron::memory::WitnessReceipt> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let receipt = blocking(move || off_record::witness(server.vault(), &owner, &request)).await?;
    Ok(Json(receipt))
}

async fn promote_off_record(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<off_record::Promote>,
) -> OwnerReply<off_record::Promoted> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let promoted = blocking(move || off_record::promote(server.vault(), &owner, &request)).await?;
    Ok(Json(promoted))
}

async fn save_off_record(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<off_record::SessionName>,
) -> OwnerReply<off_record::Saved> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let saved = blocking(move || off_record::save(server.vault(), &owner, &request)).await?;
    Ok(Json(saved))
}

async fn close_off_record(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<off_record::SessionName>,
) -> OwnerReply<off_record::Closed> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
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
    // The owner's own scoped read: the tree is what the owner's slip reads,
    // or what the owner a self-hosted root or the dev mode acts as reads,
    // with that owner's guarded key (FIX 2222).
    let reader = match super::host_action::require_host_owner_act(&server, &auth)? {
        Some(action) => action.read_key(),
        None => {
            let proof = auth
                .verified_slip()
                .ok_or_else(|| ApiError::forbidden_scope("owner"))?;
            super::credential_read_key(server.vault(), proof)?
        }
    }
    .at(auth.locality());
    let query = query_params(query)?;
    let reply = blocking(move || graph_fs::run(server.vault(), reader, &query)).await?;
    Ok(Json(reply))
}

async fn preview_feedback(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<feedback::FeedbackRequest>,
) -> OwnerReply<feedback::Preview> {
    let owner = owner(&auth, &server)?;
    let host = feedback_host(&server)?;
    let request = payload.read(&server).await?;
    Ok(Json(
        blocking(move || {
            let redactor = crate::feedback_redaction::feedback_redactor(&server);
            feedback::preview(server.vault(), &host, &owner, &request, &redactor)
        })
        .await?,
    ))
}

async fn send_feedback(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<feedback::SendRequest>,
) -> OwnerReply<feedback::Sent> {
    let owner = owner(&auth, &server)?;
    let host = feedback_host(&server)?;
    let request = payload.read(&server).await?;
    // FIX 5212: the send carries the bytes the preview kept and runs no
    // filter.
    let sent = blocking(move || feedback::send(server.vault(), &host, &owner, &request)).await?;
    Ok(Json(sent))
}

async fn feedback_inbox(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<feedback::InboxPage>, QueryRejection>,
) -> OwnerReply<Vec<oneiron::feedback::FeedbackInboxNote>> {
    owner(&auth, &server)?;
    let page = query_params(query)?;
    Ok(Json(
        blocking(move || feedback::inbox(server.vault(), &page)).await?,
    ))
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

/// `GET /v1/owner/model-catalog`: the catalog ref's sync policy, the
/// revisions it has seen and trusted, and the installed pack.
async fn model_catalog(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
) -> OwnerReply<oneiron::skill_hub::ModelCatalogSync> {
    owner(&auth, &server)?;
    Ok(Json(
        blocking(move || Ok(server.vault().model_catalog_sync()?)).await?,
    ))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SetModelCatalog {
    /// `pinned-commit`, `pinned-ref` or `content-hash-frozen`.
    sync_policy: String,
    /// The commit, the tag to follow, or the content hash to hold.
    pin: String,
}

/// `PUT /v1/owner/model-catalog`: move the catalog ref's policy. Nothing is
/// fetched until the next sync.
async fn set_model_catalog(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<SetModelCatalog>,
) -> OwnerReply<oneiron::skill_hub::ModelCatalogSync> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let policy = oneiron::skill_hub::HubSyncPolicy::parse(&request.sync_policy)
        .ok_or_else(|| ApiError::bad_request("unknown sync policy", Some("sync_policy")))?;
    let state = blocking(move || {
        Ok(server
            .vault()
            .set_model_catalog_sync(&owner, policy, request.pin)?)
    })
    .await?;
    Ok(Json(state))
}

/// What one catalog sync did, and the catalog ref after it.
#[derive(serde::Serialize)]
struct ModelCatalogSynced {
    /// `installed`, `candidate` or `blocked`.
    outcome: &'static str,
    /// Why a blocked pack did not install.
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    catalog: oneiron::skill_hub::ModelCatalogSync,
}

/// `POST /v1/owner/model-catalog/sync`: fetch the catalog at its ref's policy
/// and install it. An installed catalog's rows are admitted at once by
/// `/v1/llm` calls that name them.
async fn sync_model_catalog(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
) -> OwnerReply<ModelCatalogSynced> {
    use oneiron::skill_hub::pack_catalog::PackInstallDisposition;
    let owner = owner(&auth, &server)?;
    let host = Arc::clone(&server);
    let synced = blocking(move || {
        let vault = server.vault();
        let (outcome, reason) = match vault.sync_model_catalog(&owner)? {
            PackInstallDisposition::Installed(_) => ("installed", None),
            PackInstallDisposition::Candidate(_) => ("candidate", None),
            PackInstallDisposition::Blocked { reason } => ("blocked", Some(reason)),
        };
        Ok(ModelCatalogSynced {
            outcome,
            reason,
            catalog: vault.model_catalog_sync()?,
        })
    })
    .await?;
    // Each row the catalog brought in or changed is counted on the fixed
    // passage, in the background (OF-577).
    if synced.outcome == "installed"
        && let Some(ratios) = host.ai.model_runtime().token_ratios()
    {
        let vault = Arc::clone(host.vault());
        tokio::task::spawn_blocking(move || {
            if let Err(error) = ratios.measure_missing_blocking(&vault) {
                tracing::warn!(%error, "catalog token ratios were not measured");
            }
        });
    }
    Ok(Json(synced))
}
