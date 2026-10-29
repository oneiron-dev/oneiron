//! `/v1/owner/worlds/privacy`: a holder answers the world-privacy requests
//! agents raised (FIX 4480). He accepts or declines an agent's proposal of
//! stricter settings, confirms or declines a widen ask, undoes an agent's
//! tighten from its notice, and changes a world's settings himself (`set`).
//! Each is his own act from whichever linked surface he is on, written by the
//! engine's one settings transaction: a yes is `by: Owner` with `answer` =
//! the request.
//!
//! These routes admit any holder of a world's settings right, not only the
//! vault's owners (FIX 4707, [`holder`]): an Admin or a Delegate whose Grant
//! includes it acts on his own verified human slip, and the engine judges in
//! the acting transaction that he holds the world's right and that his slip
//! is still live. His proof lends him no owner authority anywhere else.
//!
//! `/v1/owner/worlds/privacy/widen-unanimity`: the vault's "widen needs every
//! owner" setting and its per-world overrides. Any one owner turns it on; a
//! change that turns it off while it is on waits for every owner's yes, which
//! the other owners give or refuse at `.../widen-unanimity/off/confirm|decline`.

use std::sync::Arc;

use axum::Router;
use axum::extract::rejection::QueryRejection;
use axum::extract::{Query, State};
use axum::http::{Extensions, HeaderMap};
use axum::response::Json;
use axum::routing::{get, post};
use oneiron::authority::ActAuthority;
use oneiron::consent::AuthenticatedOwner;
use oneiron::policy_model::{
    WidenUnanimity, WidenUnanimityOffRequest, WidenUnanimityOutcome, WorldPrivacyAnswer,
    WorldPrivacyOutcome, WorldPrivacyReceipt, WorldPrivacyRequest, WorldPrivacySetInput,
};
use oneiron::store::GateDecisionId;
use serde::Deserialize;

use super::{OwnerReply, blocking, owner};
use crate::api::body_spool::OwnerJsonBody;
use crate::api::query_params;
use crate::auth::{CoreAuth, CoreScope};
use crate::error::ApiError;
use crate::owner::{OwnerResult, entity_id};
use crate::server::SyncServer;

/// The grant a holder who does not own the vault needs on his slip to read
/// the requests (CALLS "FIX 4707 holder slip scope").
const HOLDER_READS: CoreScope = CoreScope::Read;
/// The grant he needs on it to answer, undo or set (CALLS "FIX 4707 holder
/// slip scope").
const HOLDER_ACTS: CoreScope = CoreScope::Write;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/worlds/privacy/requests", get(list))
        .route("/worlds/privacy/set", post(set))
        .route("/worlds/privacy/proposals/accept", post(accept))
        .route("/worlds/privacy/proposals/decline", post(decline))
        .route("/worlds/privacy/asks/confirm", post(accept))
        .route("/worlds/privacy/asks/decline", post(decline))
        .route("/worlds/privacy/undo", post(undo))
        .route(
            "/worlds/privacy/widen-unanimity",
            get(unanimity).post(set_unanimity),
        )
        .route(
            "/worlds/privacy/widen-unanimity/requests",
            get(unanimity_requests),
        )
        .route(
            "/worlds/privacy/widen-unanimity/off/confirm",
            post(confirm_off),
        )
        .route(
            "/worlds/privacy/widen-unanimity/off/decline",
            post(decline_off),
        )
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestPage {
    /// Only the requests still waiting for a holder.
    #[serde(default)]
    pending: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct AnswerRequest {
    /// The request, 32 hex characters.
    request: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct UndoChange {
    /// The settings receipt the notice carried.
    receipt: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct SetUnanimity {
    /// The world whose override this sets, 32 hex; none sets the vault's.
    #[serde(default)]
    world: Option<String>,
    /// On or off; none clears a world's override.
    #[serde(default)]
    on: Option<bool>,
}

/// The OpenAPI schema of `POST /v1/owner/worlds/privacy/set`'s body
/// (FIX 11611): [`WorldPrivacySetInput`].
pub(crate) fn set_world_privacy_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<WorldPrivacySetInput>()
}

/// The OpenAPI schema of `POST /v1/owner/worlds/privacy/set`'s answer
/// (FIX 11611): [`WorldPrivacyOutcome`].
pub(crate) fn world_privacy_outcome_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<WorldPrivacyOutcome>()
}

/// The OpenAPI schema of the world-privacy answer routes' bodies
/// (FIX 11611: `proposals/accept`, `proposals/decline`, `asks/confirm`,
/// `asks/decline`, `widen-unanimity/off/confirm`,
/// `widen-unanimity/off/decline`): [`AnswerRequest`].
pub(crate) fn world_privacy_answer_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<AnswerRequest>()
}

/// The OpenAPI schema of `POST /v1/owner/worlds/privacy/proposals/accept`'s
/// answer (FIX 11611), shared with `proposals/decline`, `asks/confirm` and
/// `asks/decline`: [`WorldPrivacyAnswer`].
pub(crate) fn world_privacy_answer_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<WorldPrivacyAnswer>()
}

/// The OpenAPI schema of `POST /v1/owner/worlds/privacy/undo`'s body
/// (FIX 11611): [`UndoChange`].
pub(crate) fn undo_world_privacy_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<UndoChange>()
}

/// The OpenAPI schema of `POST /v1/owner/worlds/privacy/undo`'s answer
/// (FIX 11611): [`WorldPrivacyReceipt`].
pub(crate) fn world_privacy_receipt_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<WorldPrivacyReceipt>()
}

/// The OpenAPI schema of `POST /v1/owner/worlds/privacy/widen-unanimity`'s
/// body (FIX 11611): [`SetUnanimity`].
pub(crate) fn set_widen_unanimity_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<SetUnanimity>()
}

/// The OpenAPI schema of `POST /v1/owner/worlds/privacy/widen-unanimity`'s
/// answer (FIX 11611), shared with `widen-unanimity/off/confirm` and
/// `widen-unanimity/off/decline`: [`WidenUnanimityOutcome`].
pub(crate) fn widen_unanimity_outcome_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<WidenUnanimityOutcome>()
}

/// The world-settings door (FIX 4707): the vault's owner as [`owner`] admits
/// him, or any other live person on their own verified human slip, bound to
/// it so the engine rechecks it in the acting transaction. Whether that
/// person holds the world's settings right is the engine's to judge in that
/// same transaction; the proof lends a non-owner no owner authority. Every
/// refusal is the owner door's 403, and a managed owner's or a host action's
/// stays the owner door's own.
pub(super) fn holder(
    auth: &CoreAuth,
    server: &SyncServer,
    scope: CoreScope,
) -> Result<AuthenticatedOwner, ApiError> {
    let owner_refusal = match owner(auth, server) {
        Ok(owner) => return Ok(owner),
        Err(refusal) => refusal,
    };
    if auth.managed_owner().is_some()
        || crate::api::host_action::host_action_of(server.vault(), auth).is_some()
    {
        return Err(owner_refusal);
    }
    let refused = || ApiError::forbidden_scope("owner");
    // A managed vault's other holders come on their own forwarded slips
    // (FIX 5122, FIX 5510), judged here as anywhere else.
    if !auth.has_scope(scope) {
        return Err(refused());
    }
    let slip = auth
        .verified_slip()
        .filter(|_| auth.actor_class() == Some("human"))
        .ok_or_else(refused)?;
    let principal = auth.principal_ref().ok_or_else(refused)?;
    let actor = oneiron::EntityId::from_hex(principal).map_err(|_| refused())?;
    // The slip is the person's own, and no invitee's.
    if slip.claims().holder_ref != actor.to_hex() || slip.claims().invitation_ref.is_some() {
        return Err(refused());
    }
    let person = server
        .vault()
        .authenticate_owner(actor, principal, true, GateDecisionId::now())
        .map_err(|_| refused())?;
    // Binding checks the slip is the person's own human slip, not handed
    // on, and live now.
    server
        .vault()
        .bind_person_credential(person, slip.clone())
        .map_err(|_| refused())
}

/// `GET /v1/owner/worlds/privacy/requests[?pending=true]`: the requests,
/// newest first. A vault owner sees every one; another holder those on the
/// worlds whose settings right he holds now.
async fn list(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<RequestPage>, QueryRejection>,
) -> OwnerReply<Vec<WorldPrivacyRequest>> {
    let holder = holder(&auth, &server, HOLDER_READS)?;
    let page = query_params(query)?;
    let requests = blocking(move || -> OwnerResult<Vec<WorldPrivacyRequest>> {
        Ok(server
            .vault()
            .world_privacy_requests_for(&holder, page.pending.unwrap_or(false))?)
    })
    .await?;
    Ok(Json(requests))
}

/// `POST /v1/owner/worlds/privacy/set`: a holder changes a world's settings
/// as his own act, in either direction (`applied`, the receipt), unless his
/// widen falls under "widen needs every owner" (`asked`, the request his own
/// yes already counts on). The body is `vault.worlds.privacy.set`'s input; a
/// `seen` revision other than the current one is a conflict.
async fn set(
    auth: CoreAuth,
    headers: HeaderMap,
    extensions: Extensions,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<WorldPrivacySetInput>,
) -> OwnerReply<WorldPrivacyOutcome> {
    let holder = holder(&auth, &server, HOLDER_ACTS)?;
    let surface =
        super::machine_routes::act_surface_admitted(&server, &auth, &headers, &extensions);
    let body = payload.read(&server).await?;
    let outcome = blocking(move || -> OwnerResult<WorldPrivacyOutcome> {
        let (world, settings, seen) = body.parse()?;
        Ok(server.vault().set_world_privacy_by(
            &ActAuthority::Owner(holder, surface),
            world,
            settings,
            seen,
        )?)
    })
    .await?;
    Ok(Json(outcome))
}

/// `POST /v1/owner/worlds/privacy/{proposals/accept,asks/confirm}`: the
/// holder's yes. It applies the frozen settings as his own act, or, under
/// "widen needs every owner", counts his yes until every owner's is in.
async fn accept(
    auth: CoreAuth,
    headers: HeaderMap,
    extensions: Extensions,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<AnswerRequest>,
) -> OwnerReply<WorldPrivacyAnswer> {
    answer(auth, headers, &extensions, server, payload, true).await
}

/// `POST /v1/owner/worlds/privacy/{proposals/decline,asks/decline}`: the
/// holder declines the request, or cancels a proposal from its notice.
async fn decline(
    auth: CoreAuth,
    headers: HeaderMap,
    extensions: Extensions,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<AnswerRequest>,
) -> OwnerReply<WorldPrivacyAnswer> {
    answer(auth, headers, &extensions, server, payload, false).await
}

async fn answer(
    auth: CoreAuth,
    headers: HeaderMap,
    extensions: &Extensions,
    server: Arc<SyncServer>,
    payload: OwnerJsonBody<AnswerRequest>,
    yes: bool,
) -> OwnerReply<WorldPrivacyAnswer> {
    let holder = holder(&auth, &server, HOLDER_ACTS)?;
    let surface = super::machine_routes::act_surface_admitted(&server, &auth, &headers, extensions);
    let body = payload.read(&server).await?;
    let answered = blocking(move || -> OwnerResult<WorldPrivacyAnswer> {
        let request = entity_id("request", &body.request)?;
        Ok(server
            .vault()
            .answer_world_privacy_request(&holder, surface, request, yes)?)
    })
    .await?;
    Ok(Json(answered))
}

/// `POST /v1/owner/worlds/privacy/undo`: the notice's one tap. It restores
/// the settings before an agent's tighten, as the holder's own act.
async fn undo(
    auth: CoreAuth,
    headers: HeaderMap,
    extensions: Extensions,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<UndoChange>,
) -> OwnerReply<WorldPrivacyReceipt> {
    let holder = holder(&auth, &server, HOLDER_ACTS)?;
    let surface =
        super::machine_routes::act_surface_admitted(&server, &auth, &headers, &extensions);
    let body = payload.read(&server).await?;
    let receipt = blocking(move || -> OwnerResult<WorldPrivacyReceipt> {
        Ok(server
            .vault()
            .undo_world_privacy_change(&holder, surface, &body.receipt)?)
    })
    .await?;
    Ok(Json(receipt))
}

/// `GET /v1/owner/worlds/privacy/widen-unanimity`: the setting as it stands.
async fn unanimity(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
) -> OwnerReply<WidenUnanimity> {
    owner(&auth, &server)?;
    let row = blocking(move || -> OwnerResult<WidenUnanimity> {
        Ok(server.vault().widen_needs_every_owner()?)
    })
    .await?;
    Ok(Json(row))
}

/// `POST /v1/owner/worlds/privacy/widen-unanimity`: an owner sets the vault's
/// setting, or a world's override. It lands at once (`set`, the row), unless
/// it turns the setting off somewhere while it is on: then it waits for every
/// owner's yes (`pending`, the turn-off request with the yeses so far).
async fn set_unanimity(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<SetUnanimity>,
) -> OwnerReply<WidenUnanimityOutcome> {
    let owner = owner(&auth, &server)?;
    let body = payload.read(&server).await?;
    let outcome = blocking(move || -> OwnerResult<WidenUnanimityOutcome> {
        let world = body
            .world
            .as_deref()
            .map(|world| entity_id("world", world))
            .transpose()?;
        Ok(server
            .vault()
            .set_widen_needs_every_owner(&owner, world, body.on)?)
    })
    .await?;
    Ok(Json(outcome))
}

/// `GET /v1/owner/worlds/privacy/widen-unanimity/requests[?pending=true]`:
/// the turn-offs of the setting, newest first.
async fn unanimity_requests(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<RequestPage>, QueryRejection>,
) -> OwnerReply<Vec<WidenUnanimityOffRequest>> {
    owner(&auth, &server)?;
    let page = query_params(query)?;
    let requests = blocking(move || -> OwnerResult<Vec<WidenUnanimityOffRequest>> {
        Ok(server
            .vault()
            .widen_unanimity_off_requests(page.pending.unwrap_or(false))?)
    })
    .await?;
    Ok(Json(requests))
}

/// `POST /v1/owner/worlds/privacy/widen-unanimity/off/confirm`: an owner's
/// yes to a pending turn-off; the yes that completes every owner's lands it.
async fn confirm_off(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<AnswerRequest>,
) -> OwnerReply<WidenUnanimityOutcome> {
    answer_off(auth, server, payload, true).await
}

/// `POST /v1/owner/worlds/privacy/widen-unanimity/off/decline`: an owner
/// declines a pending turn-off; the setting stays as it is.
async fn decline_off(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<AnswerRequest>,
) -> OwnerReply<WidenUnanimityOutcome> {
    answer_off(auth, server, payload, false).await
}

async fn answer_off(
    auth: CoreAuth,
    server: Arc<SyncServer>,
    payload: OwnerJsonBody<AnswerRequest>,
    yes: bool,
) -> OwnerReply<WidenUnanimityOutcome> {
    let owner = owner(&auth, &server)?;
    let body = payload.read(&server).await?;
    let answered = blocking(move || -> OwnerResult<WidenUnanimityOutcome> {
        let request = entity_id("request", &body.request)?;
        Ok(server
            .vault()
            .answer_widen_unanimity_off(&owner, request, yes)?)
    })
    .await?;
    Ok(Json(answered))
}
