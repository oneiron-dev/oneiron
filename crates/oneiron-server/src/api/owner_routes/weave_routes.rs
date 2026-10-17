//! `/v1/owner/weave`: the owner's doors to the weave lens (OF-499). The
//! owner sets each reader's digest schedule, reads the owner lens live,
//! renders it through the weave-report skill on demand, opens its own
//! digest, which renders its due period first, and labels a link in the
//! owner lens as wrong. A person's or agent's report and digests
//! are its own, through the `vault.weave.*` verbs; owning the vault reads
//! none of them.

use std::sync::Arc;

use axum::Router;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Query, State};
use axum::response::Json;
use axum::routing::{get, post};
use oneiron::EdgeActorClass;
use oneiron::claim::{
    WeaveDigestRequest, WeaveDigestView, WeaveLinkCorrectionView, WeaveReaderRef,
    WeaveReportRequest, WeaveReportView, WeaveScheduleView, WeaveWrongLinkRequest,
};
use oneiron::lens::LensFrameCard;
use serde::Serialize;

use super::{OwnerReply, blocking, owner};
use crate::api::json_payload;
use crate::auth::CoreAuth;
use crate::owner::{OwnerError, OwnerResult};
use crate::server::SyncServer;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/weave/schedules", get(schedules).put(set_schedule))
        .route("/weave/schedules/clear", post(clear_schedule))
        .route("/weave/report", post(report))
        .route("/weave/lens", post(lens))
        .route("/weave/digest", get(digest))
        .route("/weave/link/wrong", post(wrong_link))
}

#[derive(Debug, Serialize)]
struct ScheduleCleared {
    cleared: bool,
}

fn memory_refused(error: oneiron::memory::MemoryError) -> OwnerError {
    OwnerError::Refused(error.to_string())
}

fn memory_invalid(error: oneiron::memory::MemoryError) -> OwnerError {
    OwnerError::Invalid(error.to_string())
}

/// `GET /v1/owner/weave/schedules`: every reader's digest schedule.
async fn schedules(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
) -> OwnerReply<Vec<WeaveScheduleView>> {
    let owner = owner(&auth, &server)?;
    let rows = blocking(move || -> OwnerResult<Vec<WeaveScheduleView>> {
        Ok(server
            .vault()
            .weave_digest_schedules(&owner)?
            .iter()
            .map(WeaveScheduleView::from_schedule)
            .collect())
    })
    .await?;
    Ok(Json(rows))
}

/// `PUT /v1/owner/weave/schedules`: one reader's cadence, first due second
/// and sections. It replaces that reader's row.
async fn set_schedule(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<WeaveScheduleView>, JsonRejection>,
) -> OwnerReply<WeaveScheduleView> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let set = blocking(move || -> OwnerResult<WeaveScheduleView> {
        let row = request.into_schedule().map_err(memory_invalid)?;
        server.vault().set_weave_digest_schedule(&owner, &row)?;
        Ok(WeaveScheduleView::from_schedule(&row))
    })
    .await?;
    Ok(Json(set))
}

/// `POST /v1/owner/weave/schedules/clear`: stop one reader's digests.
async fn clear_schedule(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<WeaveReaderRef>, JsonRejection>,
) -> OwnerReply<ScheduleCleared> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let cleared = blocking(move || -> OwnerResult<ScheduleCleared> {
        let reader = request.reader().map_err(memory_invalid)?;
        Ok(ScheduleCleared {
            cleared: server.vault().clear_weave_digest_schedule(&owner, reader)?,
        })
    })
    .await?;
    Ok(Json(cleared))
}

/// `POST /v1/owner/weave/report`: the owner lens, live.
async fn report(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<WeaveReportRequest>, JsonRejection>,
) -> OwnerReply<WeaveReportView> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let locality = auth.locality();
    let view = blocking(move || -> OwnerResult<WeaveReportView> {
        let vault = server.vault();
        let actor = owner.revalidate(vault)?;
        vault
            .memory(actor, EdgeActorClass::Human)
            .at(locality)
            .weave_report(Some(&owner), &request)
            .map_err(memory_refused)
    })
    .await?;
    Ok(Json(view))
}

/// `POST /v1/owner/weave/lens`: the owner lens, live, rendered through the
/// weave-report skill on this server's Dreamer narrative route, as a card
/// whose frame this server holds for the credential's events on it.
async fn lens(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<WeaveReportRequest>, JsonRejection>,
) -> OwnerReply<LensFrameCard> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let caller = crate::ai_host::WeaveLensCaller::Owner { owner, auth };
    let lens = crate::ai_host::render_live_weave_lens(&server, caller, request)
        .await
        .map_err(|error| super::owner_error(memory_refused(error)))?;
    Ok(Json(lens))
}

/// `GET /v1/owner/weave/digest[?scheduled_for=]`: the owner's digest. The
/// due period renders now, under this proof; then the named period, or the
/// newest, is read under the current policy.
async fn digest(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Query(request): Query<WeaveDigestRequest>,
) -> OwnerReply<Option<WeaveDigestView>> {
    let owner = owner(&auth, &server)?;
    let locality = auth.locality();
    let view = blocking(move || -> OwnerResult<Option<WeaveDigestView>> {
        let vault = server.vault();
        let actor = owner.revalidate(vault)?;
        vault
            .memory(actor, EdgeActorClass::Human)
            .at(locality)
            .weave_digest(Some(&owner), &request)
            .map_err(memory_refused)
    })
    .await?;
    Ok(Json(view))
}

/// `POST /v1/owner/weave/link/wrong`: the owner labels a link it sees in the
/// owner lens as wrong. The label is not a retraction.
async fn wrong_link(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<WeaveWrongLinkRequest>, JsonRejection>,
) -> OwnerReply<WeaveLinkCorrectionView> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let locality = auth.locality();
    let filed = blocking(move || -> OwnerResult<WeaveLinkCorrectionView> {
        let vault = server.vault();
        let actor = owner.revalidate(vault)?;
        vault
            .memory(actor, EdgeActorClass::Human)
            .at(locality)
            .weave_wrong_link(Some(&owner), &owner, &request)
            .map_err(memory_refused)
    })
    .await?;
    Ok(Json(filed))
}
