//! `/v1/owner/weave`: the owner's doors to the weave lens (OF-499). The
//! owner sets each reader's digest schedule, reads the owner lens live,
//! renders it through the weave-report skill on demand, opens its own
//! digest, which renders its due period first, and labels a link in the
//! owner lens as wrong. He lists, answers and undoes the Coach's changes to
//! his own digest settings, and tells it what he wants (FIX 5495). A
//! person's or agent's report and digests
//! are its own, through the `vault.weave.*` verbs; owning the vault reads
//! none of them.

use std::sync::Arc;

use axum::extract::{Query, State};
use axum::response::Json;
use axum::routing::{get, post, put};
use oneiron::claim::{
    WeaveDigestFeedback, WeaveDigestRequest, WeaveDigestSettingAnswer, WeaveDigestSettingChange,
    WeaveDigestSettingUndo, WeaveDigestView, WeaveLinkCorrectionView, WeaveReaderRef,
    WeaveReportRequest, WeaveReportView, WeaveScheduleView, WeaveWrongLinkRequest,
};
use oneiron::lens::LensFrameCard;
use oneiron::{EdgeActorClass, EntityId};
use serde::Serialize;

use super::{OwnerReply, OwnerRoute, OwnerTable, blocking, owner};
use crate::api::body_spool::OwnerJsonBody;
use crate::auth::CoreAuth;
use crate::owner::{OwnerError, OwnerResult};
use crate::server::SyncServer;

pub(super) fn owner_table() -> OwnerTable {
    vec![
        (
            OwnerRoute {
                method: "get",
                path: "/weave/schedules",
                summary: "Every reader's digest schedule.",
                row: None,
            },
            get(schedules),
        ),
        (
            OwnerRoute {
                method: "put",
                path: "/weave/schedules",
                summary: "One reader's cadence, first due second and sections.",
                row: None,
            },
            put(set_schedule),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/weave/schedules/clear",
                summary: "Stop one reader's digests.",
                row: None,
            },
            post(clear_schedule),
        ),
        (
            OwnerRoute {
                method: "get",
                path: "/weave/setting-changes",
                summary: "The Coach's changes to the owner's own digest settings, newest first.",
                row: Some("vault.weave.setting_changes.list"),
            },
            get(setting_changes),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/weave/setting-changes/answer",
                summary: "Accept, as the owner's own act, or decline one proposed change.",
                row: Some("vault.weave.setting_changes.answer"),
            },
            post(answer_setting_change),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/weave/setting-changes/undo",
                summary: "The one-tap undo of an applied or accepted change.",
                row: Some("vault.weave.setting_changes.undo"),
            },
            post(undo_setting_change),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/weave/digest-feedback",
                summary: "What the owner tells the Coach about his own digest.",
                row: Some("vault.weave.digest_feedback.put"),
            },
            post(digest_feedback),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/weave/report",
                summary: "The owner lens, live.",
                row: None,
            },
            post(report),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/weave/lens",
                summary: "The owner lens, live, rendered through the weave-report skill on this server's Dreamer narrative route, as a card whose frame this server holds for the credential's events on it.",
                row: None,
            },
            post(lens),
        ),
        (
            OwnerRoute {
                method: "get",
                path: "/weave/digest",
                summary: "The owner's digest.",
                row: None,
            },
            get(digest),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/weave/link/wrong",
                summary: "The owner labels a link it sees in the owner lens as wrong.",
                row: None,
            },
            post(wrong_link),
        ),
    ]
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
struct ScheduleCleared {
    cleared: bool,
}

/// The OpenAPI schema of `PUT /v1/owner/weave/schedules`'s body (FIX 11611):
/// [`WeaveScheduleView`].
pub(crate) fn set_weave_schedule_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<WeaveScheduleView>()
}

/// The OpenAPI schema of `PUT /v1/owner/weave/schedules`'s answer
/// (FIX 11611): [`WeaveScheduleView`].
pub(crate) fn weave_schedule_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<WeaveScheduleView>()
}

/// The OpenAPI schema of `POST /v1/owner/weave/schedules/clear`'s body
/// (FIX 11611): [`WeaveReaderRef`].
pub(crate) fn clear_weave_schedule_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<WeaveReaderRef>()
}

/// The OpenAPI schema of `POST /v1/owner/weave/schedules/clear`'s answer
/// (FIX 11611): [`ScheduleCleared`].
pub(crate) fn weave_schedule_cleared_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<ScheduleCleared>()
}

/// The OpenAPI schema of `POST /v1/owner/weave/link/wrong`'s body
/// (FIX 11611): [`WeaveWrongLinkRequest`].
pub(crate) fn weave_wrong_link_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<WeaveWrongLinkRequest>()
}

/// The OpenAPI schema of `POST /v1/owner/weave/link/wrong`'s answer
/// (FIX 11611): [`WeaveLinkCorrectionView`].
pub(crate) fn weave_link_correction_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<WeaveLinkCorrectionView>()
}

/// The OpenAPI schema of `POST /v1/owner/weave/report`'s body (FIX 11655):
/// [`WeaveReportRequest`]. `POST /v1/owner/weave/lens` takes the same body.
pub(crate) fn weave_report_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<WeaveReportRequest>()
}

/// The OpenAPI schema of `POST /v1/owner/weave/report`'s answer (FIX 11655):
/// [`WeaveReportView`].
pub(crate) fn weave_report_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<WeaveReportView>()
}

/// The OpenAPI schema of `POST /v1/owner/weave/lens`'s answer (FIX 11655):
/// [`LensFrameCard`].
pub(crate) fn weave_lens_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<LensFrameCard>()
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
            .into_iter()
            .map(|(row, held)| WeaveScheduleView::from_schedule(&row, held))
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
    payload: OwnerJsonBody<WeaveScheduleView>,
) -> OwnerReply<WeaveScheduleView> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let set = blocking(move || -> OwnerResult<WeaveScheduleView> {
        let row = request.into_schedule().map_err(memory_invalid)?;
        server.vault().set_weave_digest_schedule(&owner, &row)?;
        Ok(WeaveScheduleView::from_schedule(&row, None))
    })
    .await?;
    Ok(Json(set))
}

/// `POST /v1/owner/weave/schedules/clear`: stop one reader's digests.
async fn clear_schedule(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<WeaveReaderRef>,
) -> OwnerReply<ScheduleCleared> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let cleared = blocking(move || -> OwnerResult<ScheduleCleared> {
        let reader = request.reader().map_err(memory_invalid)?;
        Ok(ScheduleCleared {
            cleared: server.vault().clear_weave_digest_schedule(&owner, reader)?,
        })
    })
    .await?;
    Ok(Json(cleared))
}

/// A change's id off the owner's wire.
fn change_id(change_ref: &str) -> OwnerResult<EntityId> {
    EntityId::from_hex(change_ref)
        .map_err(|_| OwnerError::Invalid("change_ref must be a 32-hex change id".to_owned()))
}

/// `GET /v1/owner/weave/setting-changes`: the Coach's changes to the owner's
/// own digest settings, newest first.
async fn setting_changes(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
) -> OwnerReply<Vec<WeaveDigestSettingChange>> {
    let owner = owner(&auth, &server)?;
    let rows = blocking(move || -> OwnerResult<Vec<WeaveDigestSettingChange>> {
        server
            .vault()
            .weave_digest_setting_changes(&owner)
            .map_err(OwnerError::from)
    })
    .await?;
    Ok(Json(rows))
}

/// `POST /v1/owner/weave/setting-changes/answer`: accept, as the owner's own
/// act, or decline one proposed change.
async fn answer_setting_change(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<WeaveDigestSettingAnswer>,
) -> OwnerReply<WeaveDigestSettingChange> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let answered = blocking(move || -> OwnerResult<WeaveDigestSettingChange> {
        let change = change_id(&request.change_ref)?;
        server
            .vault()
            .answer_weave_digest_setting_change(&owner, change, request.accept)
            .map_err(OwnerError::from)
    })
    .await?;
    Ok(Json(answered))
}

/// `POST /v1/owner/weave/setting-changes/undo`: the one-tap undo of an
/// applied or accepted change.
async fn undo_setting_change(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<WeaveDigestSettingUndo>,
) -> OwnerReply<WeaveDigestSettingChange> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let undone = blocking(move || -> OwnerResult<WeaveDigestSettingChange> {
        let change = change_id(&request.change_ref)?;
        server
            .vault()
            .undo_weave_digest_setting_change(&owner, change)
            .map_err(OwnerError::from)
    })
    .await?;
    Ok(Json(undone))
}

/// `POST /v1/owner/weave/digest-feedback`: what the owner tells the Coach
/// about his own digest.
async fn digest_feedback(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<WeaveDigestFeedback>,
) -> OwnerReply<WeaveDigestFeedback> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let told = blocking(move || -> OwnerResult<WeaveDigestFeedback> {
        server
            .vault()
            .set_weave_digest_feedback(&owner, &request)
            .map_err(OwnerError::from)
    })
    .await?;
    Ok(Json(told))
}

/// `POST /v1/owner/weave/report`: the owner lens, live.
async fn report(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<WeaveReportRequest>,
) -> OwnerReply<WeaveReportView> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
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
    payload: OwnerJsonBody<WeaveReportRequest>,
) -> OwnerReply<LensFrameCard> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let caller = crate::ai_host::WeaveLensCaller::Owner { owner, auth };
    let lens = crate::ai_host::render_live_weave_lens(&server, caller, request)
        .await
        .map_err(|error| super::owner_error(memory_refused(error)))?;
    Ok(Json(lens))
}

/// `GET /v1/owner/weave/digest[?scheduled_for=]`: the owner's digest. The
/// due period renders now, under this proof; then the named period, or the
/// newest, is read under the current policy. Its lens is a card whose frame
/// this server holds for the credential's events on it.
async fn digest(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Query(request): Query<WeaveDigestRequest>,
) -> OwnerReply<Option<WeaveDigestView>> {
    let owner = owner(&auth, &server)?;
    let view = blocking(move || -> OwnerResult<Option<WeaveDigestView>> {
        let vault = server.vault();
        let actor = owner.revalidate(vault)?;
        vault
            .memory(actor, EdgeActorClass::Human)
            .at(auth.locality())
            .weave_digest_framed(Some(&owner), &request)
            .and_then(|framed| {
                framed
                    .map(|framed| {
                        crate::api::facade::host_doors::hold_weave_digest(&server, &auth, framed)
                    })
                    .transpose()
            })
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
    payload: OwnerJsonBody<WeaveWrongLinkRequest>,
) -> OwnerReply<WeaveLinkCorrectionView> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
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
