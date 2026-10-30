//! `/v1/owner/dreamer`: the Dreamer's own changes, and the owner's revert of
//! any one of them (OF-023, owner ruling 10-18: "autoapply + revert rather
//! than holdout"). The Dreamer applies its work at once; the owner lists
//! what it changed, newest first, and takes a change back by its id. A
//! claim is retracted and what it superseded stands again; a summary or a
//! NOTE is archived; a person's `about` goes back to the lines it replaced.

use std::sync::Arc;

use axum::extract::rejection::QueryRejection;
use axum::extract::{Query, State};
use axum::response::Json;
use axum::routing::{get, post};
use oneiron::EdgeActorClass;
use oneiron::dreamer_consolidation::{DreamerChange, DreamerRevertReceipt};
use serde::{Deserialize, Serialize};

use super::{OwnerReply, OwnerRoute, OwnerTable, RestShape, blocking, owner, owner_error};
use crate::api::body_spool::OwnerJsonBody;
use crate::api::query_params;
use crate::auth::CoreAuth;
use crate::owner::{OwnerError, OwnerResult, entity_id};
use crate::server::SyncServer;

/// The most changes one list returns unless the caller asks for fewer.
const DEFAULT_LIMIT: usize = 100;

pub(super) fn owner_table() -> OwnerTable {
    vec![
        (
            OwnerRoute {
                method: "get",
                path: "/dreamer/changes",
                summary: "The Dreamer's standing changes, newest first, and the people whose about it wrote.",
                row: None,
                shape: None,
            },
            get(changes),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/dreamer/revert",
                summary: "The owner's revert of one Dreamer change, with one receipt.",
                row: None,
                shape: Some(RestShape::json(
                    revert_change_body_schema,
                    change_reverted_schema,
                )),
            },
            post(revert),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/dreamer/pause",
                summary: "Sets the owner's own Dreamer pause: no new pass starts, and the running attempt parks at its next boundary. Answers the pause and the owner's cause of it.",
                row: None,
                shape: Some(RestShape::json(
                    dreamer_pause_body_schema,
                    dreamer_paused_schema,
                )),
            },
            post(pause_dreamer),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/dreamer/resume",
                summary: "Clears the owner's own Dreamer pause; a managed freeze still holds it. Answers the pause and the owner's cause of it.",
                row: None,
                shape: Some(RestShape::json(
                    dreamer_pause_body_schema,
                    dreamer_paused_schema,
                )),
            },
            post(resume_dreamer),
        ),
    ]
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChangesQuery {
    limit: Option<usize>,
}

#[derive(Debug, Serialize)]
struct ChangesView {
    changes: Vec<ChangeView>,
    /// People whose newest `about` the Dreamer wrote, revertible by the
    /// person's id.
    people_about: Vec<PersonAboutView>,
    /// Maintenance the Dreamer applied that still stands, revertible by its
    /// finding's id; `label` is its kind.
    maintenance: Vec<ChangeView>,
}

#[derive(Debug, Serialize)]
struct ChangeView {
    change: String,
    /// `claim`, `settlement`, `evidence`, `summary`, `note` or `maintenance`.
    kind: &'static str,
    /// The claim's predicate or the NOTE's kind.
    label: String,
    at: u64,
}

#[derive(Debug, Serialize)]
struct PersonAboutView {
    person: String,
    at: u64,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct RevertChange {
    /// The change, as 32 hex: a claim, a summary, a NOTE or a PERSON.
    change: String,
}

/// `POST /v1/owner/dreamer/pause` and `/resume` carry no fields: `{}`.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct DreamerPauseRequest {}

/// The Dreamer's pause after the call, and the owner's own cause of it:
/// a managed freeze can still hold the pause past a resume.
#[derive(Debug, Serialize, schemars::JsonSchema)]
struct DreamerPaused {
    paused: bool,
    owner_paused: bool,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
struct ChangeReverted {
    change: String,
    kind: &'static str,
    /// Claims retracted: the change, the answers it gave, its supersession
    /// record, a summary's header.
    retracted: Vec<String>,
    /// Markers open again for the owner.
    reopened: Vec<String>,
    /// Claims standing again in place.
    restored: Vec<String>,
    /// The Dreamer's fresh copies of its own claims, as `[claim, copy]`.
    copied: Vec<[String; 2]>,
    /// Claims a later write closed, left as they are.
    left_closed: Vec<String>,
    /// The summary or NOTE archived; the cleanup restore brings it back.
    archived: Option<String>,
    /// The summary current again in a reverted one's place.
    current: Option<String>,
    /// A maintenance revert's settings rows put back.
    settings: Vec<String>,
    /// What a later write changed, left as it is.
    left_alone: Vec<String>,
    receipt_ref: String,
}

/// The OpenAPI schema of `POST /v1/owner/dreamer/revert`'s body (FIX 11611): [`RevertChange`].
pub(crate) fn revert_change_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<RevertChange>()
}

/// The OpenAPI schema of `POST /v1/owner/dreamer/revert`'s answer (FIX 11611):
/// [`ChangeReverted`].
pub(crate) fn change_reverted_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<ChangeReverted>()
}

/// The OpenAPI schema of `POST /v1/owner/dreamer/pause`'s body (FIX 11611), shared
/// with `POST /v1/owner/dreamer/resume`: [`DreamerPauseRequest`].
pub(crate) fn dreamer_pause_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<DreamerPauseRequest>()
}

/// The OpenAPI schema of `POST /v1/owner/dreamer/pause`'s answer (FIX 11611), shared
/// with `POST /v1/owner/dreamer/resume`: [`DreamerPaused`].
pub(crate) fn dreamer_paused_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<DreamerPaused>()
}

fn memory_refused(error: oneiron::memory::MemoryError) -> OwnerError {
    OwnerError::Refused(error.to_string())
}

fn change_view(change: DreamerChange) -> ChangeView {
    ChangeView {
        change: change.change.to_hex(),
        kind: change.kind.as_str(),
        label: change.label,
        at: change.at,
    }
}

fn reverted_view(receipt: DreamerRevertReceipt) -> ChangeReverted {
    let hex =
        |ids: &[oneiron::EntityId]| -> Vec<String> { ids.iter().map(|id| id.to_hex()).collect() };
    let reverted = receipt.reverted;
    ChangeReverted {
        change: receipt.change.to_hex(),
        kind: reverted.kind.as_str(),
        retracted: hex(&reverted.retracted),
        reopened: hex(&reverted.reopened),
        restored: hex(&reverted.restored),
        copied: reverted
            .copied
            .iter()
            .map(|(claim, copy)| [claim.to_hex(), copy.to_hex()])
            .collect(),
        left_closed: hex(&reverted.left_closed),
        archived: reverted.archived.map(|id| id.to_hex()),
        current: reverted.current.map(|id| id.to_hex()),
        settings: reverted.settings,
        left_alone: reverted.left_alone,
        receipt_ref: receipt.receipt_ref,
    }
}

/// `GET /v1/owner/dreamer/changes` (optionally `?limit=<n>`): the Dreamer's
/// standing changes, newest first, and the people whose `about` it wrote.
async fn changes(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<ChangesQuery>, QueryRejection>,
) -> OwnerReply<ChangesView> {
    let owner = owner(&auth, &server)?;
    let query = query_params(query)?;
    let locality = auth.locality();
    let listed = blocking(move || -> OwnerResult<ChangesView> {
        let vault = server.vault();
        let actor = owner.revalidate(vault)?;
        let listed = vault
            .memory(actor, EdgeActorClass::Human)
            .at(locality)
            .dreamer_changes(&owner, query.limit.unwrap_or(DEFAULT_LIMIT))
            .map_err(memory_refused)?;
        Ok(ChangesView {
            changes: listed.changes.into_iter().map(change_view).collect(),
            people_about: listed
                .people
                .into_iter()
                .map(|(person, at)| PersonAboutView {
                    person: person.to_hex(),
                    at,
                })
                .collect(),
            maintenance: listed.maintenance.into_iter().map(change_view).collect(),
        })
    })
    .await?;
    Ok(Json(listed))
}

fn dreamer_control(server: &SyncServer) -> OwnerResult<crate::ai_host::DreamerControl> {
    server
        .ai
        .dreamer_control()
        .ok_or_else(|| OwnerError::Refused("this server holds no dreamer pause control".to_owned()))
}

/// `POST /v1/owner/dreamer/pause` with `{}`: sets the owner's own Dreamer
/// pause — no new pass starts, and the running attempt parks at its next
/// boundary — and answers whether the Dreamer reads paused now.
async fn pause_dreamer(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<DreamerPauseRequest>,
) -> OwnerReply<DreamerPaused> {
    owner(&auth, &server)?;
    payload.read(&server).await?;
    let control = dreamer_control(&server).map_err(owner_error)?;
    control.set_owner_paused(true);
    Ok(Json(DreamerPaused {
        paused: control.paused(),
        owner_paused: control.owner_paused(),
    }))
}

/// `POST /v1/owner/dreamer/resume` with `{}`: clears the owner's own Dreamer
/// pause — a managed freeze still holds it — and answers whether the
/// Dreamer reads paused now.
async fn resume_dreamer(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<DreamerPauseRequest>,
) -> OwnerReply<DreamerPaused> {
    owner(&auth, &server)?;
    payload.read(&server).await?;
    let control = dreamer_control(&server).map_err(owner_error)?;
    control.resume();
    Ok(Json(DreamerPaused {
        paused: control.paused(),
        owner_paused: control.owner_paused(),
    }))
}

/// `POST /v1/owner/dreamer/revert`: the owner's revert of one Dreamer
/// change, with one receipt.
async fn revert(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<RevertChange>,
) -> OwnerReply<ChangeReverted> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let locality = auth.locality();
    let reverted = blocking(move || -> OwnerResult<ChangeReverted> {
        let change = entity_id("change", &request.change)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| {
                u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
            });
        let vault = server.vault();
        let actor = owner.revalidate(vault)?;
        let receipt = vault
            .memory(actor, EdgeActorClass::Human)
            .at(locality)
            .revert_dreamer_change(&owner, change, now)
            .map_err(memory_refused)?;
        Ok(reverted_view(receipt))
    })
    .await?;
    Ok(Json(reverted))
}
