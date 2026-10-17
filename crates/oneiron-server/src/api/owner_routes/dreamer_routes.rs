//! `/v1/owner/dreamer`: the Dreamer's own changes, and the owner's revert of
//! any one of them (OF-023, owner ruling 10-18: "autoapply + revert rather
//! than holdout"). The Dreamer applies its work at once; the owner lists
//! what it changed, newest first, and takes a change back by its id. A
//! claim is retracted and what it superseded stands again; a summary or a
//! NOTE is archived; a person's `about` goes back to the lines it replaced.

use std::sync::Arc;

use axum::Router;
use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::extract::{Query, State};
use axum::response::Json;
use axum::routing::{get, post};
use oneiron::EdgeActorClass;
use oneiron::dreamer_consolidation::{DreamerChange, DreamerRevertReceipt};
use serde::{Deserialize, Serialize};

use super::{OwnerReply, blocking, owner};
use crate::api::{json_payload, query_params};
use crate::auth::CoreAuth;
use crate::owner::{OwnerError, OwnerResult, entity_id};
use crate::server::SyncServer;

/// The most changes one list returns unless the caller asks for fewer.
const DEFAULT_LIMIT: usize = 100;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/dreamer/changes", get(changes))
        .route("/dreamer/revert", post(revert))
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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RevertChange {
    /// The change, as 32 hex: a claim, a summary, a NOTE or a PERSON.
    change: String,
}

#[derive(Debug, Serialize)]
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

/// `POST /v1/owner/dreamer/revert`: the owner's revert of one Dreamer
/// change, with one receipt.
async fn revert(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<RevertChange>, JsonRejection>,
) -> OwnerReply<ChangeReverted> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
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
