//! `/v1/owner/secrets/found*`: the owner's side of the found-key notice
//! (OF-560). A write whose mask lifted keys out of a record, or marked a
//! file, raised one inbox Ask for that record. Here the owner reads each
//! record's keys (the handle, the key's kind, where it sat, what was done
//! and what may still be done) and answers one of them:
//!
//! - rotate: the existing `POST /v1/owner/secrets/rotate`, by the key's
//!   custody `name`, which settles the key itself;
//! - delete: the record or file that holds it, a hard delete;
//! - grant: one agent's standing reveal grant on the key's class, in a
//!   project or in none, until revoked;
//! - not a secret: the value goes back where the mask left its handle, the
//!   custody record is revoked, and the write door stops reading it as a hit
//!   in that record.
//!
//! Each act writes its receipt in the engine; nothing here reads a value.

use std::sync::Arc;

use axum::Router;
use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::extract::{Query, State};
use axum::response::Json;
use axum::routing::{get, post};
use oneiron::secret_custody::{FoundKeyCard, FoundKeyNotice, FoundKeySettled};
use serde::{Deserialize, Serialize};

use super::{OwnerReply, blocking, owner};
use crate::api::{json_payload, query_params};
use crate::auth::CoreAuth;
use crate::owner::{OwnerError, OwnerResult, entity_id};
use crate::server::SyncServer;

/// The most records one read lists.
const MAX_FOUND_PAGE: usize = 200;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/secrets/found", get(found))
        .route("/secrets/found/delete", post(delete))
        .route("/secrets/found/grant", post(grant))
        .route("/secrets/found/not-a-secret", post(not_a_secret))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FoundQuery {
    /// Only the records with a key the owner has not answered.
    #[serde(default)]
    pending: bool,
    /// At most this many, newest first; 50 when unset.
    #[serde(default)]
    limit: Option<usize>,
}

/// One record's notice.
#[derive(Debug, Serialize)]
struct NoticeView {
    /// The record, or the file's ASSET, as 32 hex.
    record: String,
    keys: Vec<KeyView>,
}

impl From<FoundKeyNotice> for NoticeView {
    fn from(notice: FoundKeyNotice) -> Self {
        Self {
            record: notice.record.to_hex(),
            keys: notice.keys.into_iter().map(KeyView::from).collect(),
        }
    }
}

/// One found key: its handle, never its value.
#[derive(Debug, Serialize)]
struct KeyView {
    handle: String,
    /// The custody name `POST /v1/owner/secrets/rotate` takes.
    name: String,
    kind: String,
    place: String,
    found_at: u64,
    settled: Option<SettledView>,
    /// `rotate`, `delete`, `grant`, `not_a_secret`: what may still be done.
    actions: Vec<&'static str>,
}

impl From<FoundKeyCard> for KeyView {
    fn from(card: FoundKeyCard) -> Self {
        Self {
            handle: card.handle,
            name: card.name,
            kind: card.kind,
            place: card.place,
            found_at: card.found_at,
            settled: card.settled.map(SettledView::from),
            actions: card
                .actions
                .into_iter()
                .map(|action| action.as_str())
                .collect(),
        }
    }
}

/// What the owner did about a key, and its receipt.
#[derive(Debug, Serialize)]
struct SettledView {
    action: &'static str,
    by: Option<String>,
    at: u64,
    /// `rotation:<hex>`, `redaction:<hex>` or `gate:<hex>`.
    receipt_ref: String,
    /// The standing grant a `grant` wrote; revoke it in the consent registry.
    grant_ref: Option<String>,
}

impl From<FoundKeySettled> for SettledView {
    fn from(settled: FoundKeySettled) -> Self {
        Self {
            action: settled.action.as_str(),
            by: settled.by.map(|by| by.to_hex()),
            at: settled.at,
            receipt_ref: settled.receipt,
            grant_ref: settled.grant_ref,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FoundKey {
    /// The key's handle, such as `sc12`.
    handle: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantFoundKey {
    handle: String,
    /// The agent granted, as 32 hex.
    agent: String,
    /// The project the grant holds in, as 32 hex; absent, reveals asked
    /// outside any project.
    #[serde(default)]
    project: Option<String>,
}

/// `GET /v1/owner/secrets/found?pending=true&limit=50`: each record the
/// write door lifted keys out of, newest first, with its keys. No value is
/// read.
async fn found(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<FoundQuery>, QueryRejection>,
) -> OwnerReply<Vec<NoticeView>> {
    let owner = owner(&auth, &server)?;
    let query = query_params(query)?;
    let limit = query.limit.unwrap_or(50).min(MAX_FOUND_PAGE);
    let views = blocking(move || -> OwnerResult<Vec<NoticeView>> {
        Ok(server
            .vault()
            .found_keys(&owner, query.pending, limit)?
            .into_iter()
            .map(NoticeView::from)
            .collect())
    })
    .await?;
    Ok(Json(views))
}

/// `POST /v1/owner/secrets/found/delete` with `{"handle"}`: deletes the
/// record or file the key sits in (a hard delete, with its redaction
/// receipt) and settles every key found there.
async fn delete(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<FoundKey>, JsonRejection>,
) -> OwnerReply<SettledView> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let settled = blocking(move || -> OwnerResult<SettledView> {
        Ok(server
            .vault()
            .delete_found_key_record(&owner, &request.handle)
            .map_err(|error| OwnerError::Refused(error.to_string()))?
            .into())
    })
    .await?;
    Ok(Json(settled))
}

/// `POST /v1/owner/secrets/found/grant` with `{"handle", "agent",
/// "project"?}`: a standing grant to that agent on the key's class, in that
/// project, until revoked.
async fn grant(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<GrantFoundKey>, JsonRejection>,
) -> OwnerReply<SettledView> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let settled = blocking(move || -> OwnerResult<SettledView> {
        let agent = entity_id("agent", &request.agent)?;
        let project = request
            .project
            .as_deref()
            .map(|project| entity_id("project", project))
            .transpose()?;
        Ok(server
            .vault()
            .grant_found_key(&owner, &request.handle, &agent, project.as_ref())?
            .into())
    })
    .await?;
    Ok(Json(settled))
}

/// `POST /v1/owner/secrets/found/not-a-secret` with `{"handle"}`: the owner
/// overrules the scan for that key in its record.
async fn not_a_secret(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<FoundKey>, JsonRejection>,
) -> OwnerReply<SettledView> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let settled = blocking(move || -> OwnerResult<SettledView> {
        Ok(server
            .vault()
            .rule_found_key_not_a_secret(&owner, &request.handle)?
            .into())
    })
    .await?;
    Ok(Json(settled))
}
