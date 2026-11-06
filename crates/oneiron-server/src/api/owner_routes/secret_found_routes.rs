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
//!   in that record;
//! - re-enter: a key ruled no secret whose custody key no longer opens its
//!   kept value takes the value again (FIX 7404).
//!
//! Each act writes its receipt in the engine; nothing here reads a value.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::rejection::QueryRejection;
use axum::extract::{Query, State};
use axum::http::{Extensions, HeaderMap};
use axum::response::Json;
use axum::routing::{get, post};
use oneiron::secret_custody::{FoundKeyCard, FoundKeyCursor, FoundKeyNotice, FoundKeySettled};
use serde::{Deserialize, Serialize};

use super::{OwnerReply, OwnerRoute, OwnerTable, RestShape, blocking, owner, owner_error};
use crate::api::body_spool::OwnerJsonBody;
use crate::api::{has_json_content_type, query_params};
use crate::auth::CoreAuth;
use crate::error::ApiError;
use crate::owner::secrets::reenter_kept_value_body_schema;
use crate::owner::{OwnerError, OwnerResult, entity_id, secrets};
use crate::server::SyncServer;

/// The most records one page lists; a larger limit is served a page at a
/// time through `next_cursor` (FIX 8204).
const MAX_FOUND_PAGE: usize = 200;

pub(super) fn owner_table() -> OwnerTable {
    vec![
        (
            OwnerRoute {
                method: "get",
                path: "/secrets/found",
                summary: "Each record the write door lifted keys out of, newest first, with its keys, a page at a time: `{notices, next_cursor, done}`, continued with `after`.",
                row: None,
                shape: None,
            },
            get(found),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/secrets/found/delete",
                summary: "Deletes the record or file the key sits in (a hard delete, with its redaction receipt) and settles every key found there.",
                row: None,
                shape: Some(RestShape::json(
                    found_key_body_schema,
                    found_key_settled_schema,
                )),
            },
            post(delete),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/secrets/found/grant",
                summary: "A standing grant to that agent on the key's class, in that project, until revoked.",
                row: None,
                shape: Some(RestShape::json(
                    grant_found_key_body_schema,
                    found_key_settled_schema,
                )),
            },
            post(grant),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/secrets/found/not-a-secret",
                summary: "The owner overrules the scan for that key in its record.",
                row: None,
                shape: Some(RestShape::json(
                    found_key_body_schema,
                    found_key_settled_schema,
                )),
            },
            post(not_a_secret),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/secrets/found/re-enter",
                summary: "Seals the kept value of a key ruled no secret again, where its custody key no longer opens it.",
                row: None,
                shape: Some(RestShape::json(
                    reenter_kept_value_body_schema,
                    found_key_settled_schema,
                )),
            },
            post(reenter),
        ),
    ]
}

/// The OpenAPI schema of `POST /v1/owner/secrets/found/delete`'s body (FIX 11611),
/// shared with `POST /v1/owner/secrets/found/not-a-secret`: [`FoundKey`].
pub(crate) fn found_key_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<FoundKey>()
}

/// The OpenAPI schema of `POST /v1/owner/secrets/found/grant`'s body (FIX 11611):
/// [`GrantFoundKey`].
pub(crate) fn grant_found_key_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<GrantFoundKey>()
}

/// The OpenAPI schema of the three found-key answers (FIX 11611): [`SettledView`].
pub(crate) fn found_key_settled_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<SettledView>()
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FoundQuery {
    /// Only the records with a key the owner has not answered.
    #[serde(default)]
    pending: bool,
    /// At most this many a page, newest first; 50 when unset, and
    /// [`MAX_FOUND_PAGE`] a page past that.
    #[serde(default)]
    limit: Option<usize>,
    /// The `next_cursor` of the page before; from the newest when absent.
    #[serde(default)]
    after: Option<String>,
}

/// One page of notices, and where the next one starts.
#[derive(Debug, Serialize)]
struct FoundPage {
    notices: Vec<NoticeView>,
    /// The next page's `after`; absent once `done`.
    #[serde(skip_serializing_if = "Option::is_none")]
    next_cursor: Option<String>,
    /// No older notice is left under this filter.
    done: bool,
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
#[derive(Debug, Serialize, schemars::JsonSchema)]
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

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct FoundKey {
    /// The key's handle, such as `sc12`.
    handle: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
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

/// `GET /v1/owner/secrets/found?pending=true&limit=50&after=<cursor>`: each
/// record the write door lifted keys out of, newest first, with its keys, a
/// page at a time; `next_cursor` continues to every older notice. No value
/// is read.
async fn found(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<FoundQuery>, QueryRejection>,
) -> OwnerReply<FoundPage> {
    let owner = owner(&auth, &server)?;
    let query = query_params(query)?;
    let limit = query.limit.unwrap_or(50).min(MAX_FOUND_PAGE);
    let after = query
        .after
        .as_deref()
        .map(|text| {
            FoundKeyCursor::parse(text).ok_or_else(|| {
                ApiError::bad_request("after is not a found-key page's next_cursor", Some("after"))
            })
        })
        .transpose()?;
    let page = blocking(move || -> OwnerResult<FoundPage> {
        let page = server
            .vault()
            .found_keys_page(&owner, query.pending, after, limit)?;
        Ok(FoundPage {
            notices: page.notices.into_iter().map(NoticeView::from).collect(),
            next_cursor: page.next_cursor.map(|cursor| cursor.to_text()),
            done: page.done,
        })
    })
    .await?;
    Ok(Json(page))
}

/// `POST /v1/owner/secrets/found/delete` with `{"handle"}`: deletes the
/// record or file the key sits in (a hard delete, with its redaction
/// receipt) and settles every key found there.
async fn delete(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<FoundKey>,
) -> OwnerReply<SettledView> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
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
    payload: OwnerJsonBody<GrantFoundKey>,
) -> OwnerReply<SettledView> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
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
/// overrules the scan for that key in its record. Its revoke records where
/// his request reached this install, as this request proves it
/// (`machine_routes::act_surface_admitted`): audit only (FIX 4650).
async fn not_a_secret(
    auth: CoreAuth,
    headers: HeaderMap,
    extensions: Extensions,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<FoundKey>,
) -> OwnerReply<SettledView> {
    let owner = owner(&auth, &server)?;
    let surface =
        super::machine_routes::act_surface_admitted(&server, &auth, &headers, &extensions);
    let request = payload.read(&server).await?;
    let settled = blocking(move || -> OwnerResult<SettledView> {
        Ok(server
            .vault()
            .rule_found_key_not_a_secret(&owner, surface, &request.handle)?
            .into())
    })
    .await?;
    Ok(Json(settled))
}

/// `POST /v1/owner/secrets/found/re-enter` with `{"handle", "value_base64"}`:
/// the kept value of a key the owner ruled no secret, sealed again where its
/// custody key no longer opens it, which every batch write to its record
/// otherwise answers `credential_leaf_unreadable` for (FIX 7404). The ruling
/// stands and is returned. The body is read after the owner door, by the
/// same wiping reader as rotation's.
async fn reenter(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    headers: HeaderMap,
    body: Body,
) -> OwnerReply<SettledView> {
    let owner = owner(&auth, &server)?;
    if !has_json_content_type(&headers) {
        return Err(ApiError::bad_request("invalid JSON request body", None).into());
    }
    let request = secrets::ReenterKeptValue::read(body)
        .await
        .map_err(owner_error)?;
    let settled = blocking(move || -> OwnerResult<SettledView> {
        Ok(server
            .vault()
            .reenter_found_key_value(&owner, &request.handle, &request.value)?
            .into())
    })
    .await?;
    Ok(Json(settled))
}
