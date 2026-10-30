//! `/v1/owner/history`: the owner's erase history (ARCH-0038), behind the
//! same owner door as every other owner route. With two or more live Owners
//! an erase starts the vault's `erase` act and says so (Docs Q05).

use std::sync::Arc;

use axum::extract::rejection::QueryRejection;
use axum::extract::{Query, State};
use axum::response::Json;
use axum::routing::{get, post};
use serde::Deserialize;

use super::{OwnerReply, OwnerRoute, OwnerTable, blocking, owner};
use crate::api::body_spool::OwnerJsonBody;
use crate::api::query_params;
use crate::auth::CoreAuth;
use crate::owner::history::{self, EraseHistory, EraseOutcome, Erased, ExecuteErase};
use crate::server::SyncServer;

pub(super) fn owner_table() -> OwnerTable {
    vec![
        (
            OwnerRoute {
                method: "get",
                path: "/history",
                summary: "Every history erase filed for one text.",
                row: None,
            },
            get(receipts),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/history/erase",
                summary: "Drops one text's history below its oldest pin, or below through when that is no later.",
                row: None,
            },
            post(erase),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/history/erase/execute",
                summary: "Runs a waiting history erase the caller started, once its veto window passed with no objection.",
                row: None,
            },
            post(execute),
        ),
    ]
}

/// The OpenAPI schema of `POST /v1/owner/history/erase`'s body (FIX 11611):
/// [`EraseHistory`].
pub(crate) fn erase_history_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<EraseHistory>()
}

/// The OpenAPI schema of `POST /v1/owner/history/erase`'s answer (FIX 11611):
/// [`EraseOutcome`].
pub(crate) fn erase_outcome_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<EraseOutcome>()
}

/// The OpenAPI schema of `POST /v1/owner/history/erase/execute`'s body
/// (FIX 11611): [`ExecuteErase`].
pub(crate) fn execute_erase_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<ExecuteErase>()
}

/// The OpenAPI schema of `POST /v1/owner/history/erase/execute`'s answer
/// (FIX 11611): [`Erased`].
pub(crate) fn erased_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<Erased>()
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoryQuery {
    /// The entity whose history erases to list, as 32 hex.
    entity: String,
}

/// `GET /v1/owner/history?entity=`: every history erase filed for one text.
async fn receipts(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<HistoryQuery>, QueryRejection>,
) -> OwnerReply<Vec<Erased>> {
    owner(&auth, &server)?;
    let query = query_params(query)?;
    let receipts = blocking(move || history::receipts(server.vault(), &query.entity)).await?;
    Ok(Json(receipts))
}

/// `POST /v1/owner/history/erase`: drops one text's history below its oldest
/// pin, or below `through` when that is no later. With two or more live
/// Owners it erases nothing yet: `outcome` is `waiting`, with the vault's
/// started `erase` act.
async fn erase(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<EraseHistory>,
) -> OwnerReply<EraseOutcome> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let outcome = blocking(move || history::erase(server.vault(), &owner, &request)).await?;
    Ok(Json(outcome))
}

/// `POST /v1/owner/history/erase/execute`: runs a waiting history erase the
/// caller started, once its veto window passed with no objection.
async fn execute(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<ExecuteErase>,
) -> OwnerReply<Erased> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let erased = blocking(move || history::execute(server.vault(), &owner, &request)).await?;
    Ok(Json(erased))
}
