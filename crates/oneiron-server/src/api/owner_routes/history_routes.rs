//! `/v1/owner/history`: the owner's erase history (ARCH-0038), behind the
//! same owner door as every other owner route. With two or more live Owners
//! an erase starts the vault's `erase` act and says so (Docs Q05).

use std::sync::Arc;

use axum::Router;
use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::extract::{Query, State};
use axum::response::Json;
use axum::routing::{get, post};
use serde::Deserialize;

use super::{OwnerReply, blocking, owner};
use crate::api::{json_payload, query_params};
use crate::auth::CoreAuth;
use crate::owner::history::{self, EraseHistory, EraseOutcome, Erased, ExecuteErase};
use crate::server::SyncServer;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/history", get(receipts))
        .route("/history/erase", post(erase))
        .route("/history/erase/execute", post(execute))
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
    payload: Result<Json<EraseHistory>, JsonRejection>,
) -> OwnerReply<EraseOutcome> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let outcome = blocking(move || history::erase(server.vault(), &owner, &request)).await?;
    Ok(Json(outcome))
}

/// `POST /v1/owner/history/erase/execute`: runs a waiting history erase the
/// caller started, once its veto window passed with no objection.
async fn execute(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<ExecuteErase>, JsonRejection>,
) -> OwnerReply<Erased> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let erased = blocking(move || history::execute(server.vault(), &owner, &request)).await?;
    Ok(Json(erased))
}
