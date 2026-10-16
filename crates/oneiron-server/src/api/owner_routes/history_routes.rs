//! `/v1/owner/history`: the owner's erase history (ARCH-0038), behind the
//! same owner door as every other owner route.

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
use crate::owner::history::{self, EraseHistory, Erased};
use crate::server::SyncServer;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/history", get(receipts))
        .route("/history/erase", post(erase))
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
/// pin, or below `through` when that is no later.
async fn erase(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<EraseHistory>, JsonRejection>,
) -> OwnerReply<Erased> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let erased = blocking(move || history::erase(server.vault(), &owner, &request)).await?;
    Ok(Json(erased))
}
