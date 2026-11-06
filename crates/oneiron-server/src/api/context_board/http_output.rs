//! HTTP serialization keeps the encoded board's storage charged through delivery.

use super::{ContextBoardRequest, context_board_hydrate};
use crate::auth::CoreAuth;
use crate::error::EnvelopedApiError;
use crate::server::SyncServer;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::response::{Json, Response};
use std::sync::Arc;

pub(crate) async fn context_board_hydrate_http(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<ContextBoardRequest>, JsonRejection>,
) -> Result<(axum::Extension<crate::idempotency::ServedRows>, Response), EnvelopedApiError> {
    let (served, Json(response)) =
        context_board_hydrate(auth, State(Arc::clone(&server)), payload).await?;
    Ok((
        served,
        super::super::context_pack::output_memory::context_json_response(&response, &server.memory),
    ))
}
