//! `/v1/owner/usage/events/undecodable`: the stored usage events of this
//! server's metering scope that no longer decode, and `/remove` to remove
//! one the owner reviewed, by the hash of its bytes (FIX 6476). One such row
//! holds every offer check of the vault at unclassified; every other one
//! stays counted as before. Each route runs its `vault.usage.events.*` row's
//! verb hooks once around the engine writer the SDK and MCP doors reach,
//! which revalidates the owner's proof in the write itself. A removal's
//! receipt records where his request reached this install
//! (`machine_routes::act_surface`).

use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::http::HeaderMap;
use axum::response::Json;
use axum::routing::{get, post};
use oneiron::edge::EdgeActorClass;
use oneiron::memory::MemoryError;
use oneiron::memory::usage_repair::{
    UsageRepairListRequest, UsageRepairRemoveRequest, UsageRepairVerb,
};
use serde_json::Value;

use super::{OwnerReply, blocking, hooked_owner};
use crate::api::json_payload;
use crate::auth::CoreAuth;
use crate::error::{ApiError, ApiErrorDetails};
use crate::owner::{OwnerError, hooked_row, memory_refusal};
use crate::server::SyncServer;
use crate::usage::UsageScope;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/usage/events/undecodable", get(list))
        .route("/usage/events/undecodable/remove", post(remove))
}

/// `GET /v1/owner/usage/events/undecodable`: every stored usage event of this
/// server's metering scope that does not decode, each by its `rowRef`, its
/// `byteLength` and the BLAKE3 `hash` of its bytes, none of the bytes.
async fn list(auth: CoreAuth, State(server): State<Arc<SyncServer>>) -> OwnerReply<Value> {
    let (owner, actor) = hooked_owner(&auth, &server)?;
    let scope = metered(&server)?;
    let response = blocking(move || {
        let vault = server.vault();
        let memory = vault.memory(actor, EdgeActorClass::Human);
        hooked_row(
            vault,
            actor,
            UsageRepairVerb::List.name(),
            UsageRepairListRequest::default(),
            |_| {
                server
                    .usage_ledger
                    .list_undecodable_events(&memory, Some(&owner), Some(&scope))
                    .map_err(memory_refusal)
            },
        )
    })
    .await?;
    Ok(Json(response))
}

/// `POST /v1/owner/usage/events/undecodable/remove` with `{"rowRef",
/// "expectedHash"}` as the list gave them: removes that one row while it
/// still holds those bytes and still does not decode, and answers the
/// receipt kept in the same write. A row that is gone is not found; one
/// that changed or decodes now changes nothing.
async fn remove(
    auth: CoreAuth,
    headers: HeaderMap,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<UsageRepairRemoveRequest>, JsonRejection>,
) -> OwnerReply<Value> {
    let (owner, actor) = hooked_owner(&auth, &server)?;
    let surface = super::machine_routes::act_surface(&server, &auth, &headers);
    let request = json_payload(payload)?;
    let scope = metered(&server)?;
    let response = blocking(move || {
        let vault = server.vault();
        let memory = vault.memory(actor, EdgeActorClass::Human);
        hooked_row(
            vault,
            actor,
            UsageRepairVerb::Remove.name(),
            request,
            |request: UsageRepairRemoveRequest| {
                server
                    .usage_ledger
                    .remove_undecodable_event(
                        &memory,
                        Some(&owner),
                        Some(&scope),
                        surface,
                        &request,
                    )
                    .map_err(|error| refusal(error, &request.row_ref))
            },
        )
    })
    .await?;
    Ok(Json(response))
}

/// This server's metering scope, or the typed answer that it meters none.
fn metered(server: &SyncServer) -> Result<UsageScope, ApiError> {
    UsageScope::of(server).ok_or_else(|| {
        ApiError::new(
            "this server meters no usage, so it holds no usage event to repair",
            ApiErrorDetails::InvalidState {
                state: Some("usage_metering_unbound".to_owned()),
            },
            ["Call the server whose meter records this vault's usage."],
        )
    })
}

/// A removal's refusal, as the owner's: the row `row_ref` names is gone, or
/// it changed or decodes now and so is no longer what he reviewed.
fn refusal(error: MemoryError, row_ref: &str) -> OwnerError {
    match error.code.as_str() {
        oneiron::memory::MEMORY_CODE_NOT_FOUND => {
            OwnerError::NotFound("usage event", row_ref.to_owned())
        }
        oneiron::memory::MEMORY_CODE_INVALID_STATE => OwnerError::Changed(error.message),
        _ => memory_refusal(error),
    }
}
