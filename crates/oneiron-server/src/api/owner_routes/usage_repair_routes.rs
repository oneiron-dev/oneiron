//! `/v1/owner/usage/events/undecodable`: the stored usage events of this
//! server's metering scope, every billing owner's rows in its vault (FIX
//! 7035), that no longer decode, and `/remove` to remove one the owner
//! reviewed, by the hash of its bytes (FIX 6476). `/v1/owner/usage/repair/receipts`
//! reads the receipts those removals kept (FIX 7036). One such row holds every
//! offer check of the vault at unclassified; every other one stays counted
//! as before. Each route runs its `vault.usage.*` row's verb hooks
//! once around the engine writer the SDK and MCP doors reach, which
//! revalidates the owner's proof in the write itself; the writer's refusal
//! of his authority answers 403, and a reviewed row that changed or decodes
//! now names which in the conflict's `state` (FIX 7038). A removal's receipt
//! records where his request reached this install
//! (`machine_routes::act_surface`).

use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::Json;
use axum::routing::{get, post};
use oneiron::edge::EdgeActorClass;
use oneiron::memory::usage_repair::{
    UsageRepairListRequest, UsageRepairReceiptsRequest, UsageRepairRemoveRequest, UsageRepairVerb,
};
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MemoryError};
use serde_json::Value;

use super::{OwnerReply, blocking, hooked_owner, owner_error};
use crate::api::body_spool::OwnerJsonBody;
use crate::auth::CoreAuth;
use crate::error::{ApiError, ApiErrorDetails};
use crate::owner::{OwnerError, hooked_row, memory_refusal};
use crate::server::SyncServer;
use crate::usage::{UsageScope, removal_conflict_reason};

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/usage/events/undecodable", get(list))
        .route("/usage/events/undecodable/remove", post(remove))
        .route("/usage/repair/receipts", get(receipts))
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
        let mut answered = None;
        let listed = hooked_row(
            vault,
            actor,
            UsageRepairVerb::List.name(),
            UsageRepairListRequest::default(),
            |_| {
                server
                    .usage_ledger
                    .list_undecodable_events(&memory, Some(&owner), Some(&scope))
                    .map_err(|error| {
                        answered = Answered::of(&error);
                        memory_refusal(error)
                    })
            },
        );
        Ok(listed.map_err(|error| repair_error(error, answered)))
    })
    .await??;
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
    payload: OwnerJsonBody<UsageRepairRemoveRequest>,
) -> OwnerReply<Value> {
    let (owner, actor) = hooked_owner(&auth, &server)?;
    let surface = super::machine_routes::act_surface(&server, &auth, &headers);
    let request = payload.read(&server).await?;
    let scope = metered(&server)?;
    let response = blocking(move || {
        let vault = server.vault();
        let memory = vault.memory(actor, EdgeActorClass::Human);
        let mut answered = None;
        let removed = hooked_row(
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
                    .map_err(|error| {
                        answered = Answered::of(&error);
                        refusal(error, &request.row_ref)
                    })
            },
        );
        Ok(removed.map_err(|error| repair_error(error, answered)))
    })
    .await??;
    Ok(Json(response))
}

/// `GET /v1/owner/usage/repair/receipts`: every receipt a removal kept
/// for this server's metering scope, in key order, as its write kept it; a
/// kept row that no longer decodes is counted in `undecodable`, never read
/// as a receipt (FIX 11302).
async fn receipts(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
) -> OwnerReply<Value> {
    let (owner, actor) = hooked_owner(&auth, &server)?;
    let scope = metered(&server)?;
    let response = blocking(move || {
        let vault = server.vault();
        let memory = vault.memory(actor, EdgeActorClass::Human);
        let mut answered = None;
        let receipts = hooked_row(
            vault,
            actor,
            UsageRepairVerb::Receipts.name(),
            UsageRepairReceiptsRequest::default(),
            |_| {
                server
                    .usage_ledger
                    .list_repair_receipts(&memory, Some(&owner), Some(&scope))
                    .map_err(|error| {
                        answered = Answered::of(&error);
                        memory_refusal(error)
                    })
            },
        );
        Ok(receipts.map_err(|error| repair_error(error, answered)))
    })
    .await??;
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

/// What a repair's refusal answers beyond the owner routes' own (FIX 7038).
#[derive(Clone, Copy)]
enum Answered {
    /// The writer refused the caller's authority for the verb.
    Forbidden,
    /// A reviewed row changed or decodes now: the reason that names which.
    Conflict(&'static str),
}

impl Answered {
    fn of(error: &MemoryError) -> Option<Self> {
        if error.code == MEMORY_CODE_FORBIDDEN {
            return Some(Self::Forbidden);
        }
        removal_conflict_reason(error).map(Self::Conflict)
    }
}

/// A repair's refusal on the wire: the writer's refusal of the caller's
/// authority is 403, and a reviewed row that changed or decodes now is the
/// 409 whose `state` is `usage_event_changed` or `usage_event_decodable`;
/// every other refusal is the owner routes' own.
fn repair_error(error: OwnerError, answered: Option<Answered>) -> ApiError {
    match (answered, error) {
        (Some(Answered::Forbidden), OwnerError::Refused(message)) => ApiError::new(
            message,
            ApiErrorDetails::Forbidden {
                required_scope: None,
            },
            ["Act with the owner's own proof, or under a Grant that names this verb."],
        ),
        (Some(Answered::Conflict(reason)), OwnerError::Changed(message)) => ApiError::new(
            message,
            ApiErrorDetails::InvalidState {
                state: Some(reason.to_owned()),
            },
            ["List the undecodable usage events again, and remove what that list shows."],
        ),
        (_, error) => owner_error(error),
    }
}
