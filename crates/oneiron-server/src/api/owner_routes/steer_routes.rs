//! `/v1/owner/steer`: the vault owner's nudge to any live run in the vault,
//! whoever spawned it (FIX 783, Engine ruling 10-18). The proof is the
//! owner's own authenticated session from the owner door; the engine
//! rechecks it in the transaction that reads the run. The `steer` verb row
//! stays spawner-bound for every other actor.

use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::response::Json;
use axum::routing::post;
use oneiron::EdgeActorClass;
use oneiron::memory::MemoryError;
use oneiron::task_verb::sdk::{SteerReceipt, SteerRequest, steer_child_as_owner};

use super::{OwnerReply, blocking, owner};
use crate::api::json_payload;
use crate::auth::CoreAuth;
use crate::owner::{OwnerError, OwnerResult};
use crate::server::SyncServer;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new().route("/steer", post(steer))
}

fn steer_error(error: MemoryError) -> OwnerError {
    match error.code.as_str() {
        oneiron::memory::MEMORY_CODE_BAD_REQUEST => OwnerError::Invalid(error.message),
        oneiron::memory::MEMORY_CODE_INVALID_STATE => OwnerError::Changed(error.message),
        _ => OwnerError::Refused(error.message),
    }
}

/// `POST /v1/owner/steer`: the `steer` verb's input (`task_ref`,
/// `instruction`, `key`) and its receipt. A resend with the same key answers
/// the first receipt.
async fn steer(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<SteerRequest>, JsonRejection>,
) -> OwnerReply<SteerReceipt> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let locality = auth.locality();
    let receipt = blocking(move || -> OwnerResult<SteerReceipt> {
        let vault = server.vault();
        let actor = owner.revalidate(vault)?;
        let memory = vault.memory(actor, EdgeActorClass::Human).at(locality);
        steer_child_as_owner(&memory, &owner, request).map_err(steer_error)
    })
    .await?;
    Ok(Json(receipt))
}
