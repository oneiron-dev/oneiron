//! `/v1/owner/steer`: the vault owner's nudge to any live run in the vault,
//! whoever spawned it (FIX 783, Engine ruling 10-18). The proof is the
//! owner's own authenticated session from the owner door; the engine
//! rechecks it in the transaction that reads the run. The `steer` verb row
//! stays spawner-bound for every other actor.

use std::sync::Arc;

use axum::extract::State;
use axum::response::Json;
use axum::routing::post;
use oneiron::EdgeActorClass;
use oneiron::memory::MemoryError;
use oneiron::task_verb::sdk::{SteerReceipt, SteerRequest, steer_child_as_owner};

use super::{CHANGED, OwnerReply, OwnerRoute, OwnerTable, RestShape, blocking, owner};
use crate::api::body_spool::OwnerJsonBody;
use crate::auth::CoreAuth;
use crate::owner::{OwnerError, OwnerResult};
use crate::server::SyncServer;

pub(super) fn owner_table() -> OwnerTable {
    vec![(
        OwnerRoute {
            method: "post",
            path: "/steer",
            summary: "The steer verb's input (task_ref, instruction, key) and its receipt.",
            row: None,
            shape: Some(
                RestShape::json(steer_body_schema, steer_receipt_schema).refusing(&[CHANGED]),
            ),
        },
        post(steer),
    )]
}

/// The OpenAPI schema of `POST /v1/owner/steer`'s body (FIX 11611):
/// [`SteerRequest`].
pub(crate) fn steer_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<SteerRequest>()
}

/// The OpenAPI schema of `POST /v1/owner/steer`'s answer (FIX 11611):
/// [`SteerReceipt`].
pub(crate) fn steer_receipt_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<SteerReceipt>()
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
    payload: OwnerJsonBody<SteerRequest>,
) -> OwnerReply<SteerReceipt> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
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
