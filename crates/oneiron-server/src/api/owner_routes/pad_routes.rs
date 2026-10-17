//! `/v1/owner/pads/read`: the owner reads an agent's sealed scratchpads,
//! stating a reason the agent sees in its read log (AGM-1+8, agent-mind
//! §2.6). The ruling needs no Grant for the owner's own agents; an agent that
//! reviews reads answers the reason first.

use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::response::Json;
use axum::routing::post;
use oneiron::EdgeActorClass;
use oneiron::memory::DiaryReadOutcome;
use serde::Deserialize;

use super::{OwnerReply, blocking, owner};
use crate::api::json_payload;
use crate::auth::CoreAuth;
use crate::owner::{OwnerError, OwnerResult, entity_id};
use crate::server::SyncServer;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new().route("/pads/read", post(read))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadPads {
    /// Whose sealed pads, as 32 hex.
    agent: String,
    /// The reason the read states; the agent sees it.
    reason: String,
}

/// `POST /v1/owner/pads/read`: the owner reads an agent's sealed pads.
async fn read(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<ReadPads>, JsonRejection>,
) -> OwnerReply<DiaryReadOutcome> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let locality = auth.locality();
    let outcome = blocking(move || -> OwnerResult<DiaryReadOutcome> {
        let agent = entity_id("agent", &request.agent)?;
        let vault = server.vault();
        let actor = owner.revalidate(vault)?;
        vault
            .memory(actor, EdgeActorClass::Human)
            .at(locality)
            .read_agent_sealed_pads(Some(&owner), agent, &request.reason)
            .map_err(|error| OwnerError::Refused(error.to_string()))
    })
    .await?;
    Ok(Json(outcome))
}
