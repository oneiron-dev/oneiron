//! `/v1/owner/pads/read`: the owner reads an agent's sealed scratchpads,
//! stating a reason the agent sees in its read log (AGM-1+8, agent-mind
//! §2.6). The ruling needs no Grant for the owner's own agents; an agent that
//! reviews reads answers the reason first.

use std::sync::Arc;

use axum::extract::State;
use axum::response::Json;
use axum::routing::post;
use oneiron::EdgeActorClass;
use oneiron::memory::DiaryReadOutcome;
use serde::Deserialize;

use super::{OwnerReply, OwnerRoute, OwnerTable, blocking, owner};
use crate::api::body_spool::OwnerJsonBody;
use crate::auth::CoreAuth;
use crate::owner::{OwnerError, OwnerResult, entity_id};
use crate::server::SyncServer;

pub(super) fn owner_table() -> OwnerTable {
    vec![(
        OwnerRoute {
            method: "post",
            path: "/pads/read",
            summary: "The owner reads an agent's sealed pads.",
            row: None,
        },
        post(read),
    )]
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct ReadPads {
    /// Whose sealed pads, as 32 hex.
    agent: String,
    /// The reason the read states; the agent sees it.
    reason: String,
}

/// The OpenAPI schema of `POST /v1/owner/pads/read`'s body (FIX 11611): [`ReadPads`].
/// Its answer reuses [`super::diary_routes::diary_read_outcome_schema`].
pub(crate) fn read_pads_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<ReadPads>()
}

/// `POST /v1/owner/pads/read`: the owner reads an agent's sealed pads.
async fn read(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<ReadPads>,
) -> OwnerReply<DiaryReadOutcome> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
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
