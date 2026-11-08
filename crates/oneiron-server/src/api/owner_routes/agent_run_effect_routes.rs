//! `/v1/owner/agent/run-effects/answer`: the owner's answer to the inbox ask
//! a moved agent run's replayed step raised when the machine that ran it
//! before may already have made its call (FIX 4747 slice 7), behind the same
//! owner door as every other owner route, beside the facade's
//! `vault.agent.run_effect.answer`. No agent answers it: the owner's proof
//! only. The route runs its row's verb hooks once around the one engine
//! operation the SDK and MCP doors also call.

use std::sync::Arc;

use axum::extract::State;
use axum::response::Json;
use axum::routing::post;
use oneiron::task_verb::sdk::{self, AgentRunEffectAnswer};
use serde_json::Value;

use super::{OwnerReply, OwnerRoute, OwnerTable, blocking, hooked_owner};
use crate::api::body_spool::OwnerJsonBody;
use crate::auth::CoreAuth;
use crate::owner::{hooked_row, memory_refusal};
use crate::server::SyncServer;

pub(super) fn owner_table() -> OwnerTable {
    vec![(
        OwnerRoute {
            method: "post",
            path: "/agent/run-effects/answer",
            summary: "Answer the ask on a call an agent run moved to this machine replays, which the machine that ran it before may already have made (FIX 4747): `task_ref` (32 hex) and `intent_ref` (64 hex), both from the inbox ask, and `resend`. Resend makes the call once more under the same intent id; no resend leaves it, and the run's step reads that it may have happened elsewhere. The first answer settles the ask; a later one answers `already_settled`.",
            row: Some("vault.agent.run_effect.answer"),
            shape: None,
        },
        post(answer),
    )]
}

/// `POST /v1/owner/agent/run-effects/answer`: makes one replayed call once
/// more, or leaves it. Answers the run TASK, the call, the answer and what
/// it came to.
async fn answer(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<AgentRunEffectAnswer>,
) -> OwnerReply<Value> {
    let (owner, actor) = hooked_owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let response = blocking(move || {
        let vault = server.vault();
        hooked_row(
            vault,
            actor,
            "vault.agent.run_effect.answer",
            request,
            |request: AgentRunEffectAnswer| {
                sdk::answer_agent_run_effect_as(vault, &owner, request).map_err(memory_refusal)
            },
        )
    })
    .await?;
    Ok(Json(response))
}
