//! `/v1/owner/outbound/uncertain-sends/answer`: the owner's answer to the
//! inbox ask a scheduled send raised when it may have gone out and no
//! provider lookup could tell (FIX 4747), behind the same owner door as every
//! other owner route, beside the facade's
//! `vault.outbound.uncertain_send.answer`. No agent answers it: the owner's
//! proof only. The route runs its row's verb hooks once around the one engine
//! operation the SDK and MCP doors also call.

use std::sync::Arc;

use axum::extract::State;
use axum::response::Json;
use axum::routing::post;
use oneiron::task_verb::sdk::{self, UncertainSendAnswer};
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
            path: "/outbound/uncertain-sends/answer",
            summary: "Answer the ask on a scheduled send that may have gone out and that its provider cannot confirm (FIX 4747): `task_ref` (32 hex, from the inbox ask) and `resend`. Resend sends it once more under the same engine send id; no resend leaves it unsent for good. The first answer settles the ask; a later one answers `already_settled`.",
            row: Some("vault.outbound.uncertain_send.answer"),
            shape: None,
        },
        post(answer),
    )]
}

/// `POST /v1/owner/outbound/uncertain-sends/answer`: sends one uncertain send
/// once more, or leaves it. Answers the TASK, the answer and what it came to.
async fn answer(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<UncertainSendAnswer>,
) -> OwnerReply<Value> {
    let (owner, actor) = hooked_owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let response = blocking(move || {
        let vault = server.vault();
        hooked_row(
            vault,
            actor,
            "vault.outbound.uncertain_send.answer",
            request,
            |request: UncertainSendAnswer| {
                sdk::answer_uncertain_send_as(vault, &owner, request).map_err(memory_refusal)
            },
        )
    })
    .await?;
    Ok(Json(response))
}
