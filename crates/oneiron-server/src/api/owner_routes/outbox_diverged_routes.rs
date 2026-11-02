//! `/v1/owner/outbox/diverged`: a vault VM's outbox carrier members as the
//! owner sees them (FIX 11074, FIX 11242). Each copy the carrier keeps of a
//! member it never agreed on, as the member's origin retired the agreed
//! version, carries a card with his two answers, remove or keep; each file
//! the guest holds back as damaged at its source is listed beside them. Any
//! live vault Owner reads and answers. The answer goes to the carrier's
//! companion, which carries it out at its next turn: nothing removes a copy
//! without it. A vault with no companion lists nothing and takes no answer.
//! The page and the answer are the facade verbs' own
//! (`vault.outbox.diverged.list` and `.answer`, FIX 11739).

use std::sync::Arc;

use axum::extract::State;
use axum::response::Json;
use axum::routing::{get, post};
use oneiron::task_verb::sdk::{
    OutboxDivergedAnswerReceipt, OutboxDivergedAnswerRequest, OutboxDivergedPage,
};

use super::{OwnerReply, OwnerRoute, OwnerTable, blocking, owner};
use crate::api::body_spool::OwnerJsonBody;
use crate::api::facade::outbox_diverged_doors::{answer_diverged_copy, diverged_page};
use crate::auth::CoreAuth;
use crate::owner::{OwnerError, OwnerResult};
use crate::server::SyncServer;

pub(super) fn owner_table() -> OwnerTable {
    vec![
        (
            OwnerRoute {
                method: "get",
                path: "/outbox/diverged",
                summary: "A vault VM's outbox carrier members the owner should see (FIX 11074): each copy kept that the carrier never agreed on, after its origin retired the agreed version (`diverged_unagreed`: kind, member, the end that holds it, both digests, his answer), and each file held back as damaged at its source (`source_digest_mismatch`), each with a card. `carrier` is false where no companion answers.",
                row: None,
            },
            get(members),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/outbox/diverged",
                summary: "With {\"kind\", \"member\", \"held\", \"answer\": \"remove\" | \"keep\"}: passes the owner's answer to the diverged copy the page lists with that digest to the companion, which carries it out at its next turn; nothing removes the copy without it.",
                row: None,
            },
            post(answer),
        ),
    ]
}

/// The OpenAPI schema of `POST /v1/owner/outbox/diverged`'s body:
/// [`OutboxDivergedAnswerRequest`].
pub(crate) fn answer_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<OutboxDivergedAnswerRequest>()
}

/// The OpenAPI schema of `POST /v1/owner/outbox/diverged`'s answer:
/// [`OutboxDivergedAnswerReceipt`].
pub(crate) fn answer_receipt_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<OutboxDivergedAnswerReceipt>()
}

/// `GET /v1/owner/outbox/diverged`: every member the carrier keeps typed,
/// each with its card.
async fn members(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
) -> OwnerReply<OutboxDivergedPage> {
    owner(&auth, &server)?;
    let page = blocking(move || -> OwnerResult<OutboxDivergedPage> { Ok(diverged_page()) }).await?;
    Ok(Json(page))
}

/// `POST /v1/owner/outbox/diverged` with `{"kind", "member", "held",
/// "answer": "remove" | "keep"}`: passes the owner's answer to the copy the
/// page lists with that digest to the companion.
async fn answer(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<OutboxDivergedAnswerRequest>,
) -> OwnerReply<OutboxDivergedAnswerReceipt> {
    owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let receipt = blocking(move || -> OwnerResult<OutboxDivergedAnswerReceipt> {
        answer_diverged_copy(request).map_err(|error| OwnerError::Changed(format!("{error:#}")))
    })
    .await?;
    Ok(Json(receipt))
}
