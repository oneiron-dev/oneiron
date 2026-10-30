//! `GET /v1/owner/message-streams/refused` (FIX 11933): the stream seeds
//! the vault's last open could not replay and still keeps, each with the
//! typed refusal its replay met. Every open tries them again; this read
//! retires none. The route mirrors the `vault.message_streams.refused` row:
//! it answers that row's output and runs its verb hooks once around the
//! engine read.

use std::sync::Arc;

use axum::extract::State;
use axum::response::Json;
use axum::routing::get;
use oneiron::task_verb::sdk::EmptyRequest;
use serde_json::Value;

use super::{OwnerReply, OwnerRoute, OwnerTable, blocking, hooked_owner};
use crate::auth::CoreAuth;
use crate::owner::hooked_row;
use crate::server::SyncServer;

const VERB: &str = "vault.message_streams.refused";

pub(super) fn owner_table() -> OwnerTable {
    vec![(
        OwnerRoute {
            method: "get",
            path: "/message-streams/refused",
            summary: "The stream seeds the vault's last open could not replay and still keeps (FIX 11933), each with its MESSAGE, generation, conversation, actor and the typed refusal its replay met. Every open tries them again; this read retires none.",
            row: Some(VERB),
        },
        get(list),
    )]
}

/// `GET /v1/owner/message-streams/refused`, read in the snapshot that
/// revalidates the caller's owner proof.
async fn list(auth: CoreAuth, State(server): State<Arc<SyncServer>>) -> OwnerReply<Value> {
    let (owner, actor) = hooked_owner(&auth, &server)?;
    Ok(Json(
        blocking(move || {
            let vault = server.vault();
            hooked_row(vault, actor, VERB, EmptyRequest {}, |_: EmptyRequest| {
                Ok(vault.stream_recovery_refusals(&owner)?)
            })
        })
        .await?,
    ))
}
