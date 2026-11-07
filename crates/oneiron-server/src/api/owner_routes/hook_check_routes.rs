//! `/v1/owner/hooks/checks`: saved hook cycle and depth checks.

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

pub(super) fn owner_table() -> OwnerTable {
    vec![(
        OwnerRoute {
            method: "get",
            path: "/hooks/checks",
            summary: "Reads saved hook cycle and depth checks with their causal lineage; changes nothing.",
            row: Some("vault.hooks.checks"),
            shape: None,
        },
        get(list),
    )]
}

async fn list(auth: CoreAuth, State(server): State<Arc<SyncServer>>) -> OwnerReply<Value> {
    let (owner, actor) = hooked_owner(&auth, &server)?;
    let checks = blocking(move || {
        let vault = server.vault();
        hooked_row(vault, actor, "vault.hooks.checks", EmptyRequest {}, |_| {
            Ok(vault.hook_checks_as_owner(&owner)?)
        })
    })
    .await?;
    Ok(Json(checks))
}
