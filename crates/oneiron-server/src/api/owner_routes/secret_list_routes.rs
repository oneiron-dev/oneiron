//! `GET /v1/owner/secrets`: the owner's list of every secret in custody,
//! value-free (FIX [SECRETS-OWNER-LIST-READ], [SECRETS-HOLDER-LIST-READ]).
//! It runs the SDK row `vault.secrets.list` inside the row's verb hooks, as
//! the owner in person; the engine read revalidates the owner's proof in
//! its snapshot. One item per secret value, each with the machines that
//! hold it; two records are one item only when this install proves they
//! hold one value (RULING SECRETS-LIST-DUP-GROUPING = A). An owner read: no
//! agent grant reaches it.

use std::sync::Arc;

use axum::extract::State;
use axum::response::Json;
use axum::routing::get;
use oneiron::task_verb::sdk::{self, EmptyRequest};
use serde_json::Value;

use super::{OwnerReply, OwnerRoute, OwnerTable, blocking, hooked_owner};
use crate::auth::CoreAuth;
use crate::owner::{hooked_row, memory_refusal};
use crate::server::SyncServer;

pub(super) fn owner_table() -> OwnerTable {
    vec![(
        OwnerRoute {
            method: "get",
            path: "/secrets",
            summary: "Every secret in custody, value-free (FIX SECRETS-OWNER-LIST-READ): `items`, one per secret value, newest first, each with its display name and where that comes from, purpose, uses, payment mark, origin, times, the machines that hold it (class, role, this install) and its records; `maybe_same_as` is a hint, never a merge. Run-bound secrets are left out.",
            row: Some("vault.secrets.list"),
            shape: None,
        },
        get(list_secrets),
    )]
}

/// `GET /v1/owner/secrets`: every secret in custody, value-free.
async fn list_secrets(auth: CoreAuth, State(server): State<Arc<SyncServer>>) -> OwnerReply<Value> {
    let (owner, actor) = hooked_owner(&auth, &server)?;
    let response = blocking(move || {
        let vault = server.vault();
        hooked_row(vault, actor, "vault.secrets.list", EmptyRequest {}, |_| {
            sdk::list_secrets_as(vault, &owner).map_err(memory_refusal)
        })
    })
    .await?;
    Ok(Json(response))
}
