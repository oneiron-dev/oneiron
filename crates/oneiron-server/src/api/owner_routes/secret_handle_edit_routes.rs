//! `/v1/owner/secrets/label` and `/v1/owner/secrets/purpose`: the owner's
//! display edits on one secret (FIX [SECRETS-LABEL-PURPOSE-VERBS]). Each
//! route runs its SDK row (`vault.secrets.label.set`,
//! `vault.secrets.purpose.set`) inside the row's verb hooks, as the owner in
//! person; the engine door checks the live owner again in its writer and
//! keeps the act in a Gate record. Display only: neither grants, reveals nor
//! moves custody. An owner act: no agent grant reaches it.

use std::sync::Arc;

use axum::extract::State;
use axum::response::Json;
use axum::routing::post;
use oneiron::task_verb::sdk::{self, SecretLabelSetRequest, SecretPurposeSetRequest};
use serde_json::Value;

use super::{OwnerReply, OwnerRoute, OwnerTable, blocking, hooked_owner};
use crate::api::body_spool::OwnerJsonBody;
use crate::auth::CoreAuth;
use crate::owner::{hooked_row, memory_refusal};
use crate::server::SyncServer;

pub(super) fn owner_table() -> OwnerTable {
    vec![
        (
            OwnerRoute {
                method: "post",
                path: "/secrets/label",
                summary: "The owner sets or clears one secret's label (`secret_id`, 32 hex; `label`, one line, or null or blank to clear it): the name the secrets list and an agent's handle card show for it. Answers the handle, the stored label, the kind label a scan suggests, and the act's Gate receipt.",
                row: Some("vault.secrets.label.set"),
                shape: None,
            },
            post(set_label),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/secrets/purpose",
                summary: "The owner sets or clears what one secret is for (`secret_id`, 32 hex; `purpose`, text in the owner's words, or null or blank to clear it). Answers the handle, the text the side-row wall stored, and the act's Gate receipt.",
                row: Some("vault.secrets.purpose.set"),
                shape: None,
            },
            post(set_purpose),
        ),
    ]
}

/// `POST /v1/owner/secrets/label`: the owner's label on one secret, set or
/// cleared.
async fn set_label(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<SecretLabelSetRequest>,
) -> OwnerReply<Value> {
    let (owner, actor) = hooked_owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let response = blocking(move || {
        let vault = server.vault();
        hooked_row(
            vault,
            actor,
            "vault.secrets.label.set",
            request,
            |request: SecretLabelSetRequest| {
                sdk::set_secret_label_as(vault, &owner, request).map_err(memory_refusal)
            },
        )
    })
    .await?;
    Ok(Json(response))
}

/// `POST /v1/owner/secrets/purpose`: what one secret is for, set or
/// cleared.
async fn set_purpose(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<SecretPurposeSetRequest>,
) -> OwnerReply<Value> {
    let (owner, actor) = hooked_owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let response = blocking(move || {
        let vault = server.vault();
        hooked_row(
            vault,
            actor,
            "vault.secrets.purpose.set",
            request,
            |request: SecretPurposeSetRequest| {
                sdk::set_secret_purpose_as(vault, &owner, request).map_err(memory_refusal)
            },
        )
    })
    .await?;
    Ok(Json(response))
}
