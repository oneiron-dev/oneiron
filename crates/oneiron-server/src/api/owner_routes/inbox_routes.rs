//! The owner's cross-identity inbox lens, shared with the typed facade.
use std::sync::Arc;

use axum::extract::rejection::QueryRejection;
use axum::extract::{Query, State};
use axum::response::Json;
use axum::routing::get;
use oneiron::EdgeActorClass;
use oneiron::agent_inbox_lens::{InboxLensPage, InboxLensRequest};
use oneiron::memory::MemoryError;

use super::{OwnerReply, OwnerRoute, OwnerTable, blocking, owner};
use crate::api::query_params;
use crate::auth::CoreAuth;
use crate::owner::{OwnerError, OwnerResult};
use crate::server::SyncServer;

pub(super) fn owner_table() -> OwnerTable {
    vec![(
        OwnerRoute {
            method: "get",
            path: "/inbox",
            summary: "One page of the lens, filtered to an identity or to one agent's slice when asked.",
            row: None,
            shape: None,
        },
        get(read),
    )]
}

async fn read(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<InboxLensRequest>, QueryRejection>,
) -> OwnerReply<InboxLensPage> {
    let owner = owner(&auth, &server)?;
    let query = query_params(query)?;
    let page = blocking(move || -> OwnerResult<InboxLensPage> {
        let vault = server.vault();
        let actor = owner.revalidate(vault)?;
        vault
            .memory(actor, EdgeActorClass::Human)
            .at(auth.locality())
            .inbox_lens_as_owner(&owner, &query)
            .map_err(inbox_error)
    })
    .await?;
    Ok(Json(page))
}

/// The inbox lens's refusal as the owner's, per engine code as the sibling
/// owner routes answer it (UC-11, ruling UC11-CLIENT-STATUSES item 2): a
/// missing row is 404, an authority refusal or a state that refuses 409,
/// and a code the route does not name (an engine fault among them) 500,
/// never a 409.
pub(super) fn inbox_error(mut error: MemoryError) -> OwnerError {
    // Named overrides: the lens's words carry the engine code, and a state
    // that refuses or an owner binding refusal is refused (409), as before.
    error.message = error.to_string();
    match error.code.as_str() {
        oneiron::memory::MEMORY_CODE_INVALID_STATE
        | oneiron::memory::MEMORY_CODE_OWNER_BINDING_REQUIRED => OwnerError::Refused(error.message),
        _ => OwnerError::from_memory_code(error, Some("inbox_lens"), "inbox lens"),
    }
}
