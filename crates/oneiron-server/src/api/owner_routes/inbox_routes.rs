//! The owner's cross-identity inbox lens, shared with the typed facade.
use std::sync::Arc;

use axum::extract::rejection::QueryRejection;
use axum::extract::{Query, State};
use axum::response::Json;
use axum::routing::get;
use oneiron::EdgeActorClass;
use oneiron::agent_inbox_lens::{InboxLensPage, InboxLensRequest};
use oneiron::memory::MEMORY_CODE_BAD_REQUEST;

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
            .map_err(|error| {
                if error.code == MEMORY_CODE_BAD_REQUEST {
                    OwnerError::Invalid(error.to_string())
                } else {
                    OwnerError::Refused(error.to_string())
                }
            })
    })
    .await?;
    Ok(Json(page))
}
