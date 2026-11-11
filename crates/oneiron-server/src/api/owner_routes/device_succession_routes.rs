//! Owner-only naming of this install's predecessor device key.

use std::sync::Arc;

use axum::extract::State;
use axum::http::{Extensions, HeaderMap};
use axum::response::Json;
use axum::routing::post;
use oneiron::memory::device_succession::DevicePredecessor;

use super::{OwnerReply, OwnerRoute, OwnerTable, RestShape, blocking, owner};
use crate::api::body_spool::OwnerJsonBody;
use crate::auth::CoreAuth;
use crate::owner::OwnerError;
use crate::server::SyncServer;

pub(super) fn owner_table() -> OwnerTable {
    vec![(
        OwnerRoute {
            method: "post",
            path: "/device-successions/name",
            summary: "Name a predecessor device key for this install under the owner's proof.",
            row: None,
            shape: Some(RestShape::json(predecessor_schema, predecessor_schema)),
        },
        post(name_predecessor),
    )]
}

fn predecessor_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<DevicePredecessor>()
}

async fn name_predecessor(
    auth: CoreAuth,
    headers: HeaderMap,
    extensions: Extensions,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<DevicePredecessor>,
) -> OwnerReply<DevicePredecessor> {
    let owner = owner(&auth, &server)?;
    let surface =
        super::machine_routes::act_surface_admitted(&server, &auth, &headers, &extensions);
    let request = payload.read(&server).await?;
    let named = blocking(move || {
        let (client, device_key) = request
            .identifiers()
            .map_err(|error| OwnerError::Invalid(error.to_string()))?;
        server
            .vault()
            .name_device_predecessor_as_owner(&owner, surface, client, device_key)?;
        Ok(request)
    })
    .await?;
    Ok(Json(named))
}
