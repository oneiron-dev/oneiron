//! The owner's one OFF-default stock-model automatic approval setting.

use std::sync::Arc;

use axum::extract::State;
use axum::http::{Extensions, HeaderMap};
use axum::response::Json;
use axum::routing::{get, post};
use oneiron::settings::StockAutoapprovePolicy;
use serde::Deserialize;

use super::machine_routes::act_surface_admitted;
use super::{OwnerReply, OwnerRoute, OwnerTable, RestShape, blocking, owner};
use crate::api::body_spool::OwnerJsonBody;
use crate::auth::CoreAuth;
use crate::owner::OwnerResult;
use crate::server::SyncServer;

pub(super) fn owner_table() -> OwnerTable {
    vec![
        (
            OwnerRoute {
                method: "get",
                path: "/settings/stock-autoapprove",
                summary: "Reads the owner's stock autoapproval permission and revision.",
                row: None,
                shape: None,
            },
            get(read),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/settings/stock-autoapprove",
                summary: "The owner enables or disables stock automatic approvals.",
                row: None,
                shape: Some(RestShape::json(request_schema, policy_schema)),
            },
            post(put),
        ),
    ]
}

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct PolicyChange {
    enabled: bool,
}

fn request_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<PolicyChange>()
}

fn policy_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<StockAutoapprovePolicy>()
}

async fn read(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
) -> OwnerReply<StockAutoapprovePolicy> {
    owner(&auth, &server)?;
    let policy = blocking(move || -> OwnerResult<StockAutoapprovePolicy> {
        Ok(server.vault().stock_autoapprove_policy()?)
    })
    .await?;
    Ok(Json(policy))
}

async fn put(
    auth: CoreAuth,
    headers: HeaderMap,
    extensions: Extensions,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<PolicyChange>,
) -> OwnerReply<StockAutoapprovePolicy> {
    let owner = owner(&auth, &server)?;
    let surface = act_surface_admitted(&server, &auth, &headers, &extensions);
    let change = payload.read(&server).await?;
    let policy = blocking(move || -> OwnerResult<StockAutoapprovePolicy> {
        Ok(server
            .vault()
            .set_stock_autoapprove_policy(&owner, Some(surface), change.enabled)?)
    })
    .await?;
    Ok(Json(policy))
}
