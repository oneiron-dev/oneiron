//! `/v1/owner/agent-grants`: the owner grants a named agent (the seeded
//! Coach included) an explicit verb list, and revokes one such grant (FIX
//! 5628), behind the same owner door as every other owner route. A hosted
//! operator's root acts as nobody (FIX 2222), and no agent reaches this door
//! for its own grant: the owner's proof only. His say-so counts from any
//! surface he is authenticated on; the act records where it reached this
//! install (`machine_routes::act_surface_admitted`). Each route runs its
//! `vault.agents.grants.*` row's verb hooks once around the one engine
//! operation the SDK and MCP doors also call. The grants are reviewed in
//! the consent registry, each with its own one-tap revoke. `GET
//! /v1/owner/agents/base` names the base agents' ids a grant takes (FIX
//! 5734).

use std::sync::Arc;

use axum::extract::State;
use axum::http::{Extensions, HeaderMap};
use axum::response::Json;
use axum::routing::{get, post};
use oneiron::task_verb::sdk::{self, AgentGrantMintRequest, AgentGrantRevokeRequest, EmptyRequest};
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
                path: "/agent-grants/mint",
                summary: "Grant one named agent an explicit verb list (FIX 5628): a live agent principal of the vault (`agent`, 32 hex: an agent definition, or a base agent such as the Coach), the owner's complete six-axis scope stored exactly as given (`authority_scope`, its verbs a nonempty explicit set; it confers only with `read` among them) and an optional `expires_at` (Unix seconds; omitted, the grant stands until revoked). A second mint adds a second grant. Answers the grant, with its one-tap revoke command, and the signed act's ref.",
                row: Some("vault.agents.grants.mint"),
                shape: None,
            },
            post(mint),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/agent-grants/revoke",
                summary: "Revoke one agent grant (`grant_ref`, 32 hex; optional `seen`, 64 hex): the grant stops conferring at once. A repeat answers `changed: false`; an id that names no agent grant (an owner, own-device, guest or member grant included) is not found.",
                row: Some("vault.agents.grants.revoke"),
                shape: None,
            },
            post(revoke),
        ),
        (
            OwnerRoute {
                method: "get",
                path: "/agents/base",
                summary: "The base agents' principal ids for the owner (FIX 5734): `agents`, each `{name, id}`, the Coach first, then the Dreamer; `id` (32 hex) is what `/agent-grants/mint` takes as `agent`.",
                row: Some("vault.agents.base"),
                shape: None,
            },
            get(base),
        ),
    ]
}

/// `POST /v1/owner/agent-grants/mint`: grants one live agent principal
/// (`agent`, 32 hex) the owner's exact six-axis scope (`authority_scope`,
/// its verbs a nonempty explicit list), until `expires_at` or, without
/// one, until revoked. Answers the grant and the signed act's ref.
async fn mint(
    auth: CoreAuth,
    headers: HeaderMap,
    extensions: Extensions,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<AgentGrantMintRequest>,
) -> OwnerReply<Value> {
    let (owner, actor) = hooked_owner(&auth, &server)?;
    let surface =
        super::machine_routes::act_surface_admitted(&server, &auth, &headers, &extensions);
    let request = payload.read(&server).await?;
    let response = blocking(move || {
        let vault = server.vault();
        hooked_row(
            vault,
            actor,
            "vault.agents.grants.mint",
            request,
            |request: AgentGrantMintRequest| {
                sdk::mint_agent_grant_as(vault, &owner, surface, request).map_err(memory_refusal)
            },
        )
    })
    .await?;
    Ok(Json(response))
}

/// `POST /v1/owner/agent-grants/revoke` with `{"grant_ref": "<32 hex>"}`
/// and an optional `seen`: revokes one agent grant. A repeat answers
/// `changed: false`; an id that names no agent grant is not found.
async fn revoke(
    auth: CoreAuth,
    headers: HeaderMap,
    extensions: Extensions,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<AgentGrantRevokeRequest>,
) -> OwnerReply<Value> {
    let (owner, actor) = hooked_owner(&auth, &server)?;
    let surface =
        super::machine_routes::act_surface_admitted(&server, &auth, &headers, &extensions);
    let request = payload.read(&server).await?;
    let response = blocking(move || {
        let vault = server.vault();
        hooked_row(
            vault,
            actor,
            "vault.agents.grants.revoke",
            request,
            |request: AgentGrantRevokeRequest| {
                sdk::revoke_agent_grant_as(vault, &owner, surface, request).map_err(memory_refusal)
            },
        )
    })
    .await?;
    Ok(Json(response))
}

/// `GET /v1/owner/agents/base`: the base agents' principal ids, the Coach
/// first, each as a grant's `agent` takes it.
async fn base(auth: CoreAuth, State(server): State<Arc<SyncServer>>) -> OwnerReply<Value> {
    let (owner, actor) = hooked_owner(&auth, &server)?;
    let response = blocking(move || {
        let vault = server.vault();
        hooked_row(vault, actor, "vault.agents.base", EmptyRequest {}, |_| {
            sdk::read_base_agents_as(vault, &owner).map_err(memory_refusal)
        })
    })
    .await?;
    Ok(Json(response))
}
