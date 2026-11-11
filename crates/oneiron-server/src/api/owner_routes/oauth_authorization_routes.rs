//! `/v1/owner/oauth/authorizations/answer`: the owner's answer to an outside app's OAuth sign-in
//! request for this vault's `/mcp` (FIX 4902), behind the same owner door as every other owner
//! route, beside the facade's `vault.oauth.authorization.answer`. A hosted operator's root acts
//! as nobody (FIX 2222), and no agent answers a sign-in: the owner's proof only. His say-so
//! counts from any surface he is authenticated on; his acts record where it reached this
//! install (`machine_routes::act_surface_admitted`). The route runs its row's verb hooks once
//! around the one engine operation the SDK and MCP doors also call.

use std::sync::Arc;

use axum::extract::State;
use axum::http::{Extensions, HeaderMap};
use axum::response::Json;
use axum::routing::post;
use oneiron::task_verb::sdk::{self, OAuthAuthorizationAnswer};
use serde_json::Value;

use super::{OwnerReply, OwnerRoute, OwnerTable, blocking, hooked_owner};
use crate::api::body_spool::OwnerJsonBody;
use crate::auth::CoreAuth;
use crate::owner::{hooked_row, memory_refusal};
use crate::server::SyncServer;

pub(super) fn owner_table() -> OwnerTable {
    vec![(
        OwnerRoute {
            method: "post",
            path: "/oauth/authorizations/answer",
            summary: "Answer one pending OAuth sign-in request an outside app made for this vault's MCP endpoint (FIX 4902): `request_ref` (32 hex, from the inbox ask), `allow`, and on an allow an optional `tier` (`read`, `propose` or `full`; omitted, the tier the app asked for) and `world_ref` (32 hex; omitted, every world). An allow admits the app as the owner's agent under an agent grant the consent registry lists with its one-tap revoke; a deny sends the app `access_denied`.",
            row: Some("vault.oauth.authorization.answer"),
            shape: None,
        },
        post(answer),
    )]
}

/// `POST /v1/owner/oauth/authorizations/answer`: allows or denies one pending sign-in request.
/// Answers the request, whether it was allowed, and on an allow the agent, its grant and tier.
async fn answer(
    auth: CoreAuth,
    headers: HeaderMap,
    extensions: Extensions,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<OAuthAuthorizationAnswer>,
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
            "vault.oauth.authorization.answer",
            request,
            |request: OAuthAuthorizationAnswer| {
                sdk::answer_oauth_authorization_as(vault, &owner, surface, request)
                    .map_err(memory_refusal)
            },
        )
    })
    .await?;
    Ok(Json(response))
}
