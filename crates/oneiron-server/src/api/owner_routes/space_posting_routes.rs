//! `/v1/owner/space-posting`: the per-space ghost-mode dial (ARCH-0063 R10,
//! INB-08). A space defaults to the agent as a named participant; the owner
//! may set it to post as the owner where the channel supports it. The dial
//! never widens what the room may read, and owner presentation still needs
//! its exact owner-space grant before a send leaves.

use std::sync::Arc;

use axum::Router;
use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::extract::{Query, State};
use axum::response::Json;
use axum::routing::get;
use oneiron::channel_identity_autonomy::GroupPostingPreset;
use serde::{Deserialize, Serialize};

use super::{OwnerReply, blocking, owner};
use crate::api::{json_payload, query_params};
use crate::auth::CoreAuth;
use crate::owner::{OwnerResult, entity_id};
use crate::server::SyncServer;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new().route("/space-posting", get(read).post(set))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SpaceQuery {
    /// The channel identity, as 32 hex.
    identity: String,
    /// The platform's space: a chat, channel or thread target.
    space: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SetSpacePosting {
    identity: String,
    space: String,
    preset: GroupPostingPreset,
    /// Also grant the exact owner-space consent owner presentation needs, in
    /// the same owner act. Named presentation needs none.
    #[serde(default)]
    grant: bool,
}

#[derive(Debug, Serialize)]
struct SpacePosting {
    identity: String,
    space: String,
    preset: GroupPostingPreset,
    /// True when the agent posts as the owner (the manifest's policy_risk).
    policy_risk: bool,
    /// True while owner presentation still lacks its owner-space grant.
    needs_owner_consent: bool,
    /// The setting's receipt, when this call wrote one.
    #[serde(skip_serializing_if = "Option::is_none")]
    setting_ref: Option<String>,
}

fn plan(
    server: &SyncServer,
    identity: oneiron::EntityId,
    space: &str,
) -> OwnerResult<oneiron::channel_identity_autonomy::SpacePostingPlan> {
    Ok(server
        .vault()
        .space_posting_plan(identity, space, Default::default())?)
}

/// `GET /v1/owner/space-posting?identity=&space=`: one space's dial. A space
/// never set reads as named participant.
async fn read(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<SpaceQuery>, QueryRejection>,
) -> OwnerReply<SpacePosting> {
    owner(&auth, &server)?;
    let query = query_params(query)?;
    let reply = blocking(move || -> OwnerResult<SpacePosting> {
        let identity = entity_id("identity", &query.identity)?;
        let plan = plan(&server, identity, &query.space)?;
        Ok(SpacePosting {
            identity: identity.to_hex(),
            space: plan.space_ref,
            preset: plan.preset,
            policy_risk: plan.policy_risk,
            needs_owner_consent: plan.needs_owner_consent.is_some(),
            setting_ref: None,
        })
    })
    .await?;
    Ok(Json(reply))
}

/// `POST /v1/owner/space-posting`: sets one space's dial, and with `grant`
/// the exact owner-space consent it needs. A channel whose manifest does not
/// support owner posting refuses owner presets.
async fn set(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<SetSpacePosting>, JsonRejection>,
) -> OwnerReply<SpacePosting> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let reply = blocking(move || -> OwnerResult<SpacePosting> {
        let identity = entity_id("identity", &request.identity)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs());
        let receipt = server
            .vault()
            .set_space_posting_preset(identity, &request.space, request.preset, &owner, now)
            .map_err(|error| crate::owner::OwnerError::Invalid(error.to_string()))?;
        let mut plan = plan(&server, identity, &request.space)?;
        if request.grant
            && let Some(bound) = plan.needs_owner_consent.take()
        {
            server.vault().create_standing_grant(&owner, bound)?;
        }
        Ok(SpacePosting {
            identity: identity.to_hex(),
            space: plan.space_ref,
            preset: plan.preset,
            policy_risk: plan.policy_risk,
            needs_owner_consent: plan.needs_owner_consent.is_some(),
            setting_ref: Some(receipt.setting_ref.to_hex()),
        })
    })
    .await?;
    Ok(Json(reply))
}
