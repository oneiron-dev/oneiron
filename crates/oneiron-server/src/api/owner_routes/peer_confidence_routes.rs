//! `/v1/owner/federation/peer-confidence`: how far this vault believes each
//! federation peer (OF-149). Admission scales every claim a peer sends by
//! its scale; a peer without one gets the default.
//! `/v1/owner/federation/grant-travel`: the born-with text one federation
//! grant's windows carry to another vault (OF-491); a grant without one
//! sends none.

use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::response::Json;
use axum::routing::{get, post};
use oneiron::share_travel::TravelChoice;
use serde::{Deserialize, Serialize};

use super::{OwnerReply, blocking, owner};
use crate::api::json_payload;
use crate::auth::CoreAuth;
use crate::owner::stamp::rfc3339_secs;
use crate::owner::{OwnerResult, entity_id};
use crate::server::SyncServer;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/federation/peer-confidence", get(list).post(set))
        .route("/federation/grant-travel", post(set_travel))
}

#[derive(Debug, Serialize)]
struct PeerScales {
    /// The scale a peer without its own row gets.
    default: f32,
    peers: Vec<PeerScale>,
}

#[derive(Debug, Serialize)]
struct PeerScale {
    peer: String,
    scale: f32,
    set: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SetPeerScale {
    /// The peer principal, as 32 hex.
    peer: String,
    /// Above 0, at most 1; none returns the peer to the default.
    #[serde(default)]
    scale: Option<f32>,
}

/// `GET /v1/owner/federation/peer-confidence`: every owner-set scale.
async fn list(auth: CoreAuth, State(server): State<Arc<SyncServer>>) -> OwnerReply<PeerScales> {
    owner(&auth, &server)?;
    let scales = blocking(move || -> OwnerResult<PeerScales> {
        let peers = server
            .vault()
            .federation_peer_confidences()?
            .into_iter()
            .map(|(peer, row)| PeerScale {
                peer: peer.to_hex(),
                scale: row.scale,
                set: Some(rfc3339_secs(row.set_at)),
            })
            .collect();
        Ok(PeerScales {
            default: oneiron::sync::DEFAULT_FEDERATED_CONFIDENCE_SCALE,
            peers,
        })
    })
    .await?;
    Ok(Json(scales))
}

/// `POST /v1/owner/federation/peer-confidence`: sets or clears one peer's
/// scale. Claims already admitted keep their confidence.
async fn set(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<SetPeerScale>, JsonRejection>,
) -> OwnerReply<PeerScale> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let scale = blocking(move || -> OwnerResult<PeerScale> {
        let peer = entity_id("peer", &request.peer)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs());
        let scale = server
            .vault()
            .set_federation_peer_confidence_as(&owner, &peer, request.scale, now)
            .map_err(|error| crate::owner::OwnerError::Invalid(error.to_string()))?;
        Ok(PeerScale {
            peer: peer.to_hex(),
            scale,
            set: request.scale.map(|_| rfc3339_secs(now)),
        })
    })
    .await?;
    Ok(Json(scale))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SetGrantTravel {
    /// The federation grant, as 32 hex.
    grant: String,
    /// The born-with text its windows carry; none sends none.
    #[serde(default)]
    travel: Option<TravelChoice>,
}

#[derive(Debug, Serialize)]
struct GrantTravel {
    grant: String,
    travel: Option<TravelChoice>,
    set: Option<String>,
}

/// `POST /v1/owner/federation/grant-travel`: binds or clears one live
/// grant's travel choice. Text a guest already holds stays its copy.
async fn set_travel(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<SetGrantTravel>, JsonRejection>,
) -> OwnerReply<GrantTravel> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let travel = blocking(move || -> OwnerResult<GrantTravel> {
        let grant = entity_id("grant", &request.grant)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs());
        server
            .vault()
            .set_federation_grant_travel_as(&owner, &grant, request.travel.clone(), now)
            .map_err(|error| crate::owner::OwnerError::Invalid(error.to_string()))?;
        Ok(GrantTravel {
            grant: grant.to_hex(),
            set: request.travel.as_ref().map(|_| rfc3339_secs(now)),
            travel: request.travel,
        })
    })
    .await?;
    Ok(Json(travel))
}
