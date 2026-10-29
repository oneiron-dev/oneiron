//! `/v1/owner/federation/peer-confidence`: how far this vault believes each
//! federation peer (OF-149). Admission scales every claim a peer sends by
//! its scale; a peer without one gets the default.
//! `/v1/owner/federation/grant-travel`: the born-with text one federation
//! grant's windows carry to another vault (OF-491); a grant without one
//! sends none. GET reads one grant's effective choice, POST sets or clears
//! it for every machine of the owner's that serves the grant (FIX 2998).

use std::sync::Arc;

use axum::Router;
use axum::extract::rejection::QueryRejection;
use axum::extract::{Query, State};
use axum::http::{Extensions, HeaderMap};
use axum::response::Json;
use axum::routing::get;
use oneiron::share_travel::TravelChoice;
use serde::{Deserialize, Serialize};

use super::machine_routes::{act_surface_admitted, parse_revision, revision_hex};
use super::{OwnerReply, blocking, owner};
use crate::api::body_spool::OwnerJsonBody;
use crate::api::query_params;
use crate::auth::CoreAuth;
use crate::owner::stamp::rfc3339_secs;
use crate::owner::{OwnerError, OwnerResult, entity_id};
use crate::server::SyncServer;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/federation/peer-confidence", get(list).post(set))
        .route("/federation/grant-travel", get(get_travel).post(set_travel))
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
    payload: OwnerJsonBody<SetPeerScale>,
) -> OwnerReply<PeerScale> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
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
    /// The grant's revision the surface showed the owner, as 64 hex (the
    /// read's `revision`); none takes the current one (mesh PR1b).
    #[serde(default)]
    seen: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantTravelQuery {
    /// The federation grant, as 32 hex.
    grant: String,
}

#[derive(Debug, Serialize)]
struct GrantTravel {
    grant: String,
    travel: Option<TravelChoice>,
    set: Option<String>,
    /// The grant's revision, to present back as `seen`, as 64 hex.
    revision: String,
}

/// `GET /v1/owner/federation/grant-travel?grant=<id>`: the travel choice
/// bound to one federation grant, with when the owner set it. A grant with
/// none bound answers `travel` and `set` null: its windows send no text.
/// An id that names no federation grant is not found.
async fn get_travel(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<GrantTravelQuery>, QueryRejection>,
) -> OwnerReply<GrantTravel> {
    owner(&auth, &server)?;
    let query = query_params(query)?;
    let travel = blocking(move || -> OwnerResult<GrantTravel> {
        let grant = entity_id("grant", &query.grant)?;
        if server.vault().get_entity_type(&grant)?
            != Some(oneiron::registry::ENTITY_TYPE_FEDERATION_GRANT)
        {
            return Err(OwnerError::NotFound("grant", query.grant));
        }
        let bound = server.vault().federation_grant_travel(&grant)?;
        let revision = revision_hex(&server.vault().grant_travel_revision(&grant)?);
        Ok(GrantTravel {
            grant: grant.to_hex(),
            set: bound.as_ref().map(|bound| rfc3339_secs(bound.set_at)),
            travel: bound.map(|bound| bound.travel),
            revision,
        })
    })
    .await?;
    Ok(Json(travel))
}

/// `POST /v1/owner/federation/grant-travel`: sets or clears one live
/// grant's travel choice, and answers the effective choice after: a choice
/// another of the owner's machines made concurrently meets it. Text a guest
/// already holds stays its copy. The engine's refusal keeps its type: a
/// host's operator root stays `HostActionRequiresSupportGrant` (FIX 2222).
async fn set_travel(
    auth: CoreAuth,
    headers: HeaderMap,
    extensions: Extensions,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<SetGrantTravel>,
) -> OwnerReply<GrantTravel> {
    let owner = owner(&auth, &server)?;
    let surface = act_surface_admitted(&server, &auth, &headers, &extensions);
    let request = payload.read(&server).await?;
    let travel = blocking(move || -> OwnerResult<GrantTravel> {
        let grant = entity_id("grant", &request.grant)?;
        // The revision the surface presented, passed through: a stale one is
        // a conflict, never manufactured from current state here.
        let seen = request
            .seen
            .as_deref()
            .map(|seen| parse_revision("seen", seen))
            .transpose()?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs());
        let effective = server.vault().set_federation_grant_travel_as(
            &owner,
            surface,
            &grant,
            request.travel,
            seen,
            now,
        )?;
        let revision = revision_hex(&server.vault().grant_travel_revision(&grant)?);
        Ok(GrantTravel {
            grant: grant.to_hex(),
            set: effective.as_ref().map(|bound| rfc3339_secs(bound.set_at)),
            travel: effective.map(|bound| bound.travel),
            revision,
        })
    })
    .await?;
    Ok(Json(travel))
}
