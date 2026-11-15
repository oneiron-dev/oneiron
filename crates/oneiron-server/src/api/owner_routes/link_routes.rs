//! `/v1/owner/link`: the owner links a hosted peer of this vault, reads it,
//! and unlinks it (L10-16; canon cross-arch-0024 M4.25), through
//! `crate::linked_peer`, with the vault's cloud registration's peer calls
//! (`crate::cloud_registration`). Each route takes a fresh owner proof
//! first. `oneiron link`, `oneiron link status` and `oneiron unlink` are
//! their clients.
//!
//! `POST /link` (`{"origin": url}`, where the peer redeems its link: an
//! `https://` origin, or `http://` on this machine) answers the linked-peer
//! row, or 409 `already_linked`, `cloud_registration_required`,
//! `mesh_listener_required`, `host_issuer_required` or
//! `control_plane_failed`; `GET /link` answers where the peer stands;
//! `DELETE /link` answers the unlink's receipt, or 409 `not_linked`.

use std::sync::Arc;

use axum::extract::State;
use axum::http::{Extensions, HeaderMap};
use axum::response::Json;
use axum::routing::{delete, get, post};
use serde::Deserialize;

use super::machine_routes::act_surface_admitted;
use super::{OwnerReply, OwnerRoute, OwnerTable, blocking, owner};
use crate::api::body_spool::OwnerJsonBody;
use crate::auth::CoreAuth;
use crate::cloud_registration::{CloudPeers, PeerControl};
use crate::error::{ApiError, ApiErrorDetails};
use crate::linked_peer::{LinkRefusal, LinkStatus, LinkedPeerView, UnlinkReceipt};
use crate::owner::OwnerResult;
use crate::server::SyncServer;

pub(super) fn owner_table() -> OwnerTable {
    vec![
        (
            OwnerRoute {
                method: "post",
                path: "/link",
                summary: "Link a hosted peer of this vault (`oneiron link`): the cloud's always-on machine, a hosted node, never mine. The control plane of the vault's live cloud registration is handed the owner's one-use hosted-node link, which its peer redeems at `origin` (https://, or http:// on this machine); this serve's mesh listener must run. Answers the linked-peer row.",
                row: None,
                shape: None,
            },
            post(link),
        ),
        (
            OwnerRoute {
                method: "get",
                path: "/link",
                summary: "Where the vault's hosted peer stands (`oneiron link status`): not linked; linked, with its machine as the roster holds it and what the control plane says of it; or unlinked here with its removal still owed to the control plane, or its machine's removal to this roster.",
                row: None,
                shape: None,
            },
            get(status),
        ),
        (
            OwnerRoute {
                method: "delete",
                path: "/link",
                summary: "Unlink the vault's hosted peer (`oneiron unlink`): its machine is removed, its mesh grants and every slip its holder holds are revoked at once, then the control plane is asked to remove the peer, erasing its live copy and its keys; backups age out on the disaster-recovery schedule of 90 days or less. The local vault is not touched. A removal the control plane did not take, or a machine removal this install could not sign, is asked again by the next unlink.",
                row: None,
                shape: None,
            },
            delete(unlink),
        ),
    ]
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LinkPeer {
    /// Where the peer redeems its link: this server's origin as the peer
    /// reaches it.
    origin: String,
}

/// The registration's peer calls as the link act takes them.
fn control_of(peers: &Result<CloudPeers, String>) -> Result<&dyn PeerControl, String> {
    match peers {
        Ok(peers) => Ok(peers as &dyn PeerControl),
        Err(reason) => Err(reason.clone()),
    }
}

/// A 409 naming `state`, with `message` and one suggestion.
fn conflict(state: &str, message: String, suggestion: &str) -> ApiError {
    ApiError::new(
        message,
        ApiErrorDetails::InvalidState {
            state: Some(state.to_owned()),
        },
        [suggestion],
    )
}

fn link_refusal(refusal: LinkRefusal) -> ApiError {
    match refusal {
        LinkRefusal::AlreadyLinked => conflict(
            "already_linked",
            "this vault already has a hosted peer, or an unlink still owed".to_owned(),
            "Run `oneiron unlink` first.",
        ),
        LinkRefusal::CloudRegistrationRequired(reason) => conflict(
            "cloud_registration_required",
            reason,
            "Link this vault to your Oneiron cloud account first: `oneiron account login`.",
        ),
        LinkRefusal::MeshListenerRequired => conflict(
            "mesh_listener_required",
            "this serve runs no mesh listener, and a hosted peer dials this machine over the mesh"
                .to_owned(),
            "Start `oneiron serve` with ONEIRON_MESH_BIND set.",
        ),
        LinkRefusal::OriginNotRedeemable => ApiError::bad_request(
            "origin must be an https:// origin, or http:// on this machine, with no query or fragment",
            Some("origin"),
        ),
        LinkRefusal::NoHostIssuer => conflict(
            "host_issuer_required",
            "this host holds no slip issuer, so it signs no link".to_owned(),
            "Serve the vault from its own host.",
        ),
        LinkRefusal::ControlPlane(reason) => conflict(
            "control_plane_failed",
            reason,
            "Nothing was kept here; run `oneiron link` again.",
        ),
    }
}

async fn link(
    auth: CoreAuth,
    headers: HeaderMap,
    extensions: Extensions,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<LinkPeer>,
) -> OwnerReply<LinkedPeerView> {
    let owner = owner(&auth, &server)?;
    let surface = act_surface_admitted(&server, &auth, &headers, &extensions);
    let body = payload.read(&server).await?;
    let linked = blocking(
        move || -> OwnerResult<Result<LinkedPeerView, LinkRefusal>> {
            let peers = server
                .cloud_registration
                .peers(server.vault(), &owner, true)?;
            let mesh_listener =
                crate::device_sync::enrolment::home_bind::home_mesh_address(&server).is_some();
            Ok(crate::linked_peer::link(
                &server,
                &owner,
                surface,
                &body.origin,
                control_of(&peers),
                mesh_listener,
            )?)
        },
    )
    .await?;
    Ok(Json(linked.map_err(link_refusal)?))
}

async fn status(auth: CoreAuth, State(server): State<Arc<SyncServer>>) -> OwnerReply<LinkStatus> {
    let owner = owner(&auth, &server)?;
    let status = blocking(move || -> OwnerResult<LinkStatus> {
        let peers = server
            .cloud_registration
            .peers(server.vault(), &owner, false)?;
        Ok(crate::linked_peer::status(
            &server,
            &owner,
            control_of(&peers),
        )?)
    })
    .await?;
    Ok(Json(status))
}

async fn unlink(
    auth: CoreAuth,
    headers: HeaderMap,
    extensions: Extensions,
    State(server): State<Arc<SyncServer>>,
) -> OwnerReply<UnlinkReceipt> {
    let owner = owner(&auth, &server)?;
    let surface = act_surface_admitted(&server, &auth, &headers, &extensions);
    let receipt = blocking(move || -> OwnerResult<Option<UnlinkReceipt>> {
        let peers = server
            .cloud_registration
            .peers(server.vault(), &owner, true)?;
        Ok(crate::linked_peer::unlink(
            &server,
            &owner,
            surface,
            control_of(&peers),
        )?)
    })
    .await?;
    receipt.map(Json).ok_or_else(|| {
        conflict(
            "not_linked",
            "this vault has no hosted peer".to_owned(),
            "`oneiron link` adds one.",
        )
        .into()
    })
}
