//! MEMBER-SYNC D1, D4: a shared-vault member's selector-only sync lane.
//!
//! H8-SHARED-ENV-LANE = B: "a slip whose grant_ref names its holder's live
//! member grant gets a selector-only socket, with no root snapshot and no
//! legacy full lane". The lane asks for itself with [`MEMBER_LANE_HEADER`], a
//! restriction request that is never authority: without it every upgrade
//! takes the path it took before. With it the upgrade is a member lane or a
//! 403, never the owner's socket nor the facade socket.
//!
//! On the lane every inbound frame passes [`member_admits`], a positive
//! allow-list of the selector-qualified frames an Opened device sends, and
//! every residence RPC method passes [`member_admits_rpc_method`]. Each
//! selector it sends is pinned to the lane's own grant and holder
//! ([`super::selector_scope::SelectorLane::scope_for`]) and judged under the
//! scope the home derived, so a member reads and writes exactly what its
//! grant allows (MEMBER-SYNC-WRITES = A).

use std::sync::Arc;

use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::auth::CoreAuth;
use crate::protocol::{ProtocolError, SyncMessage, window_sub_tags};
use crate::server::SyncServer;

/// The request header a member lane's upgrade carries, valued
/// [`MEMBER_LANE_HEADER_VALUE`]: it asks for the selector-only lane and grants
/// nothing.
pub(crate) const MEMBER_LANE_HEADER: &str = "oneiron-sync-lane";
/// The one value of [`MEMBER_LANE_HEADER`].
pub(crate) const MEMBER_LANE_HEADER_VALUE: &str = "member";

/// A member lane, fixed for its socket's life: the standing its home proved
/// at the upgrade and the credential that proved it.
pub(crate) struct MemberLane {
    standing: oneiron::federation::MemberLaneStanding,
    credential: CoreAuth,
}

impl std::fmt::Debug for MemberLane {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemberLane")
            .field("standing", &self.standing)
            .finish_non_exhaustive()
    }
}

impl MemberLane {
    /// The grant, holder, scope and role the home proved at the upgrade.
    pub(crate) fn standing(&self) -> &oneiron::federation::MemberLaneStanding {
        &self.standing
    }

    /// The credential the upgrade carried; the only one `auth.bind` binds on
    /// this lane ([`Self::binds`]).
    pub(crate) fn credential(&self) -> &CoreAuth {
        &self.credential
    }

    /// Whether the lane still stands (D5): its credential is live and the
    /// home still answers the same standing for its grant and holder. A
    /// fault reads as fallen. Asked before each read and flush, so a revoked
    /// or deleted grant stops the lane (ARCH-0043:164).
    pub(crate) fn stands(&self, vault: &oneiron::Vault) -> bool {
        self.credential.credential_is_live(vault)
            && matches!(
                vault.member_lane_standing(self.standing.holder, self.standing.grant),
                Ok(Some(now)) if now == self.standing
            )
    }

    /// Whether `auth`, an in-band bind's credential, is this lane's own
    /// upgrade credential: the same token id, holder and grant. Another live
    /// slip of the same person never binds here (D4).
    pub(crate) fn binds(&self, auth: &CoreAuth) -> bool {
        auth.jti().is_some()
            && auth.jti() == self.credential.jti()
            && auth.principal_ref() == self.credential.principal_ref()
            && slip_grant_ref(auth) == slip_grant_ref(&self.credential)
    }
}

/// Whether the upgrade asks for a member lane.
pub(super) fn member_lane_requested(headers: &HeaderMap) -> bool {
    headers
        .get(MEMBER_LANE_HEADER)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case(MEMBER_LANE_HEADER_VALUE))
}

/// The member lane an upgrade that asked for one opens, or its 403 (D1).
/// Every step reads this home: the slip verified holder-bound by the binding
/// proof, a human slip held by a registered PERSON, its `grant_ref` naming a
/// live first-party member grant of that PERSON under this shared vault's own
/// scope ([`oneiron::Vault::member_lane_standing`]), and the credential live.
/// A managed vault's sockets take each call under its reap freeze (FIX
/// 5128), which this lane does not, so it is refused there. A host fault the
/// check met stays a 500, which the client redials.
pub(super) fn member_lane(
    headers: &HeaderMap,
    server: &SyncServer,
) -> Result<Arc<MemberLane>, Response> {
    let refused = || StatusCode::FORBIDDEN.into_response();
    if server.managed_issuer.is_some() {
        return Err(refused());
    }
    let credential = CoreAuth::from_headers(headers, &server.config, server.vault().as_ref())
        .map_err(IntoResponse::into_response)?;
    let Some(slip) = credential.verified_slip() else {
        return Err(refused());
    };
    if slip.claims().actor_class.as_deref() != Some("human") || slip.claims().single_use {
        return Err(refused());
    }
    let holder = credential
        .require_registered_principal()
        .ok()
        .and_then(|principal| oneiron::EntityId::from_hex(principal).ok())
        .ok_or_else(refused)?;
    let grant = slip_grant_ref(&credential).ok_or_else(refused)?;
    let standing = server
        .vault()
        .member_lane_standing(holder, grant)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())?
        .ok_or_else(refused)?;
    if !credential.credential_is_live(server.vault().as_ref()) {
        return Err(refused());
    }
    Ok(Arc::new(MemberLane {
        standing,
        credential,
    }))
}

/// The grant a credential's verified slip names, when it names one.
fn slip_grant_ref(auth: &CoreAuth) -> Option<oneiron::EntityId> {
    auth.verified_slip()?
        .claims()
        .grant_ref
        .as_deref()
        .and_then(|grant| oneiron::EntityId::from_hex(grant).ok())
}

/// Whether a member lane may speak `version`: the selector protocol or a
/// residence one, never a full-window or legacy protocol (D4).
pub(crate) fn member_hello_admits(version: u8) -> bool {
    version == oneiron::sync::transport::PROTOCOL_VERSION
        || oneiron::sync::transport::is_residence_version(version)
}

/// Whether a member lane may send `message` (D4): a positive allow-list of the
/// selector-qualified frames an Opened device sends. Root update and vector,
/// presence, lease, LFS chunk, leaf-key, sealed-update and subscription
/// frames are refused; a batch is judged member by member. A window frame
/// that would exchange a full window is admitted only on a window this
/// socket promoted under its own pinned selector (`promoted`). Each admitted
/// frame still meets its own gate.
pub(crate) fn member_admits(
    message: &SyncMessage,
    promoted: &dyn Fn(&str) -> bool,
) -> Result<(), ProtocolError> {
    let refused = || Err(ProtocolError::InvalidPayload("not served on a member lane"));
    match message {
        SyncMessage::Doc { .. } | SyncMessage::AssetBody { .. } | SyncMessage::Rpc(_) => Ok(()),
        SyncMessage::Batch(members) => members
            .iter()
            .try_for_each(|member| member_admits(member, promoted)),
        SyncMessage::WindowSync {
            window_key,
            sub_tag,
            ..
        } => match *sub_tag {
            window_sub_tags::SELECTOR_VV_REQUEST
            | window_sub_tags::SELECTOR_RETRY
            | window_sub_tags::PROMOTION_REQUEST
            | window_sub_tags::FOLLOW_REQUEST
            | window_sub_tags::WINDOW_PAD_PART
            | window_sub_tags::WINDOW_PAD_RECEIPT => Ok(()),
            window_sub_tags::UPDATE
            | window_sub_tags::VV_REQUEST
            | window_sub_tags::VV_RESPONSE
            | window_sub_tags::REPLACEMENT_REQUEST
            | window_sub_tags::RESIDENCE_UPDATE
                if promoted(window_key) =>
            {
                Ok(())
            }
            _ => refused(),
        },
        SyncMessage::LfsChunks(_)
        | SyncMessage::LeafKey { .. }
        | SyncMessage::SealedUpdate(_)
        | SyncMessage::Sub(_)
        | SyncMessage::RootUpdate(_)
        | SyncMessage::Ephemeral(_)
        | SyncMessage::RootVersionVector(_)
        | SyncMessage::LeaseRequest { .. } => refused(),
    }
}

/// Whether a member lane on `version` is handed `data` from the shared
/// fan-out (D5), a positive allow-list: a document or node batch, which the
/// loop re-exports under the lane's stored selectors only, and on a
/// residence protocol a window frame, which the loop turns into an
/// invalidation of a window this socket promoted, or drops. Root updates,
/// presence, lease, leaf-key, sealed-update and routed app frames never
/// reach it.
pub(crate) fn member_receives_broadcast(version: u8, data: &[u8]) -> bool {
    match data.first().copied() {
        Some(oneiron::sync::transport::TAG_DOCUMENT | oneiron::sync::transport::TAG_BATCH) => true,
        Some(crate::protocol::TAG_WINDOW_SYNC) => {
            oneiron::sync::transport::is_residence_version(version)
        }
        _ => false,
    }
}

/// The RPC methods a member lane may call (D4, D6): the in-band bind (of its
/// own credential only, [`MemberLane::binds`]), `ping`, and the residence
/// reads and promotion an Opened device uses, each behind its pinned
/// selector. Every other method (bundle, pad, authority, checkpoint,
/// machine history, home handoff, custody, facade verbs) is refused.
pub(crate) fn member_admits_rpc_method(method: &str) -> bool {
    matches!(
        method,
        "auth.bind"
            | "ping"
            | "residence.index"
            | "residence.touch"
            | "residence.touch.part"
            | "residence.promote"
            | "residence.window.vv"
            | "residence.search"
            | "residence.media_vectors"
            | "residence.windows"
    )
}
