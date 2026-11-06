//! FIX 4748: this machine serving another machine of its vault while their
//! home is down (owner RULING B, 2026-10-19; ARCH-0023b `#peer-fetch`: "Only
//! machines marked mine serve. The serving machine runs the same read checks
//! home runs. It serves state-only copies, never history, and both ends write
//! a receipt. It fails closed while the authority fold is unsettled.").
//!
//! A machine serves as a peer when it is a device of another home and not the
//! elected MACRO home ([`serves_as_peer`]). A sync upgrade from another
//! machine of this vault, the machine its slip proof or its mesh handshake
//! proved, is then admitted ([`admit`]) only from a machine marked mine
//! (`auth::owned_machine_stands`, its trusted identity on the key it proved),
//! and only while this machine's authority fold is settled
//! (`oneiron::sync::peer_route::authority_fold_settled`); each refusal is
//! typed, 403 and 409, and receipted.
//!
//! The socket it opens runs every read check a home's socket runs,
//! unchanged and vault-local: the slip and machine proofs, the selector and
//! residence admission, and the world read settings judged for the machine
//! it proved at every send. It serves state only: window updates and
//! replacement snapshots, the root, documents. It never serves the residence
//! lane (owed machine history, authority log ranges and checkpoints, sealed
//! bundles, home handoffs), the lease registrar, the sealed update relay or
//! the leaf-key relay, which are the home's (`ConnState::peer_served`).
//! Both ends leave a receipt naming the other machine and the session.

use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use oneiron::authority::PeerMachine;
use oneiron::sync::peer_route::{PeerSyncPart, PeerSyncReceipt};

use crate::error::{ApiError, ApiErrorDetails};
use crate::server::SyncServer;

/// One socket this machine serves as a peer, and its receipt.
pub(super) struct PeerServe {
    receipt: PeerSyncReceipt,
}

impl PeerServe {
    /// The socket closed: its receipt takes its end.
    pub(super) fn close(self, vault: &oneiron::Vault) {
        self.receipt.close(vault);
    }
}

/// FIX 4748 engine call (CALLS "FIX 4748 serves as peer"): whether this
/// machine serves the vault's other machines as a peer rather than as their
/// home. It does when it dials a home of its own (`[device_sync]` or its
/// enrolment) and is not the elected MACRO home. A home designation that
/// does not read counts as not the home: the narrower service.
pub(super) fn serves_as_peer(server: &SyncServer) -> bool {
    server.ai.device()
        && !oneiron::sync::residence::local_is_elected_home(server.vault()).unwrap_or(false)
}

/// Admits a sync upgrade this machine may serve as a peer. `Ok(None)` when it
/// serves as the home, or the upgrade proved no other machine of this vault:
/// the socket runs as today. `Ok(Some)` for an admitted peer, its receipt
/// left. The typed refusal, receipted, for a peer not marked mine (403) or
/// while this machine's authority fold is unsettled (409).
pub(super) fn admit(
    server: &SyncServer,
    headers: &HeaderMap,
    extensions: &axum::http::Extensions,
    machine: PeerMachine,
) -> Result<Option<PeerServe>, Response> {
    if !serves_as_peer(server) {
        return Ok(None);
    }
    let proved = match machine {
        PeerMachine::Proven { machine, .. } => Some(machine),
        PeerMachine::Unknown => extensions
            .get::<super::mesh::MeshProvedMachine>()
            .map(|proved| proved.0),
    };
    let Some(peer) = proved else {
        return Ok(None);
    };
    let vault = server.vault();
    let local = vault.local_machine().ok().flatten().map(|local| local.id);
    if local == Some(peer) {
        return Ok(None);
    }
    // The session both ends name: the upgrade proof's nonce.
    let session = crate::auth::BindingProof::from_headers(headers)
        .map_or_else(|_| "unbound".to_owned(), |proof| proof.nonce);
    if !crate::auth::owned_machine_stands(vault, machine) {
        let _ = PeerSyncReceipt::leave(
            vault,
            PeerSyncPart::Served,
            peer,
            &session,
            Some("not proved as a machine marked mine"),
        );
        tracing::warn!(
            peer = %peer.to_hex(),
            "peer sync refused: the machine is not proved as one marked mine"
        );
        return Err(ApiError::new(
            "peer sync refused: only a machine marked mine is served while the home is down",
            ApiErrorDetails::Forbidden {
                required_scope: Some("mine_machine".to_owned()),
            },
            ["Mark the machine as yours on the owner's surface, then dial it again."],
        )
        .into_response());
    }
    if !oneiron::sync::peer_route::authority_fold_settled(vault).unwrap_or(false) {
        let _ = PeerSyncReceipt::leave(
            vault,
            PeerSyncPart::Served,
            peer,
            &session,
            Some("this machine's authority fold is unsettled"),
        );
        tracing::warn!(
            peer = %peer.to_hex(),
            "peer sync refused: this machine's authority fold is unsettled"
        );
        return Err(ApiError::new(
            "peer sync refused: this machine's authority fold is unsettled",
            ApiErrorDetails::InvalidState {
                state: Some("authority_unsettled".to_owned()),
            },
            ["Dial another machine marked mine, or this one once its authority history is in."],
        )
        .into_response());
    }
    tracing::info!(peer = %peer.to_hex(), "peer sync served");
    Ok(Some(PeerServe {
        receipt: PeerSyncReceipt::leave(vault, PeerSyncPart::Served, peer, &session, None),
    }))
}
