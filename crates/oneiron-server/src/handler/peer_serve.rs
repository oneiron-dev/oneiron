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
//! unchanged and vault-local: the slip and machine proofs, the actor bind
//! (`auth.bind`) its promotion and document admissions judge, the selector
//! and residence admission, and the world read settings judged for the
//! machine it proved at every send. It serves state, never operations: every
//! window export is the window's state-only copy, whatever vector the asker
//! sends, and a live change goes as a notice its asker answers by asking
//! again ([`PeerExports`], cut at the export door and checked again at the
//! socket's release); the root and documents go as today. It never serves
//! the residence lane (owed machine history, authority log ranges and
//! checkpoints, sealed bundles, home handoffs), the lease registrar, the
//! sealed update relay, the leaf-key relay, selector fetches or the NOTE
//! authority
//! ([`refuse_note_authority`]), which are the home's
//! (`ConnState::peer_served`). Both ends leave a receipt naming the other
//! machine and the session.

use std::collections::{HashMap, HashSet};

use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use oneiron::authority::PeerMachine;
use oneiron::sync::WindowKey;
use oneiron::sync::peer_route::{PeerSyncPart, PeerSyncReceipt};

use super::conn_state::ConnState;
use crate::error::{ApiError, ApiErrorDetails};
use crate::protocol::ProtocolError;
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

/// The NOTE authority is the home. A socket served as a peer binds its actor
/// like any other, so its promotion and document admissions judge that
/// principal, but it takes no NOTE authority action from the bind: no NOTE
/// operation is admitted on it and no artifact publication applied.
///
/// # Errors
/// The refusal, on a socket served as a peer; the socket closes on it.
pub(super) fn refuse_note_authority(state: &ConnState) -> Result<(), ProtocolError> {
    if state.peer_served {
        return Err(ProtocolError::InvalidPayload(
            "the NOTE authority is the home: a peer admits no NOTE operation or publication",
        ));
    }
    Ok(())
}

/// What a socket served as a peer is sent of its windows (FIX 4748): state,
/// never operations. Every window frame that leaves it is a state-only copy
/// the export door cut for it ([`super::window_sync`],
/// `oneiron::sync::window::export_window_state_for`), whatever vector its
/// asker sent; no update since a vector and no live update goes. The export
/// door records each copy here, and the socket's release door
/// ([`super::window_pads::release`]) sends no other window bytes. A live
/// change reaches the asker as a `WINDOW_INVALIDATE` notice instead
/// (`connection::window_delivery`), once until it asks again; its ask is
/// answered with a fresh copy.
#[derive(Debug, Default)]
pub(super) struct PeerExports {
    /// For each window, the digests of the state-only copies cut for it that
    /// have not left yet: those bytes alone go of the window, each once.
    cuts: HashMap<WindowKey, Vec<[u8; 32]>>,
    /// Windows whose change the asker was told of and has not asked for
    /// since: no further notice goes for them until it asks.
    noticed: HashSet<WindowKey>,
}

impl PeerExports {
    /// The asker asked for `key` with its vector: the next change of the
    /// window is noticed to it again.
    fn asked(&mut self, key: &WindowKey) {
        self.noticed.remove(key);
    }

    /// The export door cut `bytes`, the state-only copy of `key`: those bytes
    /// may leave once.
    fn cut(&mut self, key: &WindowKey, bytes: &[u8]) {
        self.noticed.remove(key);
        self.cuts
            .entry(key.clone())
            .or_default()
            .push(*blake3::hash(bytes).as_bytes());
    }

    /// Whether a window frame of `key` carrying `payload` may leave: only a
    /// state-only copy cut for it and not sent yet.
    fn releases(&mut self, key: &WindowKey, payload: &[u8]) -> bool {
        let digest = *blake3::hash(payload).as_bytes();
        let Some(cuts) = self.cuts.get_mut(key) else {
            return false;
        };
        let Some(at) = cuts.iter().position(|cut| *cut == digest) else {
            return false;
        };
        cuts.swap_remove(at);
        if cuts.is_empty() {
            self.cuts.remove(key);
        }
        true
    }

    /// Whether a change of `key` is noticed to the asker now: it was not told
    /// of one since it last asked.
    fn notices(&mut self, key: &WindowKey) -> bool {
        self.noticed.insert(key.clone())
    }
}

/// This socket's [`PeerExports`], as a panic holding them left them.
fn peer_exports(state: &ConnState) -> std::sync::MutexGuard<'_, PeerExports> {
    state
        .peer_exports
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// On a socket served as a peer, its asker asked for `key` with its vector.
/// A home's socket records nothing.
pub(super) fn asked(state: &ConnState, key: &WindowKey) {
    if state.peer_served {
        peer_exports(state).asked(key);
    }
}

/// On a socket served as a peer, the export door cut `bytes`, the state-only
/// copy of `key`, for it. A home's socket records nothing.
pub(super) fn cut(state: &ConnState, key: &WindowKey, bytes: &[u8]) {
    if state.peer_served {
        peer_exports(state).cut(key, bytes);
    }
}

/// Whether a window `UPDATE` or `REPLACEMENT` frame of `key` carrying
/// `payload` may leave this socket: always on a home's socket, and on one
/// served as a peer only when it is a state-only copy [`cut`] for it, never
/// an operation.
pub(super) fn releases_window_frame(state: &ConnState, key: &WindowKey, payload: &[u8]) -> bool {
    !state.peer_served || peer_exports(state).releases(key, payload)
}

/// Whether a change of `key` is noticed to this socket now: always on a home's
/// socket, and on one served as a peer once until its asker asks for the
/// window again.
pub(super) fn notices_change(state: &ConnState, key: &WindowKey) -> bool {
    !state.peer_served || peer_exports(state).notices(key)
}
