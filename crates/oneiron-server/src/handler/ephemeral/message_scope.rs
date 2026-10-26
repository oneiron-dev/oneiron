//! Where a message's live partials go (FIX 9537). A partial the host's
//! stream relay put in the presence hub carries its conversation, from the
//! stream's own seed; it is released, live or to a socket that just joined,
//! only to a socket whose destination may read that conversation now, by
//! the vault's current world policy for the machine the socket proved, as a
//! row's release is judged. A conversation moved to another world since, or
//! a machine removed since, is judged as it stands. Presence a client wrote
//! goes as it always went, and a socket on this device takes every partial.
//! No MESSAGE row is needed: the conversation is the stream's.

use oneiron::authority::PeerMachine;
use oneiron::claim::CallerLocality;
use oneiron::settings::ReadDestination;
use oneiron::sync::{TAG_EPHEMERAL, decode_ephemeral_states};
use oneiron::{EntityId, Vault};

use super::super::conn_state::ConnState;
use crate::server::SyncServer;

/// Whether `conversation`'s partials may go to `destination` now: its
/// worlds, read again, may all be read there.
fn may_release(vault: &Vault, conversation: EntityId, destination: &ReadDestination) -> bool {
    matches!(
        vault.release_hold_for(&[conversation], destination),
        Ok(None)
    )
}

/// Whether the hub's presence key `key` may go to `destination`.
pub(super) fn releases_key(server: &SyncServer, key: &str, destination: &ReadDestination) -> bool {
    server
        .message_scopes
        .conversation(key)
        .is_none_or(|conversation| may_release(server.vault(), conversation, destination))
}

/// Where a socket joining at `locality`, on the machine it proved at its
/// upgrade, sends what it reads: that machine as the vault holds it now.
pub(super) fn joining(
    server: &SyncServer,
    locality: CallerLocality,
    machine: PeerMachine,
) -> ReadDestination {
    ReadDestination::at(locality, server.vault().peer_machine_stands(machine))
}

/// Whether `frame` may leave on the socket `conn_state` is: an ephemeral
/// frame only when each key a message stream wrote in it may go there. A
/// frame that does not decode is held.
pub(in crate::handler) fn releases_frame(
    server: &SyncServer,
    conn_state: &ConnState,
    frame: &[u8],
) -> bool {
    if frame.first() != Some(&TAG_EPHEMERAL) || server.message_scopes.is_empty() {
        return true;
    }
    let Ok(states) = decode_ephemeral_states(&frame[1..]) else {
        return false;
    };
    let vault = server.vault();
    let mut destination = None;
    states.iter().all(|state| {
        let Some(conversation) = server.message_scopes.conversation(&state.key) else {
            return true;
        };
        let destination = destination.get_or_insert_with(|| {
            ReadDestination::at(conn_state.locality, conn_state.peer_machine(vault))
        });
        may_release(vault, conversation, destination)
    })
}
