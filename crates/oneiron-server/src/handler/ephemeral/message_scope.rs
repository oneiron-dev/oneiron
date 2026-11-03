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
use oneiron::EntityId;

use super::super::conn_state::ConnState;
use crate::server::SyncServer;

/// Whether `conversation`'s partials may go to `destination` now: its
/// worlds may all be read there, judged under the vault's current write
/// generation and kept for it (FIX 11166), so a partial to every socket
/// is judged once per generation instead of once per socket.
fn may_release(server: &SyncServer, conversation: EntityId, destination: &ReadDestination) -> bool {
    if !destination.is_off_device() {
        return true;
    }
    let vault = server.vault();
    let peers = destination.peers();
    let generation = vault.write_generation();
    if let Some(may) = server
        .message_scopes
        .verdict(generation, conversation, &peers)
    {
        return may;
    }
    let may = matches!(
        vault.release_hold_for(&[conversation], destination),
        Ok(None)
    );
    server
        .message_scopes
        .record_verdict(generation, conversation, &peers, may);
    may
}

/// Whether the hub's presence key `key` may go to `destination`.
pub(super) fn releases_key(server: &SyncServer, key: &str, destination: &ReadDestination) -> bool {
    server
        .message_scopes
        .conversation(key)
        .is_none_or(|conversation| may_release(server, conversation, destination))
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
    // The conversations this frame's streams wrote, each once: one
    // snapshot judges the frame's unkept ones together (FIX 11166).
    let mut conversations: Vec<EntityId> = Vec::new();
    for state in &states {
        if let Some(conversation) = server.message_scopes.conversation(&state.key)
            && !conversations.contains(&conversation)
        {
            conversations.push(conversation);
        }
    }
    if conversations.is_empty() {
        return true;
    }
    let destination = ReadDestination::at(conn_state.locality, conn_state.peer_machine(vault));
    if !destination.is_off_device() {
        return true;
    }
    let peers = destination.peers();
    let generation = vault.write_generation();
    let mut unkept: Vec<EntityId> = Vec::new();
    for conversation in &conversations {
        match server
            .message_scopes
            .verdict(generation, *conversation, &peers)
        {
            Some(true) => {}
            Some(false) => return false,
            None => unkept.push(*conversation),
        }
    }
    if unkept.is_empty() {
        return true;
    }
    match vault.release_hold_for(&unkept, &destination) {
        Ok(None) => {
            for conversation in &unkept {
                server
                    .message_scopes
                    .record_verdict(generation, *conversation, &peers, true);
            }
            true
        }
        // One held conversation's verdict is its own to keep; a hold among
        // several names none of them, so nothing is kept and the next
        // frame judges them together again. A fault holds the frame, as a
        // per-conversation fault did.
        Ok(Some(_)) if unkept.len() == 1 => {
            server
                .message_scopes
                .record_verdict(generation, unkept[0], &peers, false);
            false
        }
        _ => false,
    }
}
