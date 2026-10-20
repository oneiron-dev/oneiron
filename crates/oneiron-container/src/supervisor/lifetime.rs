//! A guest socket's host entry lives as long as the guest holds the socket
//! (FIX 5978). The launcher reports each complete inventory of the socket
//! inodes its guest's tasks hold ([`crate::socket_lifetime`]); an entry two
//! complete inventories in a row miss is removed and its writer stops. The
//! entry's descriptors close, and its room on the host floor comes back,
//! once the last work that holds it ends: a writer finishing the datagram it
//! is relaying, or a relay answer on its way back. One miss reclaims
//! nothing, so a socket that moved between tasks while one scan ran keeps
//! its entry. A removed entry's virtual loopback ends with it: its bound
//! address, and a listener's queue and waiting accepts
//! ([`super::loopback::release`]).

use super::State;
use crate::wire;
use std::collections::{BTreeSet, HashSet};
use std::io;
use std::sync::atomic::Ordering;

/// What a stream socket's entry holds of the host floor while it lives, as
/// (descriptors, workers): its host end.
pub(super) const STREAM_ENTRY: (usize, usize) = (1, 0);
/// What a datagram socket's entry holds while it lives: its host end, the
/// host's copy of the guest's end, and its writer.
pub(super) const DATAGRAM_ENTRY: (usize, usize) = (2, 1);

/// The inventory being received, and the entries the last complete one
/// missed.
#[derive(Default)]
pub(super) struct Inventory {
    generation: u64,
    inodes: BTreeSet<u64>,
    missed: HashSet<u64>,
}

/// Takes one chunk of the launcher's inventory. A chunk of a newer scan
/// drops what an unfinished older one sent; the last chunk of a scan
/// reconciles the entries against it.
pub(super) fn receive(state: &State, chunk: wire::SocketInventory) -> io::Result<()> {
    let poisoned = || io::Error::other("fence state poisoned");
    let mut inventory = state.inventory.lock().map_err(|_| poisoned())?;
    if chunk.generation != inventory.generation {
        inventory.generation = chunk.generation;
        inventory.inodes.clear();
    }
    inventory.inodes.extend(chunk.inodes);
    if !chunk.last {
        return Ok(());
    }
    let live = std::mem::take(&mut inventory.inodes);
    let mut sockets = state.sockets.lock().map_err(|_| poisoned())?;
    let dead: HashSet<u64> = sockets
        .keys()
        .filter(|id| !live.contains(id))
        .copied()
        .collect();
    for id in dead.intersection(&inventory.missed) {
        if let Some(socket) = sockets.remove(id) {
            socket.closed.store(true, Ordering::Release);
            super::loopback::release(state, *id);
        }
    }
    inventory.missed = dead.difference(&inventory.missed).copied().collect();
    Ok(())
}
