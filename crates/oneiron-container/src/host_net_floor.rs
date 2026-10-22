//! The host's floor for a guest's network work (FIX 5978, FIX 5979).
//!
//! Every host descriptor and thread a guest's sockets hold on the host is
//! charged to one floor the host lends through its relay
//! ([`crate::EgressRelay::host_net_floor`]): a socket's entry and its writer
//! for as long as the socket lives, and each relayed datagram's own socket
//! and worker until its blocking receive ends. The floor is the host's, never
//! a second count of this crate's: a served engine lends the descriptor floor
//! its listener admits connections by, so guest relays and connections share
//! one bound.
//!
//! Past the floor a guest is back-pressured, never refused: the work waits
//! for the floor, or, where the guest asked not to wait, its call fails with
//! `EAGAIN` and the guest tries again. The error carries the floor's name
//! ([`HOST_NET_FD_FLOOR`], [`HOST_NET_WORKER_FLOOR`]) as far as the guest.

use std::io;

/// The floor's descriptors are all held: a guest call that needs one more
/// waits for it, or fails with `EAGAIN`.
pub const HOST_NET_FD_FLOOR: &str = "host_net_fd_floor";
/// The floor has no room for one more host thread: a guest call that needs
/// a worker waits for it, or fails with `EAGAIN`.
pub const HOST_NET_WORKER_FLOOR: &str = "host_net_worker_floor";
/// The floor holds no room for the bytes one more piece of guest network
/// work would hold on the host (FIX 7651): the work waits for room.
pub const HOST_NET_BYTE_FLOOR: &str = "host_net_byte_floor";

/// A host's floor for guest network work.
pub trait HostNetFloor: Send + Sync {
    /// Takes `fds` descriptors and `workers` threads of the floor together,
    /// held until the permit drops. Never waits: a full floor is
    /// `WouldBlock` naming it ([`floor_saturated`]).
    fn acquire(&self, fds: usize, workers: usize) -> io::Result<HostNetPermit>;

    /// Holds `bytes` of host memory for one piece of guest network work (a
    /// browser's paused request and its answer, FIX 7651), until the permit
    /// drops. Never waits: a full floor is `WouldBlock` naming
    /// [`HOST_NET_BYTE_FLOOR`]. A floor that keeps no byte reserve charges
    /// nothing.
    fn acquire_bytes(&self, bytes: u64) -> io::Result<HostNetPermit> {
        let _ = bytes;
        Ok(HostNetPermit::new(()))
    }
}

/// Room held on a host floor. Dropping it gives the room back.
#[must_use = "the room is held only as long as the permit"]
pub struct HostNetPermit {
    _held: Box<dyn Send + Sync>,
}

impl HostNetPermit {
    /// A permit holding `held`, whose drop gives the room back.
    pub fn new(held: impl Send + Sync + 'static) -> Self {
        Self {
            _held: Box::new(held),
        }
    }
}

/// A floor that charges nothing: for a relay that reaches nothing, or whose
/// host work a floor on the other side of a channel already charges.
pub struct UnmeteredFloor;

impl HostNetFloor for UnmeteredFloor {
    fn acquire(&self, _fds: usize, _workers: usize) -> io::Result<HostNetPermit> {
        Ok(HostNetPermit::new(()))
    }
}

/// The back-pressure a full `floor` answers with.
#[must_use]
pub fn floor_saturated(floor: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::WouldBlock, floor)
}

/// The floor `error` is back-pressure from, if it is.
#[must_use]
pub fn saturated_floor(error: &io::Error) -> Option<&'static str> {
    if error.kind() != io::ErrorKind::WouldBlock {
        return None;
    }
    known_floor(&error.get_ref()?.to_string())
}

/// The floor a name read off a wire names, if it names one.
#[must_use]
pub fn known_floor(name: &str) -> Option<&'static str> {
    [
        HOST_NET_FD_FLOOR,
        HOST_NET_WORKER_FLOOR,
        HOST_NET_BYTE_FLOOR,
    ]
    .into_iter()
    .find(|floor| *floor == name)
}
