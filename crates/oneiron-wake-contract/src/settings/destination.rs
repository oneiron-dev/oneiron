//! Moved from `crates/oneiron/src/settings/destination.rs` (core split slice 3: wake contract below core).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::machine_destination::PeerMachine;

/// Where a read's rows go: this device, or off it to every machine that
/// carries them on. Requester, executor and onward recipient are conjuncts:
/// a world reaches the read only when every one of them may read it.
///
/// Only the host builds one, from the connection a request reached it on.
/// It only narrows ([`Self::meet`]): once off this device a read never reads
/// on it again, and a later on-device locality never erases a machine it
/// carries.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ReadDestination {
    /// Whether the rows leave this device.
    pub off_device: bool,
    /// Each machine the rows go to, as its connection proved it. Empty while
    /// off this device: a destination nobody proved.
    pub proved: Vec<PeerMachine>,
}

impl ReadDestination {
    /// This device: nothing leaves it.
    #[must_use]
    pub fn on_device() -> Self {
        Self::default()
    }

    /// Off this device, to the machine `peer` names: a proved connection's
    /// machine, which every snapshot judges again, or one nobody proved.
    #[must_use]
    pub fn toward(peer: PeerMachine) -> Self {
        Self {
            off_device: true,
            proved: vec![peer],
        }
    }

    /// The machine a connection proved, before any locality says whether
    /// the rows leave: met into a read, it names where they go once a
    /// locality puts the read off this device ([`Self::meet`]). An unproved
    /// peer names nothing, so such a read stays a destination nobody proved.
    #[must_use]
    pub fn proved(peer: PeerMachine) -> Self {
        Self {
            off_device: false,
            proved: match peer {
                PeerMachine::Proven { .. } => vec![peer],
                PeerMachine::Unknown => Vec::new(),
            },
        }
    }

    /// Whether the rows leave this device.
    #[must_use]
    pub fn is_off_device(&self) -> bool {
        self.off_device
    }

    /// Meets `other` into `self`: off this device if either is, toward every
    /// machine either names. See [`BARE_LOCALITY_NAMES_NO_MACHINE`] for a
    /// bare off-device locality met into a read that already carries a
    /// proved machine.
    pub fn meet(&mut self, other: &Self) {
        self.off_device |= other.off_device;
        if other.off_device && other.proved.is_empty() && !BARE_LOCALITY_NAMES_NO_MACHINE {
            self.add(PeerMachine::Unknown);
        }
        for peer in &other.proved {
            self.add(*peer);
        }
    }

    fn add(&mut self, peer: PeerMachine) {
        if !self.proved.contains(&peer) {
            self.proved.push(peer);
        }
    }

    /// Connection peers retained even while the current locality is on-device.
    pub fn all_peers(&self) -> &[PeerMachine] {
        &self.proved
    }

    /// Every machine the judge reads the world settings for: none on this
    /// device, else each machine the rows go to. An unproved one stands for
    /// all of them, since a destination nobody proved may read the least.
    #[must_use]
    pub fn peers(&self) -> Vec<PeerMachine> {
        if !self.off_device {
            return Vec::new();
        }
        if self.proved.is_empty() || self.proved.contains(&PeerMachine::Unknown) {
            return vec![PeerMachine::Unknown];
        }
        self.proved.clone()
    }
}

impl From<&ReadDestination> for ReadDestination {
    fn from(destination: &ReadDestination) -> Self {
        destination.clone()
    }
}

/// Whether a bare off-device locality met into a read that already carries a
/// proved machine names no machine of its own (CALLS `mesh PR2b bare
/// locality`). A host stamps both from one connection, so the locality only
/// restates where that machine sits; an unproved hop is always met in as
/// [`ReadDestination::toward`]`(PeerMachine::Unknown)`.
pub const BARE_LOCALITY_NAMES_NO_MACHINE: bool = true;
