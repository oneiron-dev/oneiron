//! The proof that window bytes this client takes come from one of the
//! owner's own machines (FIX 11709). Only the connection that brought them
//! can say so: the bytes name no signer, and a tier a caller names proves
//! nothing.

use super::base::SyncClient;
use crate::EntityId;
use crate::authority::PeerMachine;

/// An own-device import's proof: the client that takes the bytes has no
/// federation peer bound, and the machine at the other end of the connection
/// that sent them proved itself over that connection's upgrade, under its
/// own fresh binding, and still stands here on the key it proved. Only
/// [`SyncClient::own_device_import`] makes one; the ingest doors mint a row's
/// own-device lane under it.
pub(in crate::sync) struct OwnDeviceImport {
    machine: EntityId,
}

impl OwnDeviceImport {
    /// The own machine that sent the bytes.
    pub(in crate::sync) fn machine(&self) -> EntityId {
        self.machine
    }
}

impl SyncClient {
    /// The proof for bytes `from` sent: the machine this client's connection
    /// proved when they came in (its `home_peer` then), rechecked now. `None`
    /// on a federation lane, for a machine no connection proved, and for one
    /// removed, poisoned or trusted under other keys since.
    pub(super) fn own_device_import(&self, from: PeerMachine) -> Option<OwnDeviceImport> {
        if self.config.federation_peer.is_some() {
            return None;
        }
        let PeerMachine::Proven { machine, .. } = self.vault.peer_machine_stands(from) else {
            return None;
        };
        Some(OwnDeviceImport { machine })
    }
}
