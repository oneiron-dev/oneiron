//! The vault's deletion as `Ping` reports it (FIX 11710): the marker itself
//! lives beside the host's write gate now, shared with the self-hosted
//! serve's deletion gate (FIX 11979).

pub(super) use crate::server::DeletionMarker;
use oneiron_vault_contract::PingDeletion;

use super::ManagedState;

impl ManagedState {
    /// The vault's deletion, as every `Ping` reports it (FIX 11710).
    pub(super) fn vault_deletion(&self) -> Option<PingDeletion> {
        self.admission.deletion().read(self.server.vault())
    }
}
