//! FIX 3374: the home a device enrolled with, pinned on the device's mesh
//! listener. The home binds the device's endpoint in its own vault and
//! grants it the sync ALPN as the enrolment completes, and answers its own
//! mesh address over the verified redeem; the device keeps that address in
//! its enrolment record. The device's vault holds no host-signed binding of
//! the home (only a roster owner signs one, and none syncs), so its listener
//! admits the pinned home besides the paired machines its vault binds: by
//! the pinned endpoint key, on the sync ALPN alone. Device sync pins the
//! home when it resolves its dial ([`pin_home`]); the listener reads the pin
//! at every admission, under this install's own MACHINE.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use oneiron::EntityId;
use oneiron_mesh_transport::{
    MachineGrants, MachineId, MachineRoster, MeshError, MeshMachineAddress, PairedMachineGrants,
    SYNC_ALPN, VaultMachineRoster,
};

/// The home each install pins, with its mesh address, by the install's own
/// MACHINE: one listener reads its own install's pin alone.
fn pins() -> &'static Mutex<HashMap<EntityId, (EntityId, MeshMachineAddress)>> {
    static PINS: OnceLock<Mutex<HashMap<EntityId, (EntityId, MeshMachineAddress)>>> =
        OnceLock::new();
    PINS.get_or_init(Mutex::default)
}

/// Pins `home` at `address` as the home the install `local` enrolled with,
/// in place of any home it pinned before.
pub(crate) fn pin_home(local: EntityId, home: EntityId, address: MeshMachineAddress) {
    if let Ok(mut pins) = pins().lock() {
        pins.insert(local, (home, address));
    }
}

/// The home the install `local` pins, and its mesh address.
pub(super) fn pinned_home(local: EntityId) -> Option<(EntityId, MeshMachineAddress)> {
    pins().lock().ok()?.get(&local).cloned()
}

/// The vault's MACHINE rows, and the pinned home's address where the vault
/// holds none for it.
#[derive(Debug)]
pub(super) struct PinnedRoster {
    pub(super) local: EntityId,
    pub(super) vault: VaultMachineRoster,
}

impl MachineRoster for PinnedRoster {
    fn by_machine(&self, machine: MachineId) -> Result<Option<MeshMachineAddress>, MeshError> {
        Ok(self.vault.by_machine(machine)?.or_else(|| {
            pinned_home(self.local)
                .filter(|(home, _)| *home == machine)
                .map(|(_, address)| address)
        }))
    }

    fn by_endpoint(
        &self,
        endpoint_key: [u8; 32],
    ) -> Result<Option<(MachineId, MeshMachineAddress)>, MeshError> {
        Ok(self.vault.by_endpoint(endpoint_key)?.or_else(|| {
            pinned_home(self.local).filter(|(_, address)| address.endpoint_key == endpoint_key)
        }))
    }
}

/// The paired machines' live grants, and the pinned home on the sync ALPN
/// under its pinned endpoint key.
#[derive(Debug)]
pub(super) struct PinnedGrants {
    pub(super) local: EntityId,
    pub(super) vault: PairedMachineGrants,
}

impl MachineGrants for PinnedGrants {
    fn permits(&self, machine: MachineId, key: [u8; 32], alpn: &[u8]) -> Result<bool, MeshError> {
        let enrolled_home = alpn == SYNC_ALPN
            && pinned_home(self.local)
                .is_some_and(|(home, address)| home == machine && address.endpoint_key == key);
        if enrolled_home {
            return Ok(true);
        }
        self.vault.permits(machine, key, alpn)
    }
}
