//! The host's last observed device-sync start outcome, never current health.

use crate::Vault;

#[doc(hidden)]
pub use oneiron_records::world_keys::owner_work::relay_start::DeviceSyncStart;

impl Vault {
    /// Records the host's last observed start outcome on this open session.
    /// Diagnostics only: no durable state, admission or relay-pass changes.
    pub fn record_device_sync_start(&self, observation: DeviceSyncStart) {
        *self
            .world_keys
            .device_sync_start
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(observation);
    }
}
