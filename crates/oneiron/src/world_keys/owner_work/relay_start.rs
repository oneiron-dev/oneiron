//! The host's last observed device-sync start outcome, never current health.

use serde::Serialize;

use crate::Vault;

/// The last device-sync start outcome recorded on this open vault session
/// (FIX 5553). Shared clones observe the same value; closing the session loses
/// it. It neither proves current connectivity nor changes pending work.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum DeviceSyncStart {
    /// Neither a device-sync section nor an enrolled home was configured then.
    NotConfigured,
    /// Resolving the configuration or enrolment failed.
    ConfigurationFailed,
    /// Reap preparation did not admit that managed start.
    FrozenForReap,
    /// Opening the sync connection failed.
    OpenFailed {
        /// The archive receiver had started before that opening failed.
        /// This is historical, not a claim that the receiver still runs.
        archive_receiver_running: bool,
    },
    /// Opening succeeded then, not necessarily still connected or running.
    Started,
}

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
