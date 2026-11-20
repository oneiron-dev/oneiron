//! The methods of [`SyncServerConfig`]: the usage debit mode its runtime
//! mode derives, and its validation.

use super::super::self_heal::validate_agent_failure_healer;
use super::SyncServerConfig;
use crate::usage::UsageMode;

impl SyncServerConfig {
    /// Usage debit mode, derived from the runtime mode.
    pub fn runtime_usage_mode(&self) -> UsageMode {
        self.runtime.mode.usage_mode()
    }

    pub fn validate(&self) -> Result<(), oneiron::Error> {
        validate_agent_failure_healer(self.agent_failure_healer.as_ref())?;
        if self.ephemeral_timeout_ms <= 0 {
            return Err(oneiron::Error::sync_protocol(
                oneiron::SyncProtocolValidation::InvalidConfig {
                    field: oneiron::SyncConfigField::EphemeralTimeoutMs,
                },
            ));
        }
        if self.max_ephemeral_snapshot_bytes == 0 {
            return Err(oneiron::Error::sync_protocol(
                oneiron::SyncProtocolValidation::InvalidConfig {
                    field: oneiron::SyncConfigField::MaxEphemeralSnapshotBytes,
                },
            ));
        }
        Ok(())
    }
}
