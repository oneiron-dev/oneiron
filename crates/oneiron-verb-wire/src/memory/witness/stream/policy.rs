//! Moved from `crates/oneiron/src/memory/witness/stream/policy.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::memory::witness::stream::*;

impl MessageWriteMode {
    pub fn validate(self) -> MessageStreamResult<()> {
        if matches!(
            self,
            Self::Streamed {
                cadence: StreamCadence::PerWindow { chars: 0 },
                ..
            }
        ) {
            return Err(MessageStreamError::InvalidRequest(
                "window must be positive",
            ));
        }
        Ok(())
    }
}

/// The owner's write mode is a Setting value (`memory.message_stream.mode`, DESIGN
/// 15-setting-primitive, stage 1): [`MessageWriteMode::validate`] is its check.
impl oneiron_setting_contract::SettingValue for MessageWriteMode {
    fn check(self) -> oneiron_contracts::error::Result<Self> {
        self.validate()
            .map_err(|error| oneiron_contracts::error::Error::InvalidConfig(error.to_string()))?;
        Ok(self)
    }
}
