//! Moved from `crates/oneiron/src/blob_artifact/esign/lifecycle.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::blob_artifact::esign::model::*;
use oneiron_base::error::Result;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EsignNoticeSwitches {
    pub invite: bool,
    pub pending: bool,
    pub completed: bool,
    pub rejection: bool,
    pub void: bool,
    pub expiry: bool,
}

impl Default for EsignNoticeSwitches {
    fn default() -> Self {
        Self {
            invite: true,
            pending: true,
            completed: true,
            rejection: true,
            void: true,
            expiry: true,
        }
    }
}

/// Rule values belong to the installing pack; the engine does not choose a
/// reminder ladder or a default expiry window. Seconds are measured from send.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EsignLifecycleRules {
    pub expiry_after_seconds: u64,
    pub first_reminder_after_seconds: u64,
    pub repeat_reminder_every_seconds: u64,
    pub reminder_cap_seconds: u64,
    pub notices: EsignNoticeSwitches,
}

impl EsignLifecycleRules {
    pub fn validate(&self) -> Result<()> {
        if self.expiry_after_seconds == 0
            || self.first_reminder_after_seconds == 0
            || self.repeat_reminder_every_seconds == 0
            || self.reminder_cap_seconds < self.first_reminder_after_seconds
            || self.reminder_cap_seconds > self.expiry_after_seconds
        {
            return Err(invalid("invalid lifecycle rules"));
        }
        Ok(())
    }
}
