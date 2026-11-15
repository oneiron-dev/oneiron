//! Moved from `crates/oneiron/src/recovery/document.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

#[cfg(feature = "sync")]
use loro::LoroValue;
#[cfg(feature = "sync")]
use loro::ValueOrContainer;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalHead {
    pub entity_id: [u8; 16],
    pub head: [u8; 16],
}

pub fn hex(value: [u8; 16]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}
