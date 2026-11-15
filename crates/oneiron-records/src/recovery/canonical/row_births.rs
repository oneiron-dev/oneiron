//! Moved from `crates/oneiron/src/recovery/canonical/row_births.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

#[cfg(feature = "sync")]
use loro::LoroValue;
#[cfg(feature = "sync")]
use loro::ValueOrContainer;
use serde::Deserialize;
use serde::Serialize;

/// One row's birth: the Named MessagePack envelope, byte for byte as the
/// window or the vault holds it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalRowBirth {
    pub id: [u8; 16],
    pub value: Vec<u8>,
}
