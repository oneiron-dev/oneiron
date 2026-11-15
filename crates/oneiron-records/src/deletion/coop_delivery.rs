//! Moved from `crates/oneiron/src/deletion/coop_delivery.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::deletion::coop_delivery::types::CooperativeDeletionDisposition;
pub use crate::deletion::coop_delivery::types::CooperativeLocalRedaction;
use oneiron_base::error::Error;
pub use oneiron_store::deletion::coop_delivery::types::CooperativeClaimValueRedaction;
pub use oneiron_store::deletion::coop_delivery::types::CooperativeDeleteOperation;
pub use oneiron_store::deletion::coop_delivery::types::CooperativeDeleteRecord;
pub use oneiron_store::deletion::coop_delivery::types::CooperativeDeleteRecordState;
pub use oneiron_store::deletion::coop_delivery::types::CooperativeDeletionRetention;
pub use oneiron_store::deletion::coop_delivery::types::CooperativeRestrictionLiftAttestation;
pub use oneiron_verb_wire::deletion::coop_delivery::types::CooperativeDeletionDispositionKind;

pub fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(format!("courtesy delete: {reason}"))
}

/// Parses `N` bytes of lowercase or uppercase hex.
pub fn parse_hex<const N: usize>(value: &str) -> Option<[u8; N]> {
    if value.len() != N * 2 || !value.is_ascii() {
        return None;
    }
    let mut out = [0; N];
    for (slot, pair) in out.iter_mut().zip(value.as_bytes().chunks(2)) {
        *slot = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(out)
}
pub mod types;
