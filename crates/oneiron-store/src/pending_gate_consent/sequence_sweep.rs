//! Monotonic sequence allocator, high-water read, and sweep-state cursors for expiry/list sweeps.

use heed::{RoTxn, RwTxn};

use crate::side_table::codec::CodecError;
use crate::side_table::codec::RawValue;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;

/// The critical-confirm sweep cursor's hand-rolled `flag ‖ cursor(8) ‖ flag ‖
/// fence(8)` layout: both present (the only shape this module ever writes)
/// or, on read, either half legitimately absent. Kept as the module's own
/// codec behind [`Raw`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SweepState {
    pub cursor: Option<u64>,
    pub fence: Option<u64>,
}

impl RawValue for SweepState {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        let (Some(cursor), Some(fence)) = (self.cursor, self.fence) else {
            // The Store-level put/get wrapper never persists a half-present
            // or fully-absent state (it deletes the row instead), so this
            // arm is unreachable in practice; kept total for the trait.
            return Err(oneiron_base::error::Error::InvariantViolation(
                "critical confirm sweep cursor and fence must be paired",
            )
            .into());
        };
        let mut value = [0_u8; 18];
        value[0] = 1;
        value[1..9].copy_from_slice(&cursor.to_be_bytes());
        value[9] = 1;
        value[10..18].copy_from_slice(&fence.to_be_bytes());
        Ok(value.to_vec())
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        // Canonical wire form is flag + u64 cursor + flag + u64 fence.
        // Reject malformed metadata rather than making a malformed sweep
        // resume at an arbitrary point.
        if bytes.len() != 18 || !matches!(bytes[0], 0 | 1) || !matches!(bytes[9], 0 | 1) {
            return Err(Error::CorruptedIndex("critical confirm sweep state").into());
        }
        let cursor_value = u64::from_be_bytes(bytes[1..9].try_into().expect("fixed slice"));
        let fence_value = u64::from_be_bytes(bytes[10..18].try_into().expect("fixed slice"));
        let cursor = (bytes[0] == 1).then_some(cursor_value);
        let fence = (bytes[9] == 1).then_some(fence_value);
        if (bytes[0] == 0 && cursor_value != 0)
            || (bytes[9] == 0 && fence_value != 0)
            || cursor.is_some() != fence.is_some()
            || cursor
                .zip(fence)
                .is_some_and(|(cursor, fence)| cursor > fence)
        {
            return Err(Error::CorruptedIndex("critical confirm sweep state").into());
        }
        Ok(Self { cursor, fence })
    }
}
