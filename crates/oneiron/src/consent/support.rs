use crate::side_table::{self, SideTable};

use super::effect::UndoFidelity;

#[doc(hidden)]
pub(super) use oneiron_consent_state::consent::support::{
    ApproveOnceMarker, invalid_row, required_value, validate_keys,
};
#[doc(hidden)]

pub(super) const CONSENT_APPROVE_ONCE_AVAILABLE: u8 = 0;
pub(super) const CONSENT_APPROVE_ONCE_SPENT: u8 = 1;
/// Approve-once state, keyed by the 32-byte effect digest. Minting writes an
/// available marker in the same transaction as its receipt. Delivery
/// atomically changes that marker to spent in the transaction that authorizes
/// the effect. Presence therefore rejects a duplicate mint, while the state
/// distinguishes the one live tap from a replay (DEC-0006 invariant 2).
pub(super) const APPROVE_ONCE_MARKERS: SideTable<[u8; 32], ApproveOnceMarker, side_table::Raw> =
    SideTable::new(&side_table::CONSENT_APPROVE_ONCE_MARKER);

#[cfg(test)]
pub(super) use crate::store::consent_bound::SUBJECT_KIND_AUDIENCE;
pub(super) use crate::store::consent_bound::{
    hash_field, normalized_ref, normalized_selectors, selectors_contain,
};

pub(super) const fn undo_fidelity_byte(fidelity: UndoFidelity) -> u8 {
    match fidelity {
        UndoFidelity::Full => 0,
        UndoFidelity::Partial => 1,
        UndoFidelity::None => 2,
        UndoFidelity::Unknown => 3,
    }
}

pub(super) use crate::store::consent_bound::invalid_bound;
