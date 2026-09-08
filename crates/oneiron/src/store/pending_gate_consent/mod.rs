//! Pending gate-consent claim records — run/group/hash indexes, sequence
//! counter, pagination, sweep-state cursors, and the critical-confirm
//! invalidation rows that share those cursors.

use super::*;

mod indexes;
mod invalidation;
mod keys;
mod records;
mod sequence_sweep;
mod tray;

pub(in crate::store) use self::keys::{
    PENDING_GATE_CONSENT_KEY_PREFIX, index_key_with_id, index_suffix_id,
    pending_gate_consent_claim_id_from_key, pending_gate_consent_upper_bound, string_index_prefix,
};
pub(crate) use self::records::PENDING_GATE_CONSENT_VERSION;
pub(in crate::store) use self::records::decode_pending_gate_consent;
pub use self::records::{PendingGateConsentGroup, PendingGateConsentRecord};
// Test-only seam (open_gates/mod.rs precedent): the store test suite names
// these bare through `use super::*`, but no non-test code outside
// pending_gate_consent/ reaches them through the seam, so the re-exports
// live under `cfg(test)`.
#[cfg(test)]
pub(in crate::store) use self::keys::{
    CRITICAL_CONFIRM_EXPIRY_CURSOR_KEY, PENDING_GATE_CONSENT_GROUP_INDEX_PREFIX,
    PENDING_GATE_CONSENT_HASH_INDEX_PREFIX, PENDING_GATE_CONSENT_INDEX_STATE_PREFIX,
    PENDING_GATE_CONSENT_RUN_INDEX_PREFIX,
};
#[cfg(test)]
pub(in crate::store) use self::records::PENDING_GATE_CONSENT_INDEX_STATE_VERSION;
