//! Moved from `crates/oneiron/src/calendar/prep/wake.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// Default lead between the EVENT start and the prep wake: T-45.
pub const DEFAULT_PREP_LEAD_SECS: u64 = 45 * 60;

/// One exact host wake: the three fields of the supervisor wake contract.
///
/// The engine-side image of `oneiron_vault_contract::WakeEntry` with
/// `Schedule::Exact` — see the module note on why the contract type is not
/// named directly at this commit. `at_utc` maps to `Schedule::Exact { at }`;
/// the other two fields map by name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrepWake {
    /// Stable wake id. Rescheduling reuses it so the host REPLACES the entry.
    pub id: String,
    /// Exact fire instant, unix seconds UTC.
    pub at_utc: u64,
    /// Opaque tag echoed back when the wake fires.
    pub reason_tag: String,
}
