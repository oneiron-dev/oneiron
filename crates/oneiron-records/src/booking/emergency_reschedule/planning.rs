//! Moved from `crates/oneiron/src/booking/emergency_reschedule/planning.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::booking::emergency_reschedule::*;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EmergencyLocalBasis {
    PreStartCancellation,
    EmergencyAtOrAfterStart,
    RequestUpdate,
}
