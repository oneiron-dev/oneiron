//! Moved from `crates/oneiron/src/edit_distance/escalation/storage.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
use oneiron_base::error::Result;
use serde::Deserialize;
use serde::Serialize;

/// Only accepted schema version for either stored row.
pub const ROW_VERSION: u8 = 1;

pub const ESCALATION_ROW_LABEL: &str = "escalation row";

pub const STANDING_POLICY_ROW_LABEL: &str = "escalation standing policy row";

pub fn encode_row<T: Serialize>(row: &T, label: &'static str) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(row).map_err(|_| Error::InvariantViolation(label))
}
