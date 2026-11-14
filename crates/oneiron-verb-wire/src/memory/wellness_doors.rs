//! Moved from `crates/oneiron/src/memory/wellness_doors.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WellnessPersonRequest {
    pub affected_person_ref: String,
}
