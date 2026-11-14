//! Moved from `crates/oneiron/src/federation/record_scope/birth_placement.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::registry::ENTITY_TYPE_SUMMARY;
use oneiron_base::registry::ENTITY_TYPE_TASK;
use serde::Deserialize;
use serde::Serialize;

/// Whether a replicated row of `kind` carries its birth placement: a TASK
/// and a SUMMARY, the kinds whose world a read takes from their stamp alone
/// and whose replicated put `stamp_put` leaves unstamped.
pub const fn carries_birth_placement(kind: u8) -> bool {
    matches!(kind, ENTITY_TYPE_TASK | ENTITY_TYPE_SUMMARY)
}
