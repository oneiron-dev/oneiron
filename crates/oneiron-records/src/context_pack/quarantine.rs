//! Moved from `crates/oneiron/src/context_pack/quarantine.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PackQuarantineContainer {
    Entities,
    Edges,
    Tombstones,
    Leases,
}
