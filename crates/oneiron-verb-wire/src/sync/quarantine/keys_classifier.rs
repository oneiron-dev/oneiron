//! Moved from `crates/oneiron/src/sync/quarantine/keys_classifier.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::register::Register;
use serde::Deserialize;
use serde::Serialize;

/// Which CRDT window-doc map the rejected op targeted.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema, Register,
)]
#[serde(rename_all = "snake_case")]
#[register("quarantine.container")]
pub enum QuarantineContainer {
    Entities,
    Edges,
    Tombstones,
    /// Root-doc `leases` registry entries (ONE-1140): a malformed lease
    /// value arriving through the root mirror is quarantined — never
    /// upserted over a previous good `ls:` row, never silently dropped.
    Leases,
    /// The base window's `office_proposals` map (FIX 2691): a carried
    /// proposal whose decisions diverge from the copy held here.
    OfficeProposals,
    /// The base window's `typed_body_rows` map (FIX 12470): a carried typed
    /// body receipt that diverges from the copy held here.
    TypedBodyRows,
}
