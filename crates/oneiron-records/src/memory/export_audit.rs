//! Moved from `crates/oneiron/src/memory/export_audit.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// What an export copied (FIX 6427).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportAuditScope {
    /// The whole vault: the archive, the OKF bundle or the JSON bundle.
    WholeVault,
    /// An off-record room's talk, as its Owner's membership shows it.
    OffRecordRoom,
}
