//! Moved from `crates/oneiron/src/secret_snapshot.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// A value-free proposal to move a detected file secret into the vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SnapshotSecretLiftProposal {
    pub path: String,
    pub detector_reason: String,
    pub suggested_secret_name: String,
    pub project_id: String,
}
