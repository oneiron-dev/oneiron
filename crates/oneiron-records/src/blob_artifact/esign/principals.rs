//! Moved from `crates/oneiron/src/blob_artifact/esign/principals.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SigningAutonomy {
    ScopedRead,
    Draft,
    SendWithApproval,
    AutonomousInEnvelope,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigningPrincipal {
    pub principal_ref: String,
    pub autonomy: SigningAutonomy,
    /// Defaults closed. This is a legal-reality dial, not a fixed safety ban.
    pub automated_sign_action: bool,
}
