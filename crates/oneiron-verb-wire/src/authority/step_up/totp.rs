//! Moved from `crates/oneiron/src/authority/step_up/totp.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use heed::RoTxn;
use heed::RwTxn;
use serde::Deserialize;
use serde::Serialize;
use zeroize::Zeroize;
use zeroize::Zeroizing;

/// Owner reset names only the person's TOTP factors, not their passkeys.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StepUpTotpResetRequest {
    pub person: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct StepUpTotpReset {
    pub person: String,
    pub removed: usize,
}
