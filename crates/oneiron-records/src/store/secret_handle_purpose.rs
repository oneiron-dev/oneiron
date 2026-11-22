//! Moved from `crates/oneiron/src/store/secret_handle_purpose.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretHandlePurpose {
    pub purpose: String,
    pub receipt: [u8; 16],
}
