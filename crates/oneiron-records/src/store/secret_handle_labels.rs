//! Moved from `crates/oneiron/src/store/secret_handle_labels.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// The stored owner-set label on one custody handle: the label text and the
/// Gate receipt of the set that wrote it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretHandleLabel {
    pub label: String,
    pub receipt: String,
}
