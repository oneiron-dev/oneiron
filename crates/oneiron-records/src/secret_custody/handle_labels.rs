//! Moved from `crates/oneiron/src/secret_custody/handle_labels.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::store::secret_handle_labels::SecretHandleLabel;
use heed::RoTxn;
use heed::RwTxn;
use serde::Deserialize;
use serde::Serialize;

/// What setting or clearing a handle's label leaves behind: the stored
/// label (`None` after a clear), the kind suggestion the card falls back
/// to, and the act's Gate receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretHandleLabelSet {
    pub label: Option<String>,
    pub suggested_label: Option<String>,
    pub receipt: String,
}
