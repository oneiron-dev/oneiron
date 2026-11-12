//! Moved from `crates/oneiron/src/origin/document_ingress.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_store::receipt_identity::ERASED_CALL_IDENTITY;

/// One push operation, including non-text blobs and mode-only changes.
/// Git objects remain pinned by the hash-keyed origin change claim.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub struct ReceivedFileOperation {
    pub operation_id: String,
    /// The pusher's hex id, or [`ERASED_CALL_IDENTITY`] once that actor was
    /// erased (FIX 4475).
    pub actor_id: String,
    pub session_id: String,
    pub ref_name: String,
    pub path: String,
    pub before_hash: [u8; 32],
    pub after_hash: [u8; 32],
    pub old_mode: Option<u32>,
    pub new_mode: Option<u32>,
    pub document_edit: bool,
}
