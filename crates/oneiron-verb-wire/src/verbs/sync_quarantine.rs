//! Moved from `crates/oneiron/src/verbs/sync_quarantine.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::sync::quarantine::keys_classifier::QuarantineContainer;
use serde::Deserialize;
use serde::Serialize;

/// Retained held-edit metadata with lossless hash strings on every transport.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SyncHeldEditEvidence {
    pub window_key: String,
    pub container: QuarantineContainer,
    /// The stored `xxh3_64` key hash as sixteen lowercase hexadecimal digits.
    pub crdt_key_hash: String,
    pub crdt_key_len: u32,
    pub reason_code: String,
    /// The stored `xxh3_64` payload hash as sixteen lowercase hexadecimal digits.
    pub payload_hash: String,
    pub quarantined_at: u64,
}
