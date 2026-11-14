//! Moved from `crates/oneiron/src/failure_signals/held/read.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use schemars::JsonSchema;
use serde::Deserialize;
use serde::Serialize;

/// The failure-signal batch the vault carries, as its owner reads it before
/// he presses (FIX 6740; CALLS `FIX 6740 view shape`). `content` is the
/// batch exactly as it was first serialized and is sent, and
/// `approval_digest` the one value `vault.consent.approve_once` or
/// `vault.consent.deny` takes for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct HeldFailureSignalBatchView {
    /// Its random id.
    pub batch_id: String,
    /// The publisher endpoint it was built for, and is sent to.
    pub endpoint: String,
    /// The send ref every send of it carries: `failure_signals:batch:{batch_id}`.
    pub send_ref: String,
    /// Its content ref: `failure_signals:digest:{content_digest}`.
    pub content_ref: String,
    /// The batch JSON, the exact UTF-8 the publisher receives.
    pub content: String,
    /// Lowercase hex BLAKE3 of `content`'s bytes.
    pub content_digest: String,
    /// The approve-once digest the owner's press on it names, 64 lower-hex.
    pub approval_digest: String,
    /// The aggregate count rows it froze.
    pub count_rows: u64,
    /// The sum of the quantities those rows froze.
    pub signal_count: u64,
    /// The code-fix records it carries.
    pub code_fix_records: u64,
    /// Whether the deployment let the publisher train on it when it was
    /// built.
    pub training_permitted: bool,
    /// Seconds since the epoch.
    pub created_at: u64,
    /// Where its custody stood after its last send: `staged`, `held` or
    /// `admitted`. A record only, never proof the owner is still awaited.
    pub custody_stage: String,
}
