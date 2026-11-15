//! Moved from `crates/oneiron/src/channel_identity_provider/mailbox_skipped.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// Where a polled message stopped before it could be admitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GmailSkipStage {
    /// Its Gmail ids or metadata did not normalize into an email envelope.
    ProviderInbound,
    /// The adapter refused the normalized envelope.
    Parse,
    /// Inbound routing rejected this message on its own account.
    Routing,
}

/// One polled Gmail message set aside so its page could go on: what it was,
/// where it stopped and why, never its text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GmailSkippedMessage {
    /// Lower-case hex id of the delegated identity whose mailbox was read.
    pub identity_ref: String,
    /// Normalized address of that mailbox.
    pub mailbox_address: String,
    /// The provider's message id, exactly as the wire returned it.
    pub message_id: String,
    /// The provider's thread id: the message's reference back at Gmail.
    pub thread_id: String,
    /// The provider's internal date of the message, in seconds.
    pub internal_date_secs: u64,
    pub stage: GmailSkipStage,
    /// The full error or rejection reason.
    pub reason: String,
    /// When a run first set it aside; a retried page keeps this time.
    pub skipped_at: u64,
}
