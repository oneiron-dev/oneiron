//! Moved from `crates/oneiron/src/channel_identity_provider/gmail/mod.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::channel_identity_provider::mail_placement::PlacementPolicy;
use serde::Deserialize;
use serde::Serialize;
use sha2::Digest;
use sha2::Sha256;

pub const GMAIL_EVENT_ID_PREFIX: &str = "gmail:";

pub const GMAIL_THREAD_PAYLOAD_PREFIX: &str = "gmail:thread:";

pub const MAX_GMAIL_MESSAGES_PER_PAGE: usize = 500;

/// Provider-native ceiling on a Gmail id, independent of where it lands.
pub const MAX_GMAIL_ID_BYTES: usize = 128;

pub const fn min_bytes(a: usize, b: usize) -> usize {
    if a < b { a } else { b }
}

/// Durable payload of a `gmail_inbox_poll` attempt.
///
/// Names only: the mailbox, the custody record, and the identity row. No token
/// bytes reach the queue.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GmailInboxPollConfig {
    pub mailbox_address: String,
    pub custody_record_ref: String,
    pub identity_ref: String,
    /// The typed placement read boundary carried into the durable poll.
    pub placement_policy: PlacementPolicy,
}
