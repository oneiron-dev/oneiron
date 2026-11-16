//! Moved from `crates/oneiron/src/channel_identity_provider/native_mail/skipped.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// How many polls in a row one message's own failure stops before the poll
/// sets it aside and reads on.
pub const NATIVE_MAIL_SET_ASIDE_AFTER_STOPS: u32 = 3;

/// One native mail message set aside so its inbox could go on, or, while
/// [`Self::is_set_aside`] says no, the message its inbox's polls stop at:
/// what it was, why it stopped and how often, never its bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeMailSkippedMessage {
    /// Lower-case hex id of the native mail identity whose inbox was read.
    pub identity_ref: String,
    /// The identity's mailbox address.
    pub mailbox_address: String,
    /// The server's JMAP email id, exactly as it returned it.
    pub message_id: String,
    /// The full error of the poll that set it aside.
    pub reason: String,
    /// The polls in a row the message stopped.
    pub polls: u32,
    /// When a poll first set it aside; a retried page keeps this time.
    /// While the message is not set aside, when a poll last stopped at it.
    pub skipped_at: u64,
}

impl NativeMailSkippedMessage {
    /// Whether the message is set aside: its own failure stopped
    /// [`NATIVE_MAIL_SET_ASIDE_AFTER_STOPS`] polls in a row.
    #[must_use]
    pub const fn is_set_aside(&self) -> bool {
        self.polls >= NATIVE_MAIL_SET_ASIDE_AFTER_STOPS
    }
}
