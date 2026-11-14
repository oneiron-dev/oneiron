//! Moved from `crates/oneiron/src/mail_pack/share.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// `vault.mail.threads.share` and `.unshare`'s input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MailThreadShareRequest {
    /// A row of the thread: its CONVERSATION, or any message in it, 32-hex.
    pub record_ref: String,
    /// The PERSON the thread is shared with, or no longer shared with,
    /// 32-hex.
    pub person_ref: String,
}

/// What a share or an unshare did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MailThreadShareReceipt {
    /// The thread's audience policy, 32-hex.
    pub thread_ref: String,
    pub person_ref: String,
    /// Whether the thread is shared with the person after this act.
    pub shared: bool,
    /// Whether this act changed anything.
    pub changed: bool,
    /// Everyone the thread is shared with now, 32-hex.
    pub shared_with: Vec<String>,
}
