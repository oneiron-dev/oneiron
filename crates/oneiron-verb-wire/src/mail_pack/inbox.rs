//! Moved from `crates/oneiron/src/mail_pack/inbox.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::mail_pack::state::MailPresence;
use crate::mail_pack::state::MailStage;
use crate::mail_pack::wire::MailAttachmentRef;
use serde::Deserialize;
use serde::Serialize;

/// `vault.mail.inbox`'s input.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MailInboxRequest {
    /// One source only, 32-hex; every source the reader reads when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_ref: Option<String>,
    /// Lists messages deleted at the provider and kept, labelled, too.
    #[serde(default)]
    pub include_source_deleted: bool,
    /// Only the messages after this place in the newest-first order: the
    /// previous page's `next_cursor`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

/// One message as the inbox lists it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MailInboxItem {
    pub source_ref: String,
    /// The thread's CONVERSATION, 32-hex.
    pub thread_ref: String,
    /// The message's TURN, 32-hex.
    pub turn_ref: String,
    /// The message's latest revision, 32-hex.
    pub message_ref: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    pub received_at: u64,
    pub labels: Vec<String>,
    pub stage: MailStage,
    pub presence: MailPresence,
    /// Whether the reader reads it through a share of its thread, not as a
    /// reader of its source.
    pub shared_with_reader: bool,
    /// Its attachments, described; `vault.mail.attachments.open` fetches one.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attachments: Vec<MailAttachmentRef>,
}

/// One inbox page, newest first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MailInboxPage {
    pub items: Vec<MailInboxItem>,
    /// The `cursor` of the next page; absent on the last.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// `vault.mail.threads.read`'s input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MailThreadRequest {
    /// The thread's CONVERSATION, 32-hex.
    pub thread_ref: String,
}

/// One thread's messages, oldest first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MailThreadView {
    pub thread_ref: String,
    pub source_ref: String,
    pub messages: Vec<MailInboxItem>,
    /// The people the thread is shared with, 32-hex, to readers of its
    /// source.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub shared_with: Vec<String>,
}
