//! Moved from `crates/oneiron/src/mail_pack/reply.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// Where one drafted reply stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MailReplyDraftState {
    /// Drafted, waiting for the owner's approval of this revision.
    Proposed,
    /// Approved; its send was dispatched and its outcome is not known yet,
    /// or the send was held: approving it again dispatches it again, and the
    /// ledger replays what it already recorded.
    Approved,
    /// The provider accepted the send.
    Sent,
    /// The dispatch failed, or its outcome is uncertain: the ledger holds it,
    /// and nothing sends it again by itself.
    Unsettled,
    /// Discarded by its drafter or the owner; it never sends.
    Discarded,
}

/// `vault.mail.reply.draft`'s input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MailReplyDraftRequest {
    /// The thread's CONVERSATION, 32-hex.
    pub thread_ref: String,
    /// The message answered, by its TURN, 32-hex; the thread's newest
    /// message this mailbox did not send when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_turn_ref: Option<String>,
    /// The reply's plain text: the whole reply for a reader without HTML.
    pub body: String,
    /// The reply as HTML, sent beside the text as its alternative: text,
    /// links (`http`, `https`, `mailto`), paragraphs, line breaks, headings,
    /// lists, quotes, code and simple emphasis, with `dir` and `lang`. Any
    /// other element or attribute is refused, not dropped; no image, style or
    /// script is sent. At most 256 KiB.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body_html: Option<String>,
    /// Replies to all: the answered message's own To and Cc recipients
    /// receive the reply too, in their roles, beside its `Reply-To` (else its
    /// sender). The mailbox's own address never does.
    #[serde(default)]
    pub reply_all: bool,
    /// More recipients in Cc, each one bare address (`name@example.com`). A
    /// list's address is one recipient; no group is expanded. To, Cc and
    /// these together name at most 50 recipients; more is refused, not cut.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cc: Vec<String>,
    /// The caller's key for this draft: the same key with the same body and
    /// recipients is the same draft; with others, its next revision.
    pub request_key: String,
}

/// One draft, as its readers see it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MailReplyDraftView {
    /// 32-hex.
    pub draft_ref: String,
    pub revision: u64,
    pub source_ref: String,
    pub thread_ref: String,
    pub parent_turn_ref: String,
    /// Every To recipient, in its place: the answered message's `Reply-To`
    /// (else its sender) first.
    pub to: Vec<String>,
    /// Every Cc recipient, in its place (fix list row 17645).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cc: Vec<String>,
    pub subject: String,
    pub body: String,
    /// The HTML alternative that sends beside the text, exactly as it
    /// sends; show it inert (fix list row 17645).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body_html: Option<String>,
    /// The frozen send plan the owner approves, exactly.
    pub plan_ref: String,
    pub state: MailReplyDraftState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<String>,
    pub drafted_at: u64,
    pub updated_at: u64,
}

/// One draft named: by its ref.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MailReplyDraftRef {
    /// 32-hex.
    pub draft_ref: String,
}

/// `vault.mail.reply.approve`'s input: the draft and the revision the owner
/// reviewed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MailReplyApproveRequest {
    /// 32-hex.
    pub draft_ref: String,
    pub revision: u64,
}

/// `vault.mail.reply.drafts`' input.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MailReplyDraftsRequest {
    /// One thread only, 32-hex; every thread the reader reads when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thread_ref: Option<String>,
    /// Lists sent and discarded drafts too.
    #[serde(default)]
    pub include_settled: bool,
}

/// The drafts a reader reads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MailReplyDraftPage {
    pub drafts: Vec<MailReplyDraftView>,
}
