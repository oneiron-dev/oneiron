//! Moved from `crates/oneiron/src/mail_pack/compliance.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// What one compliance log entry records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MailComplianceEventKind {
    Enabled,
    Disabled,
    /// One search across mailboxes, made while the setting was on.
    Search,
}

/// The setting as anyone in the vault reads it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MailComplianceSettingView {
    pub enabled: bool,
    /// Who last changed it, 32-hex; absent if it was never set, or once that
    /// actor was erased.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub set_by_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub set_at: Option<u64>,
}

/// `vault.mail.compliance.set`'s input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MailComplianceSetRequest {
    pub enabled: bool,
    /// Why, in the setter's words; kept in the compliance log.
    pub purpose: String,
}

/// One compliance log entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MailComplianceEventView {
    pub sequence: u64,
    pub kind: MailComplianceEventKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by_ref: Option<String>,
    pub at: u64,
    pub purpose: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_count: Option<u64>,
}

/// `vault.mail.compliance.search`'s input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MailComplianceSearchRequest {
    /// The words searched; the log keeps their BLAKE3, not the words.
    pub query: String,
    /// Why, in the searcher's words; kept in the compliance log.
    pub purpose: String,
    /// How many messages at most; 50 when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

/// One message a compliance search found, across mailboxes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MailComplianceHit {
    pub source_ref: String,
    pub thread_ref: String,
    pub message_ref: String,
    pub score: f32,
    /// The message's words as the vault holds them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
}

/// What a compliance search answered, after its log entry was kept.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MailComplianceSearchReply {
    /// The compliance log entry this search wrote before answering.
    pub log_sequence: u64,
    pub hits: Vec<MailComplianceHit>,
}
