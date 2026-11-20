//! Moved from `crates/oneiron/src/mail_pack/mbox_import.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// The most refusal reasons one report lists.
pub const MAX_REASONS: usize = 20;

/// `vault.mail.sources.import_mbox`'s input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MailMboxImportRequest {
    /// The mailbox source, 32-hex.
    pub source_ref: String,
    /// The mbox file, or a Google Takeout `.zip` holding mbox files, on this
    /// device: an absolute path.
    pub path: String,
    /// The messages this call reads; 500 when absent, at most 5,000.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub messages: Option<u32>,
    /// The most entries a `.zip` may declare; past it the archive is refused
    /// before its entry list is read, and the refusal names this field.
    /// 262,144 when absent: the owner raises it to import a larger archive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archive_max_entries: Option<u64>,
}
