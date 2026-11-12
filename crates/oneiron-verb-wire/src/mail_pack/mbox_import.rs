//! Moved from `crates/oneiron/src/mail_pack/mbox_import.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::mail_pack::source::MailCopySetting;
use crate::mail_pack::source::MailProvider;
use crate::mail_pack::source::MailSourceKind;
use crate::mail_pack::source::MailSourceStatus;
use crate::mail_pack::state::MailPresence;
use crate::mail_pack::state::MailStage;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::memory::MemoryError;
use oneiron_contracts::memory::MemoryResult;
use serde::Deserialize;
use serde::Serialize;
use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::path::Path;

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
}

/// What one import call did.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MailMboxImportReport {
    pub source_ref: String,
    /// Messages that landed.
    pub landed: u64,
    /// Messages the vault held whole already, or forgot.
    pub same: u64,
    /// Messages refused (no Gmail id, or refused by the write door), with
    /// why.
    pub refused: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub refusal_reasons: Vec<String>,
    /// Messages left out: trash, spam, drafts, chats, older than the copy
    /// setting keeps, or larger than this host reads.
    pub skipped: u64,
    /// Messages read from this file over every call so far.
    pub read_total: u64,
    /// Whether the whole file has been read.
    pub done: bool,
}

impl MailMboxImportReport {
    fn refuse(&mut self, reason: String) {
        self.refused += 1;
        if self.refusal_reasons.len() < MAX_REASONS {
            self.refusal_reasons.push(reason);
        }
    }
}
