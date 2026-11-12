//! Moved from `crates/oneiron/src/mail_pack/state.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::mail_pack::source::MailCopySetting;
use crate::mail_pack::wire::MailAttachmentRef;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// How much of a message has landed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MailStage {
    /// Its headers: it is searchable by sender, recipients and subject.
    Headers,
    /// Its body too.
    Body,
}

/// Whether the provider still holds a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MailPresence {
    Present,
    /// Deleted at the provider, kept as a labelled source-deleted copy (the
    /// source's "keep in memory" setting): out of the live inbox, still in
    /// the vault.
    SourceDeleted {
        at: u64,
    },
    /// Deleted at the provider and forgotten in the vault too (the source's
    /// "forget too" setting). The row stays as a fence: a later listing does
    /// not bring the message back.
    Forgotten {
        at: u64,
    },
}

/// One source's import, as its readers see it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MailSyncStatusView {
    pub source_ref: String,
    /// Whether the change feed has an anchor: new mail arrives live.
    pub live: bool,
    /// Whether the newest-first copy reached the oldest message it keeps.
    pub copy_done: bool,
    pub landed: u64,
    pub bodies: u64,
    /// Messages waiting for their bodies.
    pub bodies_waiting: u64,
    pub deleted_at_provider: u64,
    /// Messages deleted at the provider and kept whose claims wait to be
    /// checked again (FIX 15414).
    pub claim_rechecks_pending: u64,
    /// Those whose claims were checked again: each stands, or the Dreamer
    /// moved it down its demotion ladder.
    pub claim_rechecks_checked: u64,
    /// Those with a claim whose check waits for the owner's review.
    pub claim_rechecks_review_needed: u64,
    /// Checks a restore, a later delete or an erase of the message made
    /// moot.
    pub claim_rechecks_obsolete: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_step_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}
