//! Moved from `crates/oneiron/src/mail_pack/state.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

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
    /// Until when the source rests, its provider quota spent for the
    /// minute or the day, or its provider having answered that its rate is
    /// spent: no step reads the provider before it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quota_paused_until: Option<u64>,
    /// How long the copy has left at its provider's pace, from the mailbox
    /// size the provider gave (ARCH-0063 #mail-copy); `None` for search
    /// only, a provider that paces nothing, or before the size is read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub copy_estimate: Option<MailCopyEstimate>,
}

/// How long a mailbox's copy has left, from the size its provider gave
/// (Gmail `users.getProfile` `messagesTotal`) and the provider's per-user
/// limits: the copy's share of the minute's quota units, and the day's
/// download bytes once the bodies read so far show their size.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MailCopyEstimate {
    /// The messages in the mailbox when the provider was last asked.
    pub messages_total: u64,
    /// When it was asked, Unix seconds.
    pub read_at: u64,
    /// Whether the copy keeps the recent months only: the provider counts
    /// the whole mailbox, so the time is at most this.
    pub at_most: bool,
    /// The seconds the copy has left: its headers and the bodies still
    /// waiting.
    pub seconds_left: u64,
    /// The limit that sets that time.
    pub bound: MailCopyBound,
}

/// The provider limit a copy's time is bound by.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MailCopyBound {
    /// The copy's share of the minute's quota units.
    Units,
    /// The day's download bytes.
    Bytes,
}
