//! Moved from `crates/oneiron/src/inbox/restore_group.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// One owner restore's claims that still wait for the owner's word.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RestoreInboxGroup {
    /// The restore receipt's gate id (32 hex): the group's key.
    pub group_key: String,
    /// The restore receipt (`gate:<hex>`), readable through `vault.receipts`.
    pub receipt_ref: String,
    /// When the owner restored the archive.
    pub created_at: u64,
    /// The source vault id the restored archive names; absent when it names none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_vault: Option<String>,
    /// The restored claims still open: Proposed and Active.
    pub open_members: u64,
    /// The open members whose approval would supersede a live head. Accept-all
    /// leaves them waiting, for the owner to settle one by one.
    pub replaces_live_head: u64,
}

/// What became of one member of a restore group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RestoreMemberVerdict {
    /// The owner's approval landed: the claim reads as approved and is recalled.
    Landed,
    /// The owner rejected it: it is retracted, and its record is kept.
    Rejected,
    /// It still waits for the owner's word.
    Waiting,
}

/// Why a member of a restore group still waits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RestoreMemberWait {
    /// Review-each: the owner settles it with `vault.claims.review` and
    /// `vault.claims.settle`.
    ReviewEach,
    /// Its approval would supersede the live head `replaces_ref` names, so the
    /// owner settles it alone: an archived value never replaces a newer one in
    /// one click.
    ReplacesLiveHead,
    /// The owner opened it, and the actor that opened a proposal never settles it.
    OpenedByOwner,
    /// The gate refused or held the owner's answer; `detail` says why.
    Refused,
}

/// One member of a restore group after the owner's answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RestoreMemberOutcome {
    /// The restored claim (32 hex).
    pub claim_ref: String,
    pub verdict: RestoreMemberVerdict,
    /// Its own Settlement receipt (`gate:<hex>`), when it settled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_ref: Option<String>,
    /// Why it still waits, when it does.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub waiting: Option<RestoreMemberWait>,
    /// The live head its approval would supersede (32 hex), when one stands.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replaces_ref: Option<String>,
    /// One human line on a refusal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// The owner's answer to one restore group.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RestoreInboxResolution {
    /// The restore receipt's gate id (32 hex).
    pub group_key: String,
    /// The act's one bundle receipt (`gate:<hex>`, a proposal outcome), when a
    /// member settled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_ref: Option<String>,
    /// Each member the answer read, newest first.
    pub members: Vec<RestoreMemberOutcome>,
    /// The `vault.runs.revert` handle (`run:restore:<hex>`), which takes back all
    /// of the settled members or any part of them, when a member settled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revert_handle: Option<String>,
    /// The work still owed after the answer committed (FIX 7600); empty when
    /// none is.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<crate::memory::claims::settle::SettleWarning>,
}
