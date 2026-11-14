//! Moved from `crates/oneiron/src/verbs/disclosure.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_authority::federation::Scope;
use serde::Deserialize;
use serde::Serialize;

/// `vault.disclosure.offer`'s input: the clearance asked for one contact, the
/// owner whose answer it waits on, and when it lapses unanswered.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DisclosureOfferRequest {
    /// The CID-7 contact the clearance is for, as 32 hex.
    pub contact: String,
    /// The exact clearance Scope asked for, in the canonical six-axis form.
    #[schemars(with = "serde_json::Value")]
    pub scope: Scope,
    /// Why, 1..=512 bytes; the owner reads it.
    pub purpose: String,
    /// The channel the disclosure travels on. A tap on one channel never
    /// clears another.
    pub channel: String,
    /// The one party the disclosure reaches.
    pub beneficiary: String,
    /// The private TASK ask this offer rides, when one exists.
    #[serde(default)]
    pub ask: Option<String>,
    /// The principal ref of the owner whose answer the offer waits on.
    pub owner_ref: String,
    /// When the offer lapses unanswered, in engine seconds.
    pub expires_at: u64,
}

/// `vault.disclosure.offer`'s answer: the filed offer, by the ref the owner
/// reads and answers it under.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DisclosureOffered {
    pub proposal_ref: String,
    pub owner_ref: String,
    pub created_at: u64,
    pub expires_at: u64,
}

/// The owner's model-disclosure asks and quiet receipts, newest first.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RevealAsksRequest {
    #[serde(default)]
    pub pending: bool,
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RevealAskView {
    pub receipt: super::secret::RevealReceipt,
    pub state: String,
    pub expires_at: u64,
    pub disclosure: Option<String>,
    pub expected_digest: Option<String>,
    pub grant_ref: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RevealOutcome {
    Once,
    Standing,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RevealAnswerRequest {
    pub reveal: String,
    pub expected_digest: String,
    pub outcome: RevealOutcome,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RevealAnsweredView {
    pub reveal: String,
    pub outcome: String,
    pub receipt_ref: String,
    pub grant_ref: Option<String>,
}
