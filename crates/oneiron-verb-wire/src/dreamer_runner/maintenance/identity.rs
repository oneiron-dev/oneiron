//! Moved from `crates/oneiron/src/dreamer_runner/maintenance/identity.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::dreamer_runner::maintenance::identity::evidence::IdentityAnswerEvidenceRequest;
pub use crate::dreamer_runner::maintenance::identity::evidence::IdentityMentionState;
pub use crate::dreamer_runner::maintenance::identity::evidence::IdentityMentionView;
pub use crate::dreamer_runner::maintenance::identity::evidence::IdentityResolutionView;
use serde::Deserialize;
use serde::Serialize;

/// What an agent must do to the person now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum IdentityEffect {
    Send,
    Pay,
    Invite,
    Share,
}

/// A settled ask.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct IdentitySettled {
    pub ask: String,
    /// The entity the mention names, as 32 hex.
    pub entity: String,
}

/// `self.identity.answer`'s input: the person's choice on one ask.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IdentityAnswerRequest {
    /// The ask, as 64 hex.
    pub ask: String,
    /// One of the ask's options: `is:<id>` or `someone_new`.
    pub choice: String,
}

/// `self.identity.settle`'s input: an agent about to act on a person it
/// knows by the name a conversation used.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IdentityActNowRequest {
    /// The name as the conversation said it.
    pub name: String,
    /// The conversation it was said in, as 32 hex; any when absent.
    #[serde(default)]
    pub conversation: Option<String>,
    pub effect: IdentityEffect,
    /// The choice card's question, in the person's language.
    pub prompt: String,
    /// The choice card's label for someone new, in the person's language.
    pub someone_new: String,
    /// A provisional candidate's label template: `{name}` takes its name
    /// and `{day}` the day it was first said. None keeps `{name} · {day}`.
    #[serde(default)]
    pub provisional: Option<String>,
}

/// Where a name an agent must act on stands.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum IdentityActNow {
    /// The name settles to this entity: act on it.
    Settled { entity: String },
    /// No saved mention names it: there is nothing to settle against.
    Unknown,
    /// The host is deciding: ask again shortly, and do not act yet.
    Deciding { ask: String },
    /// The person must choose: show the card, and act only on their answer.
    NeedsPerson {
        ask: String,
        card: serde_json::Value,
    },
}

/// Where an effect's person target came from: one saved mention (OF-123
/// act-now guard). An effect door that carries it refuses while the mention
/// is unsettled ([`mention_unsettled_in_txn`]), and the agent settles it
/// through `self.identity.settle` first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MentionProvenance {
    /// The turn whose tags hold the mention, as 32 hex.
    pub turn: String,
    /// The message the mention is in, as 32 hex.
    pub message: String,
    /// The mention's byte span in the message text.
    pub start: u64,
    pub end: u64,
}
pub mod evidence;
