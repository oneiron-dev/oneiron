//! Moved from `crates/oneiron/src/feeds/mod.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::runtime_hooks::source::FactPosition;
use oneiron_base::error::Error;
use oneiron_contracts::entity_id::EntityId;
use oneiron_store::ports::records::ChangeOp;
use serde::Deserialize;
use serde::Serialize;

/// A position in one source. Two positions compare only within one source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Position {
    /// A change log or settlement feed position: the hooks' own.
    Fact(FactPosition),
    /// An edge feed sequence.
    Edges(u64),
    /// A redirty feed sequence.
    Redirty(u64),
}

/// What an entry says happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FeedEntryKind {
    /// An entity was created or written again: a create, an update, a supersession, a merge or
    /// a tier move.
    Edit,
    /// An entity was deleted, redacted or forgotten: a source anything derived from it stands on
    /// is withdrawn.
    Withdrawal,
    /// A proposal was settled.
    Settlement,
    /// An edge was added or removed.
    Edge,
    /// A TURN's words changed with no new version of its own: what was derived from them is
    /// due again.
    Redirty,
}

/// The write behind an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FeedOp {
    Create,
    Update,
    Supersede,
    Merge,
    TierTransition,
    Delete,
    Redact,
    Forget,
    Settle,
    EdgeAdded,
    EdgeRemoved,
    Redirty,
}

impl FeedOp {
    const fn of_change(op: ChangeOp) -> Self {
        match op {
            ChangeOp::Create => Self::Create,
            ChangeOp::Update => Self::Update,
            ChangeOp::Supersede => Self::Supersede,
            ChangeOp::Merge => Self::Merge,
            ChangeOp::TierTransition => Self::TierTransition,
            ChangeOp::Delete => Self::Delete,
            ChangeOp::Redact => Self::Redact,
            ChangeOp::Forget => Self::Forget,
        }
    }

    const fn kind(self) -> FeedEntryKind {
        match self {
            Self::Create | Self::Update | Self::Supersede | Self::Merge | Self::TierTransition => {
                FeedEntryKind::Edit
            }
            Self::Delete | Self::Redact | Self::Forget => FeedEntryKind::Withdrawal,
            Self::Settle => FeedEntryKind::Settlement,
            Self::EdgeAdded | Self::EdgeRemoved => FeedEntryKind::Edge,
            Self::Redirty => FeedEntryKind::Redirty,
        }
    }
}

/// Where a new subscription starts.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum FeedStart {
    /// After everything committed so far.
    #[default]
    Head,
    /// Before the oldest row each source still holds.
    Beginning,
}

/// A request to read a subscription's next page.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FeedReadRequest {
    #[serde(with = "oneiron_contracts::serialize::entity_ref")]
    #[schemars(with = "String")]
    pub subscription: EntityId,
    /// Entries to return from each source, at most [`FEED_READ_MAX_LIMIT`];
    /// [`FEED_READ_DEFAULT_LIMIT`] when absent.
    #[serde(default)]
    pub limit: Option<usize>,
}

/// An edge an entry names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FeedEdge {
    #[serde(with = "oneiron_contracts::serialize::entity_ref")]
    #[schemars(with = "String")]
    pub source: EntityId,
    /// The edge kind's snake_case name.
    pub kind: String,
    #[serde(with = "oneiron_contracts::serialize::entity_ref")]
    #[schemars(with = "String")]
    pub target: EntityId,
}

/// The typed gap answer: resync, then rebuild from a snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FeedGap {
    pub resync_from: FeedResyncFrom,
}

/// Where a reader past a gap rebuilds what it follows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FeedResyncFrom {
    /// A snapshot read of the vault, taken after [`Vault::feed_resync`].
    Snapshot,
}

/// A request naming one of the caller's subscriptions: to end it, or to resync it past a gap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FeedSubscriptionRequest {
    #[serde(with = "oneiron_contracts::serialize::entity_ref")]
    #[schemars(with = "String")]
    pub subscription: EntityId,
}

pub fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(reason.to_owned())
}
