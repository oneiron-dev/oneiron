//! Each origin mirror's sync strategy (FIX 6866; owner ruling 10-21 06:3x).
//!
//! A mirror carries one strategy, never a public or private flag:
//! - [`OriginMirrorSyncStrategy::AskMe`]: nothing goes out until the owner or
//!   a Grant holder approves an exact ref and commit, pushed once
//!   (`origin::publish`). The scheduler never pushes such a mirror, and a
//!   push-now refuses with [`PublishRequestRequired`].
//! - [`OriginMirrorSyncStrategy::Schedule`]: the scheduled push of every
//!   published ref at the mirror's cadence, and push-now: the same refs,
//!   forced, with deletions, in the same batches (FIX 6866 part 2 adds the
//!   frozen review, the leases and the reconcile before any resend).
//! - [`OriginMirrorSyncStrategy::FullAuto`]: each new green head goes out
//!   as soon as the published refs move (`mirror_auto`), with no waiting.
//!
//! A mirror with no strategy set is [`ORIGIN_MIRROR_DEFAULT_SYNC_STRATEGY`]:
//! a row stored without one decodes as it. Exact publish requests do not
//! read the strategy, so changing it leaves every pending or approved
//! request as it stands.
//!
//! Only the live owner changes a strategy: through mirror setup, or through
//! [`Vault::set_served_origin_mirror_strategy_in_txn`], which changes the
//! strategy and its revision and nothing else. A change of the mirror's URL,
//! user, custody record or served name moves its target generation instead,
//! which every exact request is bound to. Either change pauses the mirror's
//! unsent automatic work in the same transaction (a switch to `ask_me`
//! sends nothing more whole; a running push settles first), and every
//! automatic batch's claim fences the strategy, revision and generation.

use serde::{Deserialize, Serialize};

use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;

/// How one mirror sends what this vault publishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OriginMirrorSyncStrategy {
    /// Nothing goes out until an exact publish request is approved; each
    /// request pushes one commit to one branch, once.
    AskMe,
    /// Every published ref (imported refs aside) is pushed at the mirror's
    /// cadence, forced, with deletions, as the scheduled mirror always did.
    Schedule,
    /// Each published ref is pushed as soon as it moves, at its newest head
    /// the merge queue proved green; other heads wait for checks.
    FullAuto,
}

/// The strategy of a mirror that names none (CALLS "FIX 6866 sync
/// strategy"): ask first.
pub const ORIGIN_MIRROR_DEFAULT_SYNC_STRATEGY: OriginMirrorSyncStrategy =
    OriginMirrorSyncStrategy::AskMe;

impl Default for OriginMirrorSyncStrategy {
    fn default() -> Self {
        ORIGIN_MIRROR_DEFAULT_SYNC_STRATEGY
    }
}

impl OriginMirrorSyncStrategy {
    /// Whether the scheduler pushes the mirror when its cadence comes due.
    #[must_use]
    pub const fn runs_on_interval(self) -> bool {
        matches!(self, Self::Schedule)
    }

    /// Whether the mirror is pushed whole, by its own standing authority:
    /// on its cadence or its events, and by a push-now (a full-auto
    /// push-now still sends green heads only).
    #[must_use]
    pub const fn pushes_whole_refs(self) -> bool {
        matches!(self, Self::Schedule | Self::FullAuto)
    }

    /// The wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AskMe => "ask_me",
            Self::Schedule => "schedule",
            Self::FullAuto => "full_auto",
        }
    }
}

/// The stable code a push-now on an ask-me mirror refuses with.
pub const ORIGIN_MIRROR_PUBLISH_REQUEST_REQUIRED: &str = "publish_request_required";

/// A whole-ref push asked of a mirror whose strategy asks first. It names
/// its bound: an exact publish request, or the owner's switch to schedule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishRequestRequired {
    /// The served repository.
    pub repo: String,
    /// The mirror's strategy.
    pub strategy: OriginMirrorSyncStrategy,
}

impl From<PublishRequestRequired> for Error {
    fn from(refusal: PublishRequestRequired) -> Self {
        Error::Refused(format!(
            "{ORIGIN_MIRROR_PUBLISH_REQUEST_REQUIRED}: the mirror of {} is {}, so nothing goes \
             out whole; ask for an exact ref and commit with vault.code.origin.publish.request, \
             or have the owner set its strategy to schedule or full_auto",
            refusal.repo,
            refusal.strategy.as_str()
        ))
    }
}

/// The strategy, its revision and the target generation a setup writes.
pub struct ConfiguredStrategy {
    pub strategy: OriginMirrorSyncStrategy,
    pub revision: u64,
    pub generation: Option<EntityId>,
}
