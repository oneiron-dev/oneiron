//! Moved from `crates/oneiron/src/code_run/contribution/source_admission.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use oneiron_verb_wire::claim::learning_evidence::Anchor;

/// Who reads a contribution pair's processed source (FIX 20607).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContributionSourceConsumer {
    /// The held-out judge's question, asked under `principal`, the judge's
    /// own principal.
    HeldOutJudge { principal: EntityId },
    /// The completed audit's frozen judge. The Coach asks it and pays.
    Audit,
    /// The vault owner the pair's question asks.
    OwnerReview,
}

/// Why the consumer reads the pair's processed source (FIX 20607).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContributionSourcePurpose {
    /// A model scores each fork against the pair's frozen rubric.
    ForkScoring,
    /// The owner reads both blinded answers and judges them.
    OwnerVerdict,
}

/// What a host declares before a pair reads any of its source (FIX 20607):
/// the consumer and the purpose. These are facts. They admit no read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContributionSourceReadRequest {
    pub consumer: ContributionSourceConsumer,
    pub purpose: ContributionSourcePurpose,
}

impl ContributionSourceReadRequest {
    /// Whether `anchor`'s pair reads under this request: an owner verdict's
    /// for owner review, an audit's for the audit's judge, and any other's
    /// for the held-out judge, each for its own purpose.
    pub const fn fits(&self, anchor: &Anchor) -> bool {
        use ContributionSourceConsumer as Consumer;
        use ContributionSourcePurpose as Purpose;
        match anchor {
            Anchor::OwnerVerdict => matches!(
                (self.consumer, self.purpose),
                (Consumer::OwnerReview, Purpose::OwnerVerdict)
            ),
            Anchor::Audit { .. } => matches!(
                (self.consumer, self.purpose),
                (Consumer::Audit, Purpose::ForkScoring)
            ),
            _ => matches!(
                (self.consumer, self.purpose),
                (Consumer::HeldOutJudge { .. }, Purpose::ForkScoring)
            ),
        }
    }
}

/// Who a read of a pair's source is for (FIX 20607).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairReader {
    /// The Coach, while it prepares, generates and runs the pair's forks.
    Coach,
    /// The pair's consumer. `owner` is the owner an owner review asks.
    Consumer { owner: Option<EntityId> },
}
