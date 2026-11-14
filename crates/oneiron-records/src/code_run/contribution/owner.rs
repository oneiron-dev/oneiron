//! Moved from `crates/oneiron/src/code_run/contribution/owner.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// The owner's word that scored both forks of a pair (FIX 3609): the ask
/// that carried the pair's question, the counted word that settled it, and
/// the question digest and revision it answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnerJudgment {
    pub ask: EntityId,
    pub word: EntityId,
    pub question_digest: [u8; 32],
    pub revision: u64,
    /// Unix seconds the ask settled.
    pub at: u64,
}

/// What the owner may answer about a pair's two shown answers, by stable
/// option id. Each answer is judged on its own against the one criterion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerPairChoice {
    AOnly,
    BOnly,
    Both,
    Neither,
    CannotJudge,
}

impl OwnerPairChoice {
    pub const ALL: [Self; 5] = [
        Self::AOnly,
        Self::BOnly,
        Self::Both,
        Self::Neither,
        Self::CannotJudge,
    ];

    /// Its stable option id.
    pub const fn option(self) -> &'static str {
        match self {
            Self::AOnly => "a_only",
            Self::BOnly => "b_only",
            Self::Both => "both",
            Self::Neither => "neither",
            Self::CannotJudge => "cannot_judge",
        }
    }

    /// The label its option shows.
    pub const fn label(self) -> &'static str {
        match self {
            Self::AOnly => "Only answer A passes",
            Self::BOnly => "Only answer B passes",
            Self::Both => "Both answers pass",
            Self::Neither => "Neither answer passes",
            Self::CannotJudge => "I cannot judge these answers",
        }
    }

    /// The choice an option id names.
    pub fn of_option(option: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|choice| choice.option() == option)
    }

    /// Whether answer A, then answer B, passed; `None` for "cannot judge".
    const fn shown(self) -> Option<(bool, bool)> {
        match self {
            Self::AOnly => Some((true, false)),
            Self::BOnly => Some((false, true)),
            Self::Both => Some((true, true)),
            Self::Neither => Some((false, false)),
            Self::CannotJudge => None,
        }
    }
}

/// Where a pending pair's question stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnerPairRoute {
    /// Kept, with its ids reserved; no ask carries it yet.
    Reserved,
    /// The ask that carries it, at the revision and question digest it was
    /// admitted with.
    Asked {
        ask: EntityId,
        revision: u64,
        question_digest: [u8; 32],
    },
    /// The owner's word was admitted, but a temporary subject fence, or a
    /// source admission that lapsed (FIX 20607), kept it from scoring the
    /// forks. Its judgment carries the ask and time.
    Accepted {
        with_passed: bool,
        without_passed: bool,
        judgment: OwnerJudgment,
    },
    /// The owner's word scored both forks.
    Judged(OwnerJudgment),
    /// Its ask settled with no score: "cannot judge", no owner's word, a
    /// fallback, a stale ask or an answer that no longer reads.
    Closed { ask: EntityId, at: u64 },
}
