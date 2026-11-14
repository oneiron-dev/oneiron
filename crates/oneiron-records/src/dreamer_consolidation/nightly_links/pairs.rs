//! Moved from `crates/oneiron/src/dreamer_consolidation/nightly_links/pairs.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_store::model_decision::DecisionAnswer;
use oneiron_wake_contract::dreamer_consolidation::provenance::KeptDecision;
use serde::Deserialize;
use serde::Serialize;

/// What one link question decided about its pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NightlyLinkVerdict {
    /// The two state the same thing: a proposed SameAs status claim is
    /// written, never an applied edge.
    SameAs,
    /// The two state different things.
    NoLink,
    /// Not settled: the reader said so, abstained, or has not answered.
    Unresolved,
}

impl NightlyLinkVerdict {
    /// Every verdict, in the order a question offers them.
    pub const ALL: [Self; 3] = [Self::SameAs, Self::NoLink, Self::Unresolved];

    /// The verdict as its question offers it.
    const fn option(self) -> &'static str {
        match self {
            Self::SameAs => "same_as",
            Self::NoLink => "no_link",
            Self::Unresolved => "unresolved",
        }
    }

    /// The verdict `decision` gives: the option it answers. An abstention,
    /// an answer still waiting, or any other answer leaves the pair
    /// unresolved.
    pub fn of(decision: &KeptDecision) -> Self {
        match decision.answer() {
            Some(DecisionAnswer::Choice(option)) => Self::ALL
                .into_iter()
                .find(|verdict| verdict.option() == option.as_str())
                .unwrap_or(Self::Unresolved),
            _ => Self::Unresolved,
        }
    }
}
