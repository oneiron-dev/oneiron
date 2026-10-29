//! When a reach-out whose draft failed is drafted again (FIX 9465). A draft
//! that failed over inputs that did not move is tried again after a wait
//! that doubles with each further failure in a row, up to a ceiling, with
//! no vault write needed to wake it. It is never given up on: it stays
//! pending and owed. Any change of its inputs, or a draft that lands,
//! resets its wait. The pace is kept in memory: a restart drafts each
//! pending reach-out at once. A provider recovery ends every wait at once.
use std::collections::{HashMap, HashSet};
use std::time::Duration;

use oneiron::EntityId;
use oneiron::dreamer_runner::maintenance::stewardship::StewardshipDraftRequest;
use tokio::time::Instant;

/// How long a reach-out whose draft failed over the same inputs waits
/// before its next try: `first` after one failure, doubled after each
/// further failure in a row, never more than `ceiling`. One policy for the
/// owner to change here; it limits no tries and ends no reach-out.
pub(super) struct RetryPace {
    first: Duration,
    ceiling: Duration,
}

/// Today's pace: one round's settle after the first failure, doubling, up
/// to an hour.
pub(super) const DRAFT_RETRY_PACE: RetryPace = RetryPace {
    first: super::SETTLE,
    ceiling: Duration::from_secs(60 * 60),
};

impl RetryPace {
    /// The wait after `failures` failures in a row, one at least:
    /// `first` × 2^(failures − 1), up to `ceiling`.
    fn wait(&self, failures: u32) -> Duration {
        let doublings = failures.saturating_sub(1).min(31);
        self.first
            .saturating_mul(1_u32 << doublings)
            .min(self.ceiling)
    }
}

/// One reach-out's failures in a row over the same inputs.
struct Owed {
    input: StewardshipDraftRequest,
    failures: u32,
    due: Instant,
}

/// The reach-outs whose drafts failed, by proposal, and when each is due.
#[derive(Default)]
pub(super) struct Pace(HashMap<EntityId, Owed>);

impl Pace {
    /// Whether `draft` is due now: it never failed, its inputs changed
    /// since it did (which resets its wait), or its wait is over.
    pub(super) fn due(&mut self, draft: &StewardshipDraftRequest) -> bool {
        let Some(owed) = self.0.get(&draft.proposal) else {
            return true;
        };
        if owed.input == *draft {
            return Instant::now() >= owed.due;
        }
        self.0.remove(&draft.proposal);
        true
    }

    /// Records one more failure over `input`: the wait until its next try.
    pub(super) fn failed(&mut self, input: StewardshipDraftRequest) -> Duration {
        let failures = match self.0.get(&input.proposal) {
            Some(owed) if owed.input == input => owed.failures.saturating_add(1),
            _ => 1,
        };
        let wait = DRAFT_RETRY_PACE.wait(failures);
        self.0.insert(
            input.proposal,
            Owed {
                input,
                failures,
                due: Instant::now() + wait,
            },
        );
        wait
    }

    /// A provider recovery ends every wait at once; counts and inputs stay.
    pub(super) fn wake_all(&mut self) {
        let now = Instant::now();
        for owed in self.0.values_mut() {
            owed.due = now;
        }
    }

    /// A reach-out drafted, or no longer asking for one: its wait goes.
    pub(super) fn clear(&mut self, proposal: EntityId) {
        self.0.remove(&proposal);
    }

    /// Keeps the waits of the reach-outs in `seen` only, after a round read
    /// the whole index.
    pub(super) fn retain(&mut self, seen: &HashSet<EntityId>) {
        self.0.retain(|proposal, _| seen.contains(proposal));
    }

    /// When the earliest wait ends; `None` with none.
    pub(super) fn next_due(&self) -> Option<Instant> {
        self.0.values().map(|owed| owed.due).min()
    }
}
