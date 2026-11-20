//! A rung's daily hours on its seat's walk (UNBUILT-14; RULING
//! UNBUILT14-BATCH-MODEL-PICK = A): inside them the walk tries the rung
//! before the rungs that keep none, and outside them it passes the rung at
//! once, never waiting for them to open. A picked ladder, the one model a
//! caller or the owner's manifest named, is no walk: its rung serves at any
//! hour.
use super::*;

impl OfferLadder {
    /// Now, for the walk's hours: on the clock rests are kept on, else the
    /// wall clock. `None` when this ladder is picked or no rung keeps hours.
    fn hours_now(&self) -> Option<u64> {
        if self.picked || self.rungs.iter().all(|rung| rung.hours.is_none()) {
            return None;
        }
        Some(
            self.rests
                .now()
                .unwrap_or_else(oneiron_base::unix_seconds_now),
        )
    }

    /// The order the walk tries this ladder's rungs: each one inside its
    /// hours first, then the others, each part in ladder order. A rung
    /// outside its hours is among the others, where [`Self::outside_hours`]
    /// passes it.
    pub(super) fn walk_order(&self) -> impl Iterator<Item = usize> {
        let now = self.hours_now();
        let inside = move |index: &usize| {
            now.is_some_and(|now| {
                self.rungs[*index]
                    .hours
                    .as_ref()
                    .is_some_and(|hours| hours.contains(now))
            })
        };
        let all = 0..self.rungs.len();
        all.clone()
            .filter(inside)
            .chain(all.filter(move |index| !inside(index)))
    }

    /// Whether the walk passes the rung at `index` for its hours: it keeps
    /// hours, this ladder is no pick, and now is outside them.
    pub(super) fn outside_hours(&self, index: usize) -> bool {
        self.rungs[index]
            .hours
            .as_ref()
            .is_some_and(|hours| self.hours_now().is_some_and(|now| !hours.contains(now)))
    }

    /// The end of a call that met no failure and passed rungs for their
    /// hours: no rung serves at this hour, with when the first of those
    /// rungs' hours opens. Such a walk ends here when the rungs that keep no
    /// hours are gone, such as one whose provider was unavailable when the
    /// runtime was built. `None` when the walk passed no rung for its hours.
    pub(super) fn outside_hours_refusal(&self, walk: &Walk) -> Option<LlmError> {
        let now = self.hours_now()?;
        let mut passed = walk
            .passed
            .iter()
            .filter(|(_, passed)| matches!(passed, Passed::OutsideHours))
            .peekable();
        passed.peek()?;
        let opens = passed
            .filter_map(|(index, _)| self.rungs[*index].hours.as_ref()?.next_open(now))
            .min();
        Some(
            RetryableLlmError::OutsideHours {
                retry_after: opens.map(|at| at.saturating_sub(now)),
                resets_at: opens.into_iter().collect(),
            }
            .into(),
        )
    }
}
