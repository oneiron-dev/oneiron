//! The rows a Coach answer on an agent-health card was drafted from (FIX
//! 9220). The brief's numbers are review state that names no rows, so the
//! brief's own source set stays unknown (FIX 6997); the rows it is known to
//! read are kept beside it, frozen with the answer: the agent and its TASK,
//! the skills its run loaded and that run, the observed brief's TASK or the
//! CLAIM its text came from, the pad read's row and each pad it returned. An
//! erase of any of them clears the draft's text (`erase.rs`), on the live
//! card and on a saved Weave copy alike.
use std::collections::BTreeSet;

use super::AgentHealthCard;
use super::ask::{AgentHealthCoachAnswer, AgentHealthPadRead};
use crate::EntityId;

/// Every row the Coach's brief for `card` is known to read: the agent and
/// its TASK, each of `parts` and the pad read's row and pads, sorted and
/// deduplicated. The numbers that name no row add none.
pub(super) fn known_source_rows(
    card: &AgentHealthCard,
    pads: &AgentHealthPadRead,
    parts: [&[EntityId]; 4],
) -> Vec<EntityId> {
    let mut rows = BTreeSet::from([card.subject]);
    rows.extend(card.task);
    for part in parts {
        rows.extend(part.iter().copied());
    }
    rows.extend(pad_rows(pads));
    rows.into_iter().collect()
}

/// A granted pad read's row and the pads it returned; none for another read.
fn pad_rows(pads: &AgentHealthPadRead) -> Vec<EntityId> {
    match pads {
        AgentHealthPadRead::Read { read, pad_ids, .. } => {
            read.iter().chain(pad_ids).copied().collect()
        }
        _ => Vec::new(),
    }
}

impl AgentHealthCoachAnswer {
    /// The rows this answer names as read: its frozen `source_rows`, none
    /// from them when it predates them, and its pad read's row and pads.
    pub(crate) fn known_sources(&self) -> BTreeSet<EntityId> {
        let mut rows: BTreeSet<EntityId> = self.source_rows.iter().flatten().copied().collect();
        rows.extend(pad_rows(&self.pads));
        rows
    }
}

impl AgentHealthCard {
    /// The rows this card's standing Coach draft was written from: its
    /// answer's known sources, the agent, its TASK and each pinned brief's
    /// TASK. Empty while the card holds no draft, and once an erase cleared
    /// the draft's text.
    pub(crate) fn draft_source_rows(&self) -> BTreeSet<EntityId> {
        let Some(ask) = self.coach.as_ref() else {
            return BTreeSet::new();
        };
        let Some(answer) = ask
            .answer
            .as_ref()
            .filter(|answer| answer.draft.is_some() && answer.draft_erased != Some(true))
        else {
            return BTreeSet::new();
        };
        let mut rows = answer.known_sources();
        rows.insert(self.subject);
        rows.extend(self.task);
        rows.extend(self.observed_brief.as_ref().map(|pin| pin.task));
        rows.extend(ask.observed_brief.as_ref().map(|pin| pin.task));
        rows
    }
}
