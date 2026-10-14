//! Saving a stretch's whole talk (ARCH-0052 D5): which turns one save keeps,
//! and what a saved copy of a turn holds.
//!
//! A save keeps every turn the saver could see whole that nobody saved yet,
//! and, in a turn this stretch saved before, every message said into it
//! since (an agent's run keeps speaking into one turn). The turn's own
//! promote receipt stays as the first save wrote it; what a later save adds
//! lands through the floor's copy into a saved turn, with a receipt per
//! message (Codex burn engine-prs-30).

use std::collections::BTreeSet;

use crate::Vault;
use crate::batch::BatchOp;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::off_record::promote::PromoteInitiator;
use crate::registry::ENTITY_TYPE_MESSAGE;
use crate::session_overlay::{JournalRole, OverlaySnapshot, PromotePlan, replayed_subject};

use super::room::{
    Hearing, SavedTurns, post_notice, require_sight_in_txn, turn_put, visible, visible_message,
};
use super::session::OffRecordSession;
use super::types::OffRecordNoticeAct;

impl OffRecordSession<'_> {
    /// Saves the talk so far for `initiator` in ONE transaction that runs
    /// `authority` again and, in a room, checks that they are still there and
    /// see every moment of each turn it keeps. The room hears a `saved_talk`
    /// notice whether or not there was anything new to keep, and each turn's
    /// receipt names them.
    pub(super) fn save_talk(
        &self,
        initiator: PromoteInitiator,
        room: Option<EntityId>,
        authority: impl FnOnce(&Vault, &heed::RoTxn<'_>) -> Result<()>,
    ) -> Result<SavedTurns> {
        let by = initiator.actor();
        let windows = room.map(|room| self.vault.windows(room, by)).transpose()?;
        let saved = {
            let mut state = self.recording_state()?;
            let snapshot = self.entry.overlay.snapshot()?;
            let (mut plans, mut times, mut appended) = (Vec::new(), Vec::new(), Vec::new());
            for (turn, minted_here) in pending_turns(&snapshot) {
                let saved_before = state.record.promoted_turns.contains(turn.as_bytes());
                // A message said into a turn this stretch never saved (one
                // that is not its own) has no turn here to save it with.
                if !saved_before && !minted_here {
                    continue;
                }
                // A turn is saved whole, so only a turn whose every moment
                // the saver's membership shows is theirs to save: what of it
                // is still in the room, and what this stretch saved of it.
                let mut turn_times = turn_times(&snapshot, turn);
                if saved_before {
                    let Some(header) = self.vault.read_entity_header(&turn)? else {
                        continue;
                    };
                    turn_times.push(header.occurred_start);
                    turn_times.extend(state.kept_times(turn));
                }
                if !turn_times.iter().all(|at| visible(windows.as_deref(), *at)) {
                    continue;
                }
                // The copy holds what the room showed, as an export does: a
                // turn that showed nothing new is not saved at all.
                let plan = if saved_before {
                    append_plan(&snapshot, turn)?
                } else {
                    copy_plan(&snapshot, turn)?
                };
                if let Some(plan) = plan {
                    plans.push(plan);
                    times.extend(turn_times);
                    if saved_before {
                        appended.push(turn);
                    }
                }
            }
            drop(snapshot);
            #[cfg(test)]
            if let Some(hook) = self
                .vault
                .test_hooks()
                .after_save_plan
                .lock()
                .expect("save plan hook poisoned")
                .take()
            {
                hook();
            }
            let check = |txn: &heed::RoTxn<'_>| {
                authority(self.vault, txn)?;
                if let Some(room) = room {
                    // A saved turn's time as base holds it in this
                    // transaction: another writer may have moved it since
                    // the plan read it (Sol on engine-prs-30).
                    let mut times = times.clone();
                    for turn in &appended {
                        if let Some(header) = self.vault.entity_header_in_txn(txn, turn)? {
                            times.push(header.occurred_start);
                        }
                    }
                    require_sight_in_txn(self.vault, txn, &self.session_ref, room, by, &times)?;
                }
                Ok(Hearing::in_txn(self.vault, txn, room))
            };
            // A save that finds nothing new keeps nothing, and the room still
            // hears it, on the same checks a save that keeps something runs.
            let (saved, hearing) = if plans.is_empty() {
                (Vec::new(), check(&self.vault.store.env.read_txn()?)?)
            } else {
                self.promote_plans(&mut state, plans, &initiator, |wtxn| check(wtxn))?
            };
            post_notice(&mut state, OffRecordNoticeAct::SavedTalk, by, hearing);
            self.entry.publish_state(&state);
            saved
        };
        let turns: Vec<EntityId> = saved.iter().map(|(turn, _)| *turn).collect();
        self.refresh_promoted_turns(&turns);
        Ok(saved)
    }
}

/// Each turn the room's journal still holds something of, in the order the
/// room took them, and whether its TURN is still there too (so this stretch
/// minted it and has not saved it).
fn pending_turns(snapshot: &OverlaySnapshot) -> Vec<(EntityId, bool)> {
    let mut turns: Vec<(EntityId, bool)> = Vec::new();
    for entry in snapshot.journal_entries() {
        let turn = entry.scope.turn();
        let minted = turn_put(entry).is_some();
        let message = entry.role == JournalRole::MessagePartOf
            && matches!(&entry.op, BatchOp::Put { entity_type, .. } if *entity_type == ENTITY_TYPE_MESSAGE);
        if !minted && !message {
            continue;
        }
        match turns.iter_mut().find(|(seen, _)| *seen == turn) {
            Some((_, minted_here)) => *minted_here |= minted,
            None => turns.push((turn, minted)),
        }
    }
    turns
}

/// Every moment a turn still in the room holds: when it was said, and when
/// each of its messages was.
pub(super) fn turn_times(snapshot: &OverlaySnapshot, turn: EntityId) -> Vec<u64> {
    snapshot
        .journal_entries()
        .iter()
        .filter(|entry| {
            entry.scope.turn() == turn
                && matches!(entry.op, BatchOp::Put { .. })
                && matches!(
                    entry.role,
                    JournalRole::TurnPut | JournalRole::MessagePartOf
                )
        })
        .map(|entry| entry.occurred.start)
        .collect()
}

/// What a saved copy of `turn` holds (ARCH-0052 D5): what the room showed
/// of it, as an export does. That is the room's shell, the TURN and its own
/// edge, and each visible message with its edges and text. A hidden message
/// (an agent's own reasoning), a summary and anything else of the turn stay
/// out, and stay in the room. `None` when the turn showed nothing.
pub(super) fn copy_plan(snapshot: &OverlaySnapshot, turn: EntityId) -> Result<Option<PromotePlan>> {
    let shown = shown_messages(snapshot, turn)?;
    if shown.is_empty() {
        return Ok(None);
    }
    snapshot
        .plan_promotion_where(turn, |entry| match entry.role {
            JournalRole::ConversationShell | JournalRole::TurnPut => true,
            JournalRole::SummaryDerivedFrom => false,
            JournalRole::MessagePartOf | JournalRole::AttributionEdge => {
                replayed_subject(&entry.op).is_some_and(|id| shown.contains(&id))
            }
            // The TURN's own edge to the room, and a shown message's text.
            JournalRole::TurnOwnedArtifact => match &entry.op {
                BatchOp::Edge { src, .. } => *src == turn,
                op => replayed_subject(op).is_some_and(|id| shown.contains(&id)),
            },
        })
        .map(Some)
}

/// What a later save adds to `turn`, which this stretch saved before: each
/// visible message said into it since, with its edges and text, and nothing
/// of the turn itself. `None` when nothing visible was.
fn append_plan(snapshot: &OverlaySnapshot, turn: EntityId) -> Result<Option<PromotePlan>> {
    let shown = shown_messages(snapshot, turn)?;
    if shown.is_empty() {
        return Ok(None);
    }
    snapshot
        .plan_append_where(turn, |entry| match entry.role {
            JournalRole::MessagePartOf
            | JournalRole::AttributionEdge
            | JournalRole::TurnOwnedArtifact => {
                replayed_subject(&entry.op).is_some_and(|id| shown.contains(&id))
            }
            JournalRole::ConversationShell
            | JournalRole::TurnPut
            | JournalRole::SummaryDerivedFrom => false,
        })
        .map(Some)
}

/// The visible messages of `turn` still in the room.
fn shown_messages(snapshot: &OverlaySnapshot, turn: EntityId) -> Result<BTreeSet<EntityId>> {
    let mut shown = BTreeSet::new();
    for entry in snapshot.journal_entries() {
        if let (
            JournalRole::MessagePartOf,
            BatchOp::Put {
                id,
                entity_type,
                data,
                ..
            },
        ) = (&entry.role, &entry.op)
            && *entity_type == ENTITY_TYPE_MESSAGE
            && entry.scope.turn() == turn
            && visible_message(data)?.is_some()
        {
            shown.insert(*id);
        }
    }
    Ok(shown)
}
