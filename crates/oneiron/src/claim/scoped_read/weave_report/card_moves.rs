//! The notes and steers an agent-health card in a weave keeps (FIX 8536).
//!
//! A card shows in a weave to its recipients and a live owner, never to the
//! agent it is about. Its moves name rows beyond the card's own: a note's
//! room, TURN and MESSAGEs, a steer's TASK. A served copy, live or a saved
//! period's, keeps each move whose rows the reader's own floor reads, each
//! judged on its own, and leaves out a move it does not read whole. The card,
//! its other moves and the period always stay. A stored card and a saved
//! period keep every move as it landed. The rows a kept move names are among
//! the rows the report reads ([`move_rows`]).

use std::collections::BTreeMap;

use super::{WeaveItem, WeaveReport};
use crate::EntityId;
use crate::claim::ScopedRead;
use crate::dreamer_runner::maintenance::agent_health::{ConcernMoveLink, ConcernMoveReceipt};
use crate::gate::{PolicyManifestResolution, ResolvedRetrievalFilter};

impl ScopedRead<'_> {
    /// Keeps, on each agent-health card in `report`, the moves this reader's
    /// own floor reads whole ([`Self::is_entity_retrievable_with_policy_in`]
    /// for every row a move's own door answered with). A floor that does not
    /// answer leaves the move out.
    pub(crate) fn project_card_moves_in(
        &self,
        txn: &heed::RoTxn<'_>,
        policy: &PolicyManifestResolution,
        filter: &ResolvedRetrievalFilter,
        report: &mut WeaveReport,
    ) {
        let mut floor: BTreeMap<EntityId, bool> = BTreeMap::new();
        let mut admits = |id: EntityId| -> bool {
            *floor.entry(id).or_insert_with(|| {
                match self.is_entity_retrievable_with_policy_in(txn, policy, filter, &id) {
                    Ok(readable) => readable,
                    Err(error) => {
                        tracing::warn!(
                            error_kind = ?error.kind(),
                            "the read floor did not answer for a card move's row; left out"
                        );
                        false
                    }
                }
            })
        };
        for item in report
            .sections
            .iter_mut()
            .flat_map(|section| &mut section.items)
        {
            if let WeaveItem::AgentHealth { card, .. } = item {
                card.moves_taken.retain(|receipt| {
                    link_rows(&receipt.link).is_some_and(|rows| rows.into_iter().all(&mut admits))
                });
            }
        }
    }
}

/// The rows a move's own door answered with: a note's room, TURN and
/// MESSAGEs, a steer's TASK. `None` when one of them is no id: such a move is
/// read as one whose rows the reader does not read.
fn link_rows(link: &ConcernMoveLink) -> Option<Vec<EntityId>> {
    let refs: Vec<&str> = match link {
        ConcernMoveLink::Note {
            room,
            turn,
            messages,
        } => std::iter::once(room.as_str())
            .chain(turn.as_deref())
            .chain(messages.iter().map(String::as_str))
            .collect(),
        ConcernMoveLink::Steer { task_ref, .. } => vec![task_ref.as_str()],
    };
    refs.into_iter()
        .map(|id| EntityId::from_hex(id).ok())
        .collect()
}

/// Every row a kept move names (FIX 8536): its actor, the card's TASK, agent
/// and attempt when it landed, and the rows its door answered with, the
/// steered attempt too. A value that is no id names none.
pub(super) fn move_rows(receipt: &ConcernMoveReceipt) -> Vec<EntityId> {
    let mut rows = vec![receipt.actor, receipt.subject];
    rows.extend(receipt.task.into_iter().chain(receipt.attempt));
    match &receipt.link {
        ConcernMoveLink::Note {
            room,
            turn,
            messages,
        } => rows.extend(
            std::iter::once(room.as_str())
                .chain(turn.as_deref())
                .chain(messages.iter().map(String::as_str))
                .filter_map(|id| EntityId::from_hex(id).ok()),
        ),
        ConcernMoveLink::Steer {
            task_ref, branch, ..
        } => rows.extend(
            [task_ref.as_str(), branch.as_str()]
                .into_iter()
                .filter_map(|id| EntityId::from_hex(id).ok()),
        ),
    }
    rows
}
