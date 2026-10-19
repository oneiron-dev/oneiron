//! A project question's kept answer, or a settled project card, that named an
//! erased actor, as stored (FIX 4229): history only.
//!
//! The answer keeps its source's place, its answer, its decision receipt's
//! measurements and its times; the card keeps its id, its goal, its picks,
//! its state and its times. Each id it named reads as no one where the actor
//! was erased. It sits in its table under its own shape, which no live reader
//! decodes, so nothing drafts, proposes, shows, confirms or replays on it
//! again.

use serde::{Deserialize, Serialize};

use super::{
    ACTOR_ERASE_PENDING_PROJECT, CONVERSATION_CARDS, ProjectCardRecord, ProjectCardState,
    ProjectDetectionAnswer, ProjectDetectionVerdict, refused,
};
use crate::genui::ProjectGoalDraft;
use crate::receipt::ERASED_CALL_IDENTITY;
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;
use crate::workspace_roster::join_receipt::names_no_actor;
use crate::workspace_roster::{RosterActor, RosterErase};
use crate::{EntityId, Error, Result, Vault};

/// What an actor's erase does with a project question's kept answer that
/// names it: its source's person, its receipt's principal or its drafter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectVerdictErase {
    /// The answer stays as inert history, naming no one where it named the
    /// actor; nothing drafts or proposes on it again.
    KeepInertHistory,
    /// The answer goes.
    Delete,
}

/// A kept answer is the question's receipt, so it stays as history rather
/// than going (FIX 4229; a call).
pub const ACTOR_ERASE_PROJECT_VERDICT: ProjectVerdictErase = ProjectVerdictErase::KeepInertHistory;

/// What an actor's erase does with a minted or dismissed card that names it
/// as its person, its leader or one of its board.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettledProjectCardErase {
    /// The card stays in its table as history only, naming no one where it
    /// named the actor; no reader shows, confirms or replays it.
    HistoryOnly,
    /// The card goes.
    Delete,
}

/// A settled card is the record of what was minted or turned down, so it
/// stays as history rather than going (FIX 4229; a call).
pub const ACTOR_ERASE_SETTLED_PROJECT_CARD: SettledProjectCardErase =
    SettledProjectCardErase::HistoryOnly;

/// Every kept answer as stored: a live one, or one that turned history. Key:
/// id16 (source message).
const VERDICT_ROWS: SideTable<EntityId, VerdictRow, Named> =
    SideTable::new(&side_table::PROJECT_PROPOSAL_VERDICT);
/// Every card as stored: a live one, or one that turned history. Key: blake3
/// hash32 of the card id.
const CARD_ROWS: SideTable<[u8; 32], CardRow, Named> =
    SideTable::new(&side_table::PROJECT_PROPOSAL_CARD);

/// One kept answer: the live one every door reads, or its history.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
enum VerdictRow {
    Live(Box<ProjectDetectionVerdict>),
    History { erased_history: VerdictHistory },
}

/// One card: the live one every door reads, or its history.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
enum CardRow {
    Live(ProjectCardRecord),
    History { erased_history: CardHistory },
}

/// [`super::ProjectDetectionSource`] as history holds it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HistorySource {
    conversation: EntityId,
    turn: EntityId,
    message: EntityId,
    author: RosterActor,
    thread: Option<EntityId>,
    at: u64,
}

/// A kept answer as history holds it: its decision receipt as kept, but
/// its principal spelled as a [`RosterActor`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct VerdictHistory {
    source: HistorySource,
    answer: ProjectDetectionAnswer,
    receipt: serde_json::Value,
    house: Option<RosterActor>,
}

impl VerdictHistory {
    /// `verdict` as history once `actor` was erased.
    fn of(verdict: &ProjectDetectionVerdict, actor: EntityId) -> Result<Self> {
        let value = serde_json::to_value(verdict)
            .map_err(|_| Error::InvariantViolation("project verdict encode"))?;
        let mut history: Self = serde_json::from_value(value)
            .map_err(|_| Error::InvariantViolation("project verdict history shape"))?;
        history.forget(actor);
        Ok(history)
    }

    /// Takes `actor` out of every id this history names. Whether it named
    /// the actor.
    fn forget(&mut self, actor: EntityId) -> bool {
        let mut named = self.source.author.forget(actor);
        if let Some(house) = &mut self.house {
            named |= house.forget(actor);
        }
        if let Some(principal) = self.receipt.get_mut("principal")
            && principal.as_str() == Some(actor.to_hex().as_str())
        {
            *principal = ERASED_CALL_IDENTITY.into();
            named = true;
        }
        named
    }
}

/// Whether a live answer names `actor`.
fn names(verdict: &ProjectDetectionVerdict, actor: EntityId) -> bool {
    verdict.source.author == actor
        || verdict.receipt.principal == actor
        || verdict.house == Some(actor)
}

/// [`crate::genui::ProjectProposalCard`] as history holds it: its refs as
/// stored, an erased one spelled as no one, none of them checked as a live
/// ref again.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoryCard {
    card_id: String,
    principal_ref: String,
    source_message_ref: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source_room_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source_thread_ref: Option<String>,
    goal: ProjectGoalDraft,
    leader_agent_def_ref: String,
    board_human_refs: Vec<String>,
    budget_share_bps: u16,
    starting_skill_refs: Vec<String>,
}

/// A settled card as history holds it: [`ProjectCardRecord`]'s fields, its
/// card as [`HistoryCard`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CardHistory {
    card: HistoryCard,
    conversation: EntityId,
    detection: EntityId,
    drafted_by: RosterActor,
    state: ProjectCardState,
    at: u64,
}

impl CardHistory {
    /// `record` as history once `actor` was erased.
    fn of(record: &ProjectCardRecord, actor: EntityId) -> Result<Self> {
        let value = serde_json::to_value(record)
            .map_err(|_| Error::InvariantViolation("project card encode"))?;
        let mut history: Self = serde_json::from_value(value)
            .map_err(|_| Error::InvariantViolation("project card history shape"))?;
        history.forget(actor);
        Ok(history)
    }

    /// Takes `actor` out of every ref and id this history names. Whether it
    /// named the actor.
    fn forget(&mut self, actor: EntityId) -> bool {
        let hex = actor.to_hex();
        let mut named = self.drafted_by.forget(actor);
        let card = &mut self.card;
        for slot in [&mut card.principal_ref, &mut card.leader_agent_def_ref]
            .into_iter()
            .chain(card.board_human_refs.iter_mut())
        {
            if *slot == hex {
                *slot = ERASED_CALL_IDENTITY.to_owned();
                named = true;
            }
        }
        named
    }
}

/// Whether a live card names `actor` as its person, its leader or one of its
/// board.
fn card_names(record: &ProjectCardRecord, hex: &str) -> bool {
    let card = &record.card;
    card.principal_ref == hex
        || card.leader_agent_def_ref == hex
        || card.board_human_refs.iter().any(|human| human == hex)
}

/// The live answer kept on `message`, if any. One that turned history
/// refuses: nothing drafts or proposes on it again (FIX 4229).
///
/// # Errors
///
/// Storage errors, a row that cannot be read, or a history row.
pub(super) fn live_verdict(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    message: &EntityId,
) -> Result<Option<ProjectDetectionVerdict>> {
    match VERDICT_ROWS.get(store, txn, message)? {
        None => Ok(None),
        Some(VerdictRow::Live(verdict)) => Ok(Some(*verdict)),
        Some(VerdictRow::History { .. }) => Err(refused(
            "the project question's answer on this message named an actor that was erased; \
             it is history, and nothing drafts on it",
        )),
    }
}

/// The live card filed under `key`, if any. One that turned history
/// refuses: nothing shows, confirms or replays it (FIX 4229).
///
/// # Errors
///
/// Storage errors, a row that cannot be read, or a history row.
pub(super) fn live_card(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    key: &[u8; 32],
) -> Result<Option<ProjectCardRecord>> {
    match CARD_ROWS.get(store, txn, key)? {
        None => Ok(None),
        Some(CardRow::Live(record)) => Ok(Some(record)),
        Some(CardRow::History { .. }) => Err(refused(
            "this card named an actor that was erased; it is history, and nothing shows, \
             confirms or replays it",
        )),
    }
}

/// [`live_card`] for a walk over a conversation's cards: a card that turned
/// history is not shown, and reads as none.
pub(super) fn shown_card(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    key: &[u8; 32],
) -> Result<Option<ProjectCardRecord>> {
    Ok(match CARD_ROWS.get(store, txn, key)? {
        Some(CardRow::Live(record)) => Some(record),
        Some(CardRow::History { .. }) | None => None,
    })
}

/// The state and the leader of the card filed under `key`, as stored, live
/// or history: what a goal-intake run on its project is checked against. An
/// erased leader reads as no one, which leads nothing.
pub(super) fn card_mint(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    key: &[u8; 32],
) -> Result<Option<(ProjectCardState, String)>> {
    Ok(match CARD_ROWS.get(store, txn, key)? {
        Some(CardRow::Live(record)) => Some((record.state, record.card.leader_agent_def_ref)),
        Some(CardRow::History { erased_history }) => Some((
            erased_history.state,
            erased_history.card.leader_agent_def_ref,
        )),
        None => None,
    })
}

/// Erasing `actor` from the host-held cards (FIX 3520, 4229): a card no tap
/// answered that the actor drafted, is for, would lead or sits on the board
/// of goes with its place in its conversation, when
/// [`ACTOR_ERASE_PENDING_PROJECT`] says so. A minted or dismissed card that
/// is for the actor, or names it as its leader or on its board, turns
/// history, as [`ACTOR_ERASE_SETTLED_PROJECT_CARD`] says; one the actor only
/// drafted keeps its row, its card and its time, and names no drafter. A
/// history card takes the actor out too. One-way, in the erase's own
/// transaction. An id whose entity is no actor scans nothing.
///
/// # Errors
///
/// Storage errors, or a card row that cannot be read.
pub(crate) fn erase_card_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    if names_no_actor(vault, wtxn, actor)? {
        return Ok(());
    }
    let hex = actor.to_hex();
    let mut doomed = Vec::new();
    let mut rows = Vec::new();
    for (key, row) in CARD_ROWS.scan(&vault.store, wtxn)? {
        let mut record = match row {
            CardRow::Live(record) => record,
            CardRow::History { mut erased_history } => {
                if erased_history.forget(*actor) {
                    rows.push((key, CardRow::History { erased_history }));
                }
                continue;
            }
        };
        let named = card_names(&record, &hex);
        if record.state == ProjectCardState::Proposed {
            if (named || record.drafted_by.is(*actor))
                && ACTOR_ERASE_PENDING_PROJECT == RosterErase::Delete
            {
                doomed.push((key, record.conversation));
            } else if record.drafted_by.forget(*actor) {
                rows.push((key, CardRow::Live(record)));
            }
        } else if named && ACTOR_ERASE_SETTLED_PROJECT_CARD == SettledProjectCardErase::Delete {
            doomed.push((key, record.conversation));
        } else if named {
            let erased_history = CardHistory::of(&record, *actor)?;
            rows.push((key, CardRow::History { erased_history }));
        } else if record.drafted_by.forget(*actor) {
            rows.push((key, CardRow::Live(record)));
        }
    }
    for (key, conversation) in &doomed {
        CARD_ROWS.delete(&vault.store, wtxn, key)?;
        CONVERSATION_CARDS.delete(&vault.store, wtxn, &(*conversation, *key))?;
    }
    for (key, row) in &rows {
        CARD_ROWS.put(&vault.store, wtxn, key, row)?;
    }
    Ok(())
}

impl Vault {
    /// Erasing `actor` from the project questions' kept answers (FIX 4229):
    /// an answer whose source the actor wrote, whose receipt names it as its
    /// principal or whose drafter it is turns history, as
    /// [`ACTOR_ERASE_PROJECT_VERDICT`] says: its source's place, its answer,
    /// its receipt's measurements and its times stay, and it names no one
    /// where it named the actor. A history answer takes the actor out too.
    /// One-way, in the erase's own transaction. An id whose entity is no
    /// actor scans nothing.
    ///
    /// # Errors
    ///
    /// Storage errors, or an answer row that cannot be read.
    pub(crate) fn erase_project_verdict_actor_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        actor: &EntityId,
    ) -> Result<()> {
        if names_no_actor(self, wtxn, actor)? {
            return Ok(());
        }
        let mut doomed = Vec::new();
        let mut rows = Vec::new();
        for (message, row) in VERDICT_ROWS.scan(&self.store, wtxn)? {
            let erased_history = match row {
                VerdictRow::History { mut erased_history } => {
                    if !erased_history.forget(*actor) {
                        continue;
                    }
                    erased_history
                }
                VerdictRow::Live(verdict) if names(&verdict, *actor) => {
                    if ACTOR_ERASE_PROJECT_VERDICT == ProjectVerdictErase::Delete {
                        doomed.push(message);
                        continue;
                    }
                    VerdictHistory::of(&verdict, *actor)?
                }
                VerdictRow::Live(_) => continue,
            };
            rows.push((message, VerdictRow::History { erased_history }));
        }
        for message in &doomed {
            VERDICT_ROWS.delete(&self.store, wtxn, message)?;
        }
        for (message, row) in &rows {
            VERDICT_ROWS.put(&self.store, wtxn, message, row)?;
        }
        Ok(())
    }
}
