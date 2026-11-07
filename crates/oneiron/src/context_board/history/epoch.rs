//! A past turn's board history with its compaction epoch (FIX 5038).
//!
//! An epoch mint folds the boards of exactly the turns it covers, and an
//! exact reconstruction of a folded turn's board refuses (ARCH-0067). That
//! refusal stays: no exact board is rebuilt from a summary. This view is a
//! separate, typed answer for a reader of chat history: for a turn a
//! conversation's compaction folded, the epoch summary that stands for it,
//! read through the same standing-summary reader the chat log uses, under
//! the caller's current read and disclosure clamp. Any other refusal, and a
//! summary that no longer stands, refuses as the exact reconstruction does.

use super::types::{BoardHistoryError, ReconstructedBoard};
use crate::claim::ScopedRead;
use crate::compaction::FoldedTurnSummary;
use crate::registry::ENTITY_TYPE_SUMMARY;
use crate::{EntityId, Vault};

type Result<T> = std::result::Result<T, BoardHistoryError>;

/// What a past turn's board history reads as: the exact board at the
/// frontier the turn recorded, or, for a chat turn a conversation's
/// compaction folded, the epoch that stands for it now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BoardTurnHistory {
    Board(Box<ReconstructedBoard>),
    Epoch(BoardTurnEpoch),
}

/// The epoch summary a conversation's compaction folded a turn into, as the
/// caller reads it now. It is the agent's own record of the covered turns,
/// never their boards.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoardTurnEpoch {
    /// The folded TURN.
    pub turn: EntityId,
    /// The SUMMARY that stands for it.
    pub summary: EntityId,
    /// The epoch's lineage: the conversation's turns within the SESSION.
    pub session: EntityId,
    pub conversation: EntityId,
    pub epoch: u64,
    /// The conversation's turn numbers within the SESSION the epoch covers.
    pub turn_start: u64,
    pub turn_end: u64,
    /// The summary's words.
    pub text: String,
}

impl BoardTurnEpoch {
    fn of(turn: EntityId, epoch: FoldedTurnSummary) -> Self {
        Self {
            turn,
            summary: epoch.summary,
            session: epoch.session,
            conversation: epoch.conversation,
            epoch: epoch.epoch,
            turn_start: epoch.turn_start,
            turn_end: epoch.turn_end,
            text: epoch.text,
        }
    }
}

impl Vault {
    /// [`Self::reconstruct_board_for`], with a turn a conversation's
    /// compaction folded read as the epoch that stands for it (FIX 5038).
    /// The TURN, the board owner and the caller pass the exact read's checks
    /// first. The epoch's evidence and words then pass `caller`'s CURRENT
    /// read, and the SUMMARY `disclosure`'s clamp. A folded turn with no
    /// standing epoch, or one the caller may not be shown, refuses as
    /// [`BoardHistoryError::Compacted`]; every other refusal is the exact
    /// read's.
    pub fn board_turn_history_for(
        &self,
        turn: &EntityId,
        caller: &ScopedRead<'_>,
        disclosure: Option<&crate::disclosure::DisclosureContext>,
    ) -> Result<BoardTurnHistory> {
        let folded = match self.reconstruct_board_for(turn, caller, disclosure) {
            Ok(board) => return Ok(BoardTurnHistory::Board(Box::new(board))),
            Err(BoardHistoryError::Compacted(folded)) => folded,
            Err(error) => return Err(error),
        };
        let txn = self.store.env.read_txn()?;
        let Some(epoch) = crate::compaction::folded_turn_summary_in(caller, &txn, &folded)? else {
            return Err(BoardHistoryError::Compacted(folded));
        };
        if let Some(disclosure) = disclosure
            && !disclosure.admits(&self.store, &txn, &epoch.summary, ENTITY_TYPE_SUMMARY, None)?
        {
            return Err(BoardHistoryError::Compacted(folded));
        }
        Ok(BoardTurnHistory::Epoch(BoardTurnEpoch::of(folded, epoch)))
    }
}
