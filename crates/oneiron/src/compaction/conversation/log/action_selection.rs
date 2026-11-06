//! The raw turns a turn action is answered from (FIX 5032): its TARGET turn,
//! the latest user turn before it, and the turns whose lines fill the history
//! before that user turn. The action's context and a Retry's breakpoint seed
//! read these turns only, never the whole branch.
//!
//! The selection lists TARGET's branch from row headers
//! ([`Memory::transcript_turn_keys`]): a DAG conversation's retained Parent
//! chain to TARGET, never the chain to HEAD, or any other conversation's time
//! order up to TARGET. It reads TARGET first. A TARGET the reader does not
//! read selects nothing. It then reads the listed turns backward from TARGET,
//! at most [`MAX_TRANSCRIPT_PAGE_TURNS`] turns a batch
//! ([`Memory::selected_transcript_turns`]). It reads an earlier batch only
//! while it still needs the user turn or more history lines.
//!
//! A line is a non-system message with text. The history counts lines, not
//! turns, and keeps the last ones, so its oldest turn can be kept in part.
//! Every readable turn in the history's span is read, so a line that became
//! readable there joins the history. No summary stands in, and no coverage
//! or receipt is read. When a turn's time moves while it is read, the
//! selection lists again, as a transcript page does.

use crate::compaction::MAX_TRANSCRIPT_PAGE_TURNS;
use crate::conversation::TurnActionLine;
use crate::memory::{Memory, TRANSCRIPT_READ_ATTEMPTS, TranscriptTurn, WitnessAuthor};
use crate::{EntityId, Error};
use oneiron_contracts::memory::{MEMORY_CODE_INVALID_STATE, MemoryError, MemoryResult};

/// The raw turns a turn action is answered from, as one reader read them
/// (FIX 5032).
pub(crate) struct ActionSelection {
    /// The branch read: TARGET on a DAG conversation, `None` on any other.
    pub(crate) branch: Option<EntityId>,
    /// TARGET, as the reader reads it.
    pub(crate) target: TranscriptTurn,
    /// The latest readable turn before TARGET that holds a user line, with
    /// the history before it. `None` when the reader reads no such turn.
    pub(crate) user: Option<ActionUserTurn>,
}

/// The user turn a turn action answers, and the history before it.
pub(crate) struct ActionUserTurn {
    pub(crate) id: EntityId,
    pub(crate) turn: TranscriptTurn,
    /// Its user lines' words, joined by a blank line.
    pub(crate) text: String,
    /// Its user lines' TURN and MESSAGE rows. `None` when any identity is
    /// unknown.
    pub(crate) sources: Option<Vec<EntityId>>,
    /// The last lines before it, oldest first: at most the caller's
    /// `history_lines`.
    pub(crate) history: Vec<TurnActionLine>,
    /// Each turn that `history` keeps a line of, oldest first. The oldest
    /// can be kept in part.
    pub(crate) history_turns: Vec<TranscriptTurn>,
}

/// Selects and reads, as `memory`'s reader, the raw turns a turn action on
/// `target` in `conversation` is answered from (FIX 5032): TARGET, the latest
/// user turn before it, and the last `history_lines` lines before that user
/// turn. `None` when the reader does not read TARGET on its branch.
///
/// # Errors
///
/// `NOT_FOUND` when the reader may not read the conversation, a branch whose
/// chain does not prove, turns that keep moving in time while they are read,
/// and storage errors.
pub(crate) fn select_action_turns(
    memory: &Memory<'_>,
    conversation: EntityId,
    target: EntityId,
    history_lines: usize,
) -> MemoryResult<Option<ActionSelection>> {
    let vault = memory.vault();
    let dag = {
        let txn = vault.store.env.read_txn().map_err(Error::from)?;
        crate::conversation_dag::keeps_dag_topology(&vault.store, &txn, &conversation)?
    };
    let branch = dag.then_some(target);
    for _ in 0..TRANSCRIPT_READ_ATTEMPTS {
        if let Some(selection) = select_once(memory, conversation, branch, target, history_lines)? {
            return Ok(selection);
        }
    }
    Err(MemoryError::new(
        MEMORY_CODE_INVALID_STATE,
        "the conversation's turns kept moving while the action's turns were read",
        &["Read the conversation's transcript again before acting on the turn."],
    ))
}

/// One attempt at [`select_action_turns`] on `branch`: `None` when a selected
/// turn's time moved between its listing and its read, and `Some(None)` when
/// the reader does not read TARGET.
fn select_once(
    memory: &Memory<'_>,
    conversation: EntityId,
    branch: Option<EntityId>,
    target: EntityId,
    history_lines: usize,
) -> MemoryResult<Option<Option<ActionSelection>>> {
    let keys = memory.transcript_turn_keys(&conversation, branch.as_ref())?;
    // TARGET ends the listing: no turn after it is read.
    let Some(at) = keys.iter().rposition(|(_, turn)| *turn == target) else {
        return Ok(Some(None));
    };
    let Some(read) = memory.selected_transcript_turns(&conversation, &keys[at..=at])? else {
        return Ok(None);
    };
    let Some(target_turn) = read.into_iter().next() else {
        return Ok(Some(None));
    };
    // Newest first: the user turn with its lines, then each earlier turn
    // with lines, until the history holds `history_lines` lines.
    let mut user: Option<(TranscriptTurn, Vec<TurnActionLine>)> = None;
    let mut kept: Vec<(TranscriptTurn, Vec<TurnActionLine>)> = Vec::new();
    let mut held = 0;
    let mut end = at;
    while end > 0 && (user.is_none() || held < history_lines) {
        let start = end.saturating_sub(MAX_TRANSCRIPT_PAGE_TURNS);
        let Some(batch) = memory.selected_transcript_turns(&conversation, &keys[start..end])?
        else {
            return Ok(None);
        };
        end = start;
        for turn in batch.into_iter().rev() {
            let lines = action_lines(&turn);
            if user.is_none() {
                if lines.iter().any(|line| line.author == WitnessAuthor::User) {
                    user = Some((turn, lines));
                }
                continue;
            }
            if held >= history_lines {
                break;
            }
            if !lines.is_empty() {
                held += lines.len();
                kept.push((turn, lines));
            }
        }
    }
    let user = user
        .map(|(turn, lines)| user_turn(turn, &lines, kept, history_lines))
        .transpose()?;
    Ok(Some(Some(ActionSelection {
        branch,
        target: target_turn,
        user,
    })))
}

/// The user turn `turn`, read with its `lines`, and the history before it:
/// the last `history_lines` lines of `kept`, the turns before it that hold
/// lines, newest first.
fn user_turn(
    turn: TranscriptTurn,
    lines: &[TurnActionLine],
    mut kept: Vec<(TranscriptTurn, Vec<TurnActionLine>)>,
    history_lines: usize,
) -> MemoryResult<ActionUserTurn> {
    let user: Vec<&TurnActionLine> = lines
        .iter()
        .filter(|line| line.author == WitnessAuthor::User)
        .collect();
    let text = user
        .iter()
        .map(|line| line.text.as_str())
        .collect::<Vec<_>>()
        .join("\n\n");
    let sources = user.iter().try_fold(Vec::new(), |mut rows, line| {
        rows.extend_from_slice(line.sources.as_deref()?);
        Some(rows)
    });
    kept.reverse();
    let mut history: Vec<TurnActionLine> = kept
        .iter()
        .flat_map(|(_, turn_lines)| turn_lines.iter().cloned())
        .collect();
    history.drain(..history.len().saturating_sub(history_lines));
    Ok(ActionUserTurn {
        id: EntityId::from_hex(&turn.id)?,
        turn,
        text,
        sources,
        history,
        history_turns: kept.into_iter().map(|(turn, _)| turn).collect(),
    })
}

/// `turn`'s lines as a chat request carries them: its non-system messages
/// with text, in order, each with its TURN and MESSAGE rows.
fn action_lines(turn: &TranscriptTurn) -> Vec<TurnActionLine> {
    let turn_source = EntityId::from_hex(&turn.id).ok();
    turn.messages
        .iter()
        .filter_map(|message| {
            let author = WitnessAuthor::parse(&message.role)?;
            (author != WitnessAuthor::System && !message.text.is_empty()).then(|| TurnActionLine {
                author,
                text: message.text.clone(),
                sources: turn_source
                    .zip(EntityId::from_hex(&message.id).ok())
                    .map(|(turn, message)| vec![turn, message]),
            })
        })
        .collect()
}
