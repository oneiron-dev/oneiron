//! A chat log's read plan (FIX 5032): which turns its summaries cover, and
//! which turns it reads raw, decided before any raw history is read.
//!
//! The plan lists the TURN ids of the exact conversation and branch from row
//! headers alone: a DAG conversation's branch to its HEAD or to a queued
//! action's TARGET turn, any other conversation's time order, cut before the
//! user turn an action answers (FIX 5027). It reads the conversation's
//! landing receipts through their conversation index. A summary stands for
//! its turns when every one of them is listed, none is covered already, and
//! the existing checks hold as the reader reads now ([`standing_words_in`]):
//! its evidence reads to the pins its landing took, its writer's home still
//! stands, and its words pass the reader's read. A covered turn is read
//! through that evidence. Its MESSAGE bodies are never hydrated.
//!
//! Only the turns no summary covers are hydrated: each gap between covered
//! turns and the suffix after the last one, through the transcript's own
//! page reader ([`Memory::selected_transcript_turns`]). The plan never starts
//! after the latest summary. A summary that does not read, is stale, is on
//! another branch or lies past an uncovered gap covers nothing, and its turns
//! stay raw. When a turn's time moves while the plan reads it, the plan lists
//! again, as a transcript page does.

use std::collections::{BTreeMap, BTreeSet};

use super::super::standing::standing_words_in;
use super::super::storage::{ConversationLandingReceipt, conversation_receipts_in};
use super::{ChatLogCut, ReadTurn, read_turn};
use crate::claim::ScopedRead;
use crate::memory::{Memory, TRANSCRIPT_READ_ATTEMPTS};
use crate::{EntityId, Error};
use oneiron_contracts::memory::{MEMORY_CODE_INVALID_STATE, MemoryError, MemoryResult};

/// One turn of a chat log's plan, up to its last covered turn.
pub(super) enum PlannedTurn {
    /// A turn a standing summary covers, with the summary's place in
    /// [`ChatLogPlan::standing`]: read through the summary's evidence.
    Covered { turn: EntityId, summary: usize },
    /// A turn in a gap between covered turns, hydrated and read raw.
    Raw(ReadTurn),
}

/// A chat log's read plan (FIX 5032), with the raw turns it hydrated. Only
/// the turns the reader reads are in it, in their order.
pub(super) struct ChatLogPlan {
    /// The branch read: a DAG conversation's HEAD, or a retry action's TARGET turn.
    pub(super) branch: Option<EntityId>,
    /// The turns up to and including the last covered one.
    pub(super) prefix: Vec<PlannedTurn>,
    /// The turns after the last covered one, all raw: what the threshold
    /// counts, and what the window and the hot tail are read from.
    pub(super) suffix: Vec<ReadTurn>,
    /// The standing summaries with their words, in SUMMARY order.
    pub(super) standing: Vec<(ConversationLandingReceipt, String)>,
}

impl ChatLogPlan {
    /// The last turn the reader reads.
    pub(super) fn last_turn(&self) -> Option<EntityId> {
        if let Some(turn) = self.suffix.last() {
            return Some(turn.id);
        }
        self.prefix.last().map(|turn| match turn {
            PlannedTurn::Covered { turn, .. } => *turn,
            PlannedTurn::Raw(turn) => turn.id,
        })
    }
}

/// The summaries that stand for a plan's listed turns, and the summary that
/// covers each turn they cover.
struct Coverage {
    /// The standing summaries with their words, in SUMMARY order.
    standing: Vec<(ConversationLandingReceipt, String)>,
    /// Each covered turn, by its summary's place in `standing`.
    covering: BTreeMap<EntityId, usize>,
}

/// Plans `conversation`'s chat log as `memory`'s reader, with `scoped` its
/// whole key, cut at `cut` when an action reads it, and hydrates the turns
/// no summary covers (FIX 5032).
///
/// # Errors
///
/// A conversation the reader may not read, a cut whose user turn the reader
/// does not read on its branch, turns that keep moving in time while they
/// are read, a corrupted receipt index, and storage errors.
pub(super) fn plan_chat_log(
    memory: &Memory<'_>,
    scoped: &ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    conversation: EntityId,
    cut: Option<ChatLogCut>,
) -> MemoryResult<ChatLogPlan> {
    for _ in 0..TRANSCRIPT_READ_ATTEMPTS {
        if let Some(plan) = plan_once(memory, scoped, txn, conversation, cut)? {
            return Ok(plan);
        }
    }
    Err(MemoryError::new(
        MEMORY_CODE_INVALID_STATE,
        "the conversation's turns kept moving while its chat log was read",
        &["Read the chat log again."],
    ))
}

/// One attempt at [`plan_chat_log`]: `None` when a turn's time moved between
/// its listing and its read.
fn plan_once(
    memory: &Memory<'_>,
    scoped: &ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    conversation: EntityId,
    cut: Option<ChatLogCut>,
) -> MemoryResult<Option<ChatLogPlan>> {
    let vault = memory.vault();
    let dag = {
        let txn = vault.store.env.read_txn().map_err(Error::from)?;
        crate::conversation_dag::keeps_dag_topology(&vault.store, &txn, &conversation)?
    };
    let branch = match (dag, cut) {
        (false, _) => None,
        (true, Some(cut)) => Some(cut.target),
        (true, None) => vault.head(&conversation)?,
    };
    if dag && branch.is_none() {
        return Ok(Some(ChatLogPlan {
            branch: None,
            prefix: Vec::new(),
            suffix: Vec::new(),
            standing: Vec::new(),
        }));
    }
    let mut listed = memory.transcript_turn_keys(&conversation, branch.as_ref())?;
    // An action's log holds the turns before the user turn it answers (FIX
    // 5027). That turn is hydrated with the raw turns, so the plan proves the
    // reader reads it, and then left out.
    let mut before = None;
    if let Some(cut) = cut {
        match listed.iter().position(|(_, turn)| *turn == cut.before) {
            Some(at) => {
                before = Some(listed[at]);
                listed.truncate(at);
            }
            None => listed.clear(),
        }
    }
    let ids: Vec<EntityId> = listed.iter().map(|(_, turn)| *turn).collect();
    let Coverage { standing, covering } = coverage(scoped, txn, conversation, &ids)?;
    let last_covered = ids.iter().rposition(|turn| covering.contains_key(turn));
    let mut selected: Vec<(u64, EntityId)> = listed
        .iter()
        .filter(|(_, turn)| !covering.contains_key(turn))
        .copied()
        .collect();
    selected.extend(before);
    let Some(hydrated) = memory.selected_transcript_turns(&conversation, &selected)? else {
        return Ok(None);
    };
    let mut read: BTreeMap<EntityId, ReadTurn> = BTreeMap::new();
    for turn in &hydrated {
        let turn = read_turn(turn)?;
        read.insert(turn.id, turn);
    }
    if let Some(cut) = cut
        && read.remove(&cut.before).is_none()
    {
        return Err(MemoryError::not_found(
            "the user turn the action answers is not read",
        ));
    }
    let mut prefix = Vec::new();
    let mut suffix = Vec::new();
    for (at, turn) in ids.iter().enumerate() {
        if let Some(&summary) = covering.get(turn) {
            prefix.push(PlannedTurn::Covered {
                turn: *turn,
                summary,
            });
        } else if let Some(raw) = read.remove(turn) {
            if last_covered.is_some_and(|last| at < last) {
                prefix.push(PlannedTurn::Raw(raw));
            } else {
                suffix.push(raw);
            }
        }
    }
    Ok(Some(ChatLogPlan {
        branch,
        prefix,
        suffix,
        standing,
    }))
}

/// The summaries of `conversation` that stand for `listed` turns as `scoped`
/// reads them, in SUMMARY order: each one whose evidence names only listed
/// turns, none covered by an earlier one, while [`standing_words_in`] holds.
/// Read in `txn`, the log's one governing snapshot, which its raw pins, its
/// window and its SESSION are read in too (FIX 5032): its caller persisted
/// grant time before opening it (FIX 6188).
fn coverage(
    scoped: &ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    conversation: EntityId,
    listed: &[EntityId],
) -> MemoryResult<Coverage> {
    let mut coverage = Coverage {
        standing: Vec::new(),
        covering: BTreeMap::new(),
    };
    if listed.is_empty() {
        return Ok(coverage);
    }
    let vault = scoped.vault();
    let listed: BTreeSet<EntityId> = listed.iter().copied().collect();
    for receipt in conversation_receipts_in(&vault.store, txn, conversation)? {
        let Some(evidence) = receipt.evidence() else {
            continue;
        };
        if !evidence
            .turns
            .iter()
            .all(|span| listed.contains(&span.turn))
            || evidence
                .turns
                .iter()
                .any(|span| coverage.covering.contains_key(&span.turn))
        {
            continue;
        }
        let Some(text) = standing_words_in(scoped, txn, &receipt)? else {
            continue;
        };
        for span in &evidence.turns {
            coverage.covering.insert(span.turn, coverage.standing.len());
        }
        coverage.standing.push((receipt, text));
    }
    Ok(coverage)
}
