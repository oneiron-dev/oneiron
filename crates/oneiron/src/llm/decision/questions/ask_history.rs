//! One commit-ordered log of a question's asks (FIX 2337, FIX 1585): each graph
//! answer receipt a question lands, by its claim, and each artifact ask with the pins it
//! read and the proposal its answers wait under, a failed one too. The latest
//! `TYPED_QUESTION_ARTIFACT_ASKED` stamp stays the scheduling projection; this log is
//! what the answers door reads past it.
//!
//! Each entry's sequence is allocated in the write transaction that lands it, from a
//! per-question high-water row inside `TYPED_QUESTION`, shared by the graph and artifact
//! writers. A later commit always holds a higher sequence than an earlier one, whatever
//! its clock or the claim id it minted, and an erased entry's sequence is never reused.

use std::ops::Bound;

use serde::{Deserialize, Serialize};

use super::records::AnswerRecord;
use super::store::{
    AnswerKey, QUESTION_ANSWER, decode_family, family_prefix, secret_scan_before_put,
};
use crate::side_table::{self, Named, SideKey, SideTable};
use crate::{EntityId, Error, ErrorKind, Result, Vault};

/// Key of one log entry: id16(question) + u64be(sequence).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct AskHistoryKey {
    pub(super) question: EntityId,
    pub(super) sequence: u64,
}

impl SideKey for AskHistoryKey {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.question.as_bytes());
        out.extend_from_slice(&self.sequence.to_be_bytes());
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        let (question, sequence) = bytes.split_at_checked(16)?;
        Some(Self {
            question: EntityId::from_bytes(question.try_into().ok()?).ok()?,
            sequence: u64::from_be_bytes(sequence.try_into().ok()?),
        })
    }
}

/// Key of one question's log high-water mark, a row family of `TYPED_QUESTION`.
/// Family: `ask_history_head`, suffix: empty.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct AskHistoryHeadKey(pub(super) EntityId);

impl SideKey for AskHistoryHeadKey {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&family_prefix(self.0, b"ask_history_head"));
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        let (id, suffix) = decode_family(bytes, b"ask_history_head")?;
        suffix.is_empty().then_some(Self(id))
    }
}

pub(super) const ASK_HISTORY: SideTable<AskHistoryKey, QuestionAskHistoryEntry, Named> =
    SideTable::new(&side_table::TYPED_QUESTION_ASK_HISTORY);
/// The last sequence a question's log allocated; none before its first entry.
pub(super) const ASK_HISTORY_HEAD: SideTable<AskHistoryHeadKey, u64, Named> =
    SideTable::new(&side_table::TYPED_QUESTION);

/// One entry of a question's log: whose question it is, and the ask.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct QuestionAskHistoryEntry {
    pub(super) principal: EntityId,
    pub(super) event: AskHistoryEvent,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum AskHistoryEvent {
    /// A graph answer receipt, by the claim its immutable `AnswerRecord` is keyed by.
    Graph { claim: EntityId },
    /// One artifact ask, as it ran.
    Artifact(Box<ArtifactAskEvent>),
}

/// One ask of one artifact by a standing artifact question: the pins it read, when, the
/// proposal its answers wait under and, for an ask that failed, its error's kind.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ArtifactAskEvent {
    /// The ask's own id, minted before it ran; its run ref names it.
    pub(super) ask_id: EntityId,
    pub(super) artifact: EntityId,
    pub(super) question_version: u32,
    /// Each read artifact's head version when it was asked, the artifact first.
    pub(super) versions: Vec<(EntityId, u64)>,
    pub(super) asked_at: u64,
    /// The proposal its answers wait under; none when no unit was answered.
    pub(super) proposal_ref: Option<String>,
    /// The failed ask's error kind, as its stable wire name (FIX 9177); none when it
    /// completed.
    pub(super) failed: Option<ErrorKind>,
}

impl ArtifactAskEvent {
    /// Every id the entry names besides its question and principal.
    fn names(&self, id: &EntityId) -> bool {
        self.artifact == *id
            || self.ask_id == *id
            || self.versions.iter().any(|(read, _)| read == id)
    }
}

/// The highest sequence `question`'s log has allocated, 0 before its first entry.
pub(super) fn ask_history_through_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    question: EntityId,
) -> Result<u64> {
    Ok(ASK_HISTORY_HEAD
        .get(&vault.store, txn, &AskHistoryHeadKey(question))?
        .unwrap_or(0))
}

/// The artifact asks `principal`'s `question` logged after sequence `after`, up to
/// `through`, each with its sequence, in the order they committed.
pub(super) fn artifact_events_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    question: EntityId,
    principal: EntityId,
    after: u64,
    through: u64,
) -> Result<Vec<(u64, ArtifactAskEvent)>> {
    let start = AskHistoryKey {
        question,
        sequence: after,
    };
    let end = AskHistoryKey {
        question,
        sequence: through,
    };
    let mut events = Vec::new();
    if through <= after {
        return Ok(events);
    }
    let rows = ASK_HISTORY.iter_range(
        &vault.store,
        txn,
        Bound::Excluded(&start),
        Bound::Included(&end),
    )?;
    for row in rows {
        let (key, entry) = row?;
        if let AskHistoryEvent::Artifact(event) = entry.event
            && entry.principal == principal
        {
            events.push((key.sequence, *event));
        }
    }
    Ok(events)
}

/// Appends `event` to `question`'s log in the writer's own transaction, at the next
/// sequence.
fn append_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    question: EntityId,
    principal: EntityId,
    event: AskHistoryEvent,
) -> Result<()> {
    let sequence = ask_history_through_in_txn(vault, txn, question)?
        .checked_add(1)
        .ok_or(Error::ArithmeticOverflow("question ask history"))?;
    let entry = QuestionAskHistoryEntry { principal, event };
    secret_scan_before_put(&entry)?;
    let key = AskHistoryKey { question, sequence };
    ASK_HISTORY.put(&vault.store, txn, &key, &entry)?;
    ASK_HISTORY_HEAD.put(&vault.store, txn, &AskHistoryHeadKey(question), &sequence)
}

/// Stores a new graph answer receipt under `question` and appends its claim to the
/// question's log, in one transaction. A read or an idempotent replay that finds the
/// receipt already stored calls neither.
pub(super) fn put_graph_answer_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    question: EntityId,
    principal: EntityId,
    answer: &AnswerRecord,
) -> Result<()> {
    QUESTION_ANSWER.put(
        &vault.store,
        txn,
        &AnswerKey {
            question,
            claim: answer.claim,
        },
        answer,
    )?;
    append_in_txn(
        vault,
        txn,
        question,
        principal,
        AskHistoryEvent::Graph {
            claim: answer.claim,
        },
    )
}

/// Appends one artifact ask to `question`'s log, in the transaction that commits its
/// proposal and stamp, or alone for a failed ask.
pub(super) fn append_artifact_ask_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    question: EntityId,
    principal: EntityId,
    event: ArtifactAskEvent,
) -> Result<()> {
    append_in_txn(
        vault,
        txn,
        question,
        principal,
        AskHistoryEvent::Artifact(Box::new(event)),
    )
}

/// Erasing `actor` from the ask logs (FIX 3520), in the erase's own transaction: every
/// entry that names it as its question, its principal, its graph claim, its artifact or
/// a file it read goes. A surviving question's high-water mark stays, so no sequence is
/// handed out twice.
pub(crate) fn erase_ask_history_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    let mut gone = Vec::new();
    for row in ASK_HISTORY.iter_from(&vault.store, wtxn, &[])? {
        let (key, entry) = row?;
        let named = match &entry.event {
            AskHistoryEvent::Graph { claim } => claim == actor,
            AskHistoryEvent::Artifact(event) => event.names(actor),
        };
        if named || key.question == *actor || entry.principal == *actor {
            gone.push(key);
        }
    }
    for key in gone {
        ASK_HISTORY.delete(&vault.store, wtxn, &key)?;
    }
    Ok(())
}
