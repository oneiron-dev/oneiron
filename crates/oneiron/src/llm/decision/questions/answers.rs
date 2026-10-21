//! `vault.questions.answers` (FIX 1585, FIX 2337): one reader for every door that
//! serves it. Without a cursor it is every answer of the caller's standing question,
//! as one bare list, unpaged and uncapped, as it always was. A cursor opts into pages
//! over the question's ask log: graph answers first, then artifact asks, each in
//! commit order, across every version.
//!
//! The first page fixes the log's high-water mark, so a later answer or ask, whatever
//! its clock or claim id, is never in the read, and an edit or a newer stamp moves no
//! entry; an erased entry leaves it. The cursor is a position, never a grant: each
//! page checks the question is the caller's again, and the cursor names the question,
//! the caller and the vault's restore epoch, so a restore, which can roll the log back
//! under it, ends it. Where an artifact ask's answers stand is read live on each page.

use std::ops::Bound;

use base64::Engine;
use serde::{Deserialize, Serialize};

use super::artifact_refresh::{artifact_ask_records, artifact_event_record};
use super::ask_history::{
    ASK_HISTORY, ArtifactAskEvent, AskHistoryEvent, AskHistoryKey, ask_history_through_in_txn,
};
use super::records::AnswerRecord;
use super::store::{AnswerKey, QUESTION_ANSWER, owned_head};
use crate::receipt::{
    QuestionAnswer, QuestionAnswersPage, QuestionAnswersReply, QuestionAnswersRequest,
};
use crate::{EntityId, Error, Result, Vault};

/// The cursor's wire version.
const CURSOR_VERSION: u8 = 1;

/// Which part of the log a page reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Phase {
    Graph,
    Artifact,
}

/// Where a paged read stands: the log entries it covers end at `through`, and it has
/// consumed every one of `phase` up to `after`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    v: u8,
    question: EntityId,
    principal: EntityId,
    /// The latest restore epoch when the read began; none before the vault's first.
    epoch: Option<u64>,
    through: u64,
    phase: Phase,
    after: u64,
}

impl Cursor {
    fn encode(&self) -> Result<String> {
        let bytes = rmp_serde::to_vec_named(self)
            .map_err(|_| Error::InvariantViolation("question answers cursor encoding"))?;
        Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
    }

    /// The position `token` names, for this question, caller and epoch only.
    fn decode(
        token: &str,
        question: EntityId,
        principal: EntityId,
        epoch: Option<u64>,
    ) -> Result<Self> {
        let refused = || Error::InvalidConfig("not a cursor of this question's answers".into());
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(token)
            .map_err(|_| refused())?;
        let cursor: Self = rmp_serde::from_slice(&bytes).map_err(|_| refused())?;
        if cursor.v != CURSOR_VERSION
            || cursor.question != question
            || cursor.principal != principal
            || cursor.after > cursor.through
        {
            return Err(refused());
        }
        if cursor.epoch != epoch {
            return Err(Error::ConcurrentWrite(
                "the vault was restored since this read began; read again from an empty cursor",
            ));
        }
        Ok(cursor)
    }
}

/// The caller's standing question's answers, as `vault.questions.answers` serves them:
/// without a cursor, every graph answer receipt then every artifact ask, unpaged; with
/// one, the page it names, at most `page_size` entries when that is above 0. Another
/// principal's question is not found.
pub fn question_answers(
    vault: &Vault,
    principal: EntityId,
    request: &QuestionAnswersRequest,
) -> Result<QuestionAnswersReply> {
    let Some(token) = request.cursor.as_deref() else {
        let graph = super::answer_records(vault, principal, request.id)?;
        let asks = artifact_ask_records(vault, principal, request.id)?;
        return Ok(QuestionAnswersReply::All(QuestionAnswer::union(graph, asks)));
    };
    let limit = request.page_size.filter(|size| *size > 0);
    let (entries, next) = {
        let txn = vault.store.env.read_txn()?;
        owned_head(vault, &txn, principal, request.id)?;
        let epoch = crate::recovery::checkpoint::latest_restore_epoch_in_txn(vault, &txn)?;
        let cursor = if token.is_empty() {
            Cursor {
                v: CURSOR_VERSION,
                question: request.id,
                principal,
                epoch,
                through: ask_history_through_in_txn(vault, &txn, request.id)?,
                phase: Phase::Graph,
                after: 0,
            }
        } else {
            Cursor::decode(token, request.id, principal, epoch)?
        };
        page_in_txn(vault, &txn, cursor, limit)?
    };
    // An artifact ask's standing is read after the log's own read is closed.
    let mut answers = Vec::with_capacity(entries.len());
    for entry in entries {
        answers.push(match entry {
            Entry::Graph(answer) => QuestionAnswer::Graph(*answer),
            Entry::Artifact(event) => {
                QuestionAnswer::Artifact(artifact_event_record(vault, &event)?)
            }
        });
    }
    Ok(QuestionAnswersReply::Page(QuestionAnswersPage {
        answers,
        next_cursor: next.as_ref().map(Cursor::encode).transpose()?,
    }))
}

/// One page's entry, as the log's read finds it.
enum Entry {
    Graph(Box<AnswerRecord>),
    Artifact(Box<ArtifactAskEvent>),
}

/// The entries of the page `cursor` names, at most `limit` of them, and the cursor of
/// the next page, none when the read is done. An entry that no longer resolves (an
/// erased answer) or is not the caller's is passed over; the page stops before an
/// entry it has no room for, so the next page starts there.
fn page_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    mut cursor: Cursor,
    limit: Option<usize>,
) -> Result<(Vec<Entry>, Option<Cursor>)> {
    let question = cursor.question;
    let mut entries = Vec::new();
    loop {
        let start = AskHistoryKey {
            question,
            sequence: cursor.after,
        };
        let end = AskHistoryKey {
            question,
            sequence: cursor.through,
        };
        if cursor.after < cursor.through {
            let rows = ASK_HISTORY.iter_range(
                &vault.store,
                txn,
                Bound::Excluded(&start),
                Bound::Included(&end),
            )?;
            for row in rows {
                let (key, record) = row?;
                let entry = if record.principal == cursor.principal {
                    entry_in_txn(vault, txn, question, cursor.phase, record.event)?
                } else {
                    None
                };
                if let Some(entry) = entry {
                    if limit.is_some_and(|limit| entries.len() >= limit) {
                        return Ok((entries, Some(cursor)));
                    }
                    entries.push(entry);
                }
                cursor.after = key.sequence;
            }
        }
        match cursor.phase {
            Phase::Graph => {
                cursor.phase = Phase::Artifact;
                cursor.after = 0;
            }
            Phase::Artifact => return Ok((entries, None)),
        }
    }
}

/// `event` as an entry of a `phase` page: a graph answer that still resolves on the
/// graph page, an artifact ask on the artifact page, none else.
fn entry_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    question: EntityId,
    phase: Phase,
    event: AskHistoryEvent,
) -> Result<Option<Entry>> {
    Ok(match (phase, event) {
        (Phase::Graph, AskHistoryEvent::Graph { claim }) => QUESTION_ANSWER
            .get(&vault.store, txn, &AnswerKey { question, claim })?
            .map(|answer| Entry::Graph(Box::new(answer))),
        (Phase::Artifact, AskHistoryEvent::Artifact(event)) => Some(Entry::Artifact(event)),
        _ => None,
    })
}
