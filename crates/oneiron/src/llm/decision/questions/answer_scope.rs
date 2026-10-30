//! OF-506 (FIX 1712, 1857): a caller reads its own standing question's
//! answers through its own live lane. A question may be saved under one
//! credential and read under a narrower one of the same principal; each
//! answer it holds then stays only while that lane reads every row the
//! answer names, the way a listing door leaves out a row whose ref the lane
//! does not read ([`crate::claim::ScopedRead::refs_readable_each`]).
//!
//! A full lane, one that freezes as its principal's own, reads every answer
//! exactly as before: no row is judged for it. Model trials read the stored
//! receipts directly ([`super::answer_records`]) and stay exempt, so a trial
//! never loses an answer to a caller's narrowing. Graph answers and artifact
//! asks pass the same filter, so the union stays one consistent reply.
//! Only the asker reads a question's answers: `store::owned_head` still
//! admits the record's principal alone, so a wider audience would need
//! that gate opened to it before any filter here judges its lane.

use super::question_answers;
use crate::claim::ScopedRead;
use crate::receipt::{QuestionAnswer, QuestionAnswersReply, QuestionAnswersRequest};
use crate::{EntityId, Result, Vault};

/// [`question_answers`] as `lane`, the caller's own live lane, reads them:
/// every answer for a full lane; for a narrowed one, each answer whose rows
/// the lane reads in one snapshot.
///
/// # Errors
/// As [`question_answers`], and a store failure judging the rows.
pub fn question_answers_in_lane(
    vault: &Vault,
    lane: &ScopedRead<'_>,
    principal: EntityId,
    request: &QuestionAnswersRequest,
) -> Result<QuestionAnswersReply> {
    let reply = question_answers(vault, principal, request)?;
    if lane.freeze().is_ok_and(|frozen| frozen.is_principal()) {
        return Ok(reply);
    }
    Ok(match reply {
        QuestionAnswersReply::All(answers) => QuestionAnswersReply::All(lane_reads(lane, answers)?),
        QuestionAnswersReply::Page(mut page) => {
            page.answers = lane_reads(lane, page.answers)?;
            QuestionAnswersReply::Page(page)
        }
    })
}

/// The answers `lane` reads every row of.
fn lane_reads(lane: &ScopedRead<'_>, answers: Vec<QuestionAnswer>) -> Result<Vec<QuestionAnswer>> {
    if answers.is_empty() {
        return Ok(answers);
    }
    let sets: Vec<Vec<EntityId>> = answers.iter().map(answer_rows).collect();
    let each = lane.refs_readable_each(&sets)?;
    Ok(answers
        .into_iter()
        .zip(each)
        .filter_map(|(answer, read)| read.then_some(answer))
        .collect())
}

/// The rows one answer names: a graph answer's claim, unit, evidence and
/// each neighbour it left out; an artifact ask's artifact and the proposal
/// its answers were held under.
fn answer_rows(answer: &QuestionAnswer) -> Vec<EntityId> {
    match answer {
        QuestionAnswer::Graph(answer) => answer
            .decision
            .evidence
            .iter()
            .copied()
            .chain([answer.claim, answer.unit])
            .chain(answer.omitted.iter().map(|omitted| omitted.id))
            .collect(),
        QuestionAnswer::Artifact(ask) => ask
            .proposal_ref
            .iter()
            .filter_map(|reference| EntityId::from_hex(reference).ok())
            .chain(std::iter::once(ask.artifact))
            .collect(),
    }
}
