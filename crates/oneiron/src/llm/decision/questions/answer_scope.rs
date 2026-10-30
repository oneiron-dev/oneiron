//! OF-506 (FIX 1712, 1857, 11827): a caller reads its own standing
//! question's answers, and what a refresh, a backfill, its outcome windows,
//! labels and calibration pairs and a projection answer of them, through its
//! own live lane. A question may be saved under one credential and read under
//! a narrower one of the same principal; each item a reply holds then stays
//! only while that lane reads every row the item names, the way a listing
//! door leaves out a row whose ref the lane does not read
//! ([`crate::claim::ScopedRead::refs_readable_each`]). What the verbs write
//! is unchanged: a refresh, a backfill and a projection run as they ran, and
//! only their replies are judged.
//!
//! A full lane, one that freezes as its principal's own, reads every reply
//! exactly as before: no row is judged for it. Model trials read the stored
//! receipts directly ([`super::answer_records`]) and stay exempt, so a trial
//! never loses an answer to a caller's narrowing. Graph answers and artifact
//! asks pass the same filter, so the union stays one consistent reply.
//! Only the asker reads a question's answers: `store::owned_head` still
//! admits the record's principal alone, so a wider audience would need
//! that gate opened to it before any filter here judges its lane.

use super::{
    CalibrationPair, GraphQuestionInput, OutcomeLabel, OutcomeWindowClose, ScheduledBackfill,
    calibration_pairs, closed_outcome_windows, outcome_labels, project_bound_outcomes,
    question_answers, schedule_backfill,
};
use crate::claim::ScopedRead;
use crate::receipt::{QuestionAnswer, QuestionAnswersReply, QuestionAnswersRequest};
use crate::settings::ReadDestination;
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
    if reads_as_principal(lane) {
        return Ok(reply);
    }
    Ok(match reply {
        QuestionAnswersReply::All(answers) => {
            QuestionAnswersReply::All(lane_keeps(lane, answers, answer_rows)?)
        }
        QuestionAnswersReply::Page(mut page) => {
            page.answers = lane_keeps(lane, page.answers, answer_rows)?;
            QuestionAnswersReply::Page(page)
        }
    })
}

/// `answers`, a refresh by hand's reply, as `lane` reads them (FIX 11827):
/// every answer for a full lane; for a narrowed one, each answer whose rows
/// the lane reads in one snapshot, as [`question_answers_in_lane`] keeps
/// them.
///
/// # Errors
/// A store failure judging the rows.
pub fn answers_in_lane(
    lane: &ScopedRead<'_>,
    answers: Vec<QuestionAnswer>,
) -> Result<Vec<QuestionAnswer>> {
    if reads_as_principal(lane) {
        return Ok(answers);
    }
    lane_keeps(lane, answers, answer_rows)
}

/// [`schedule_backfill`], its reply as `lane` reads it (FIX 11827): the
/// backfill is scheduled as asked; for a narrowed lane the reply names each
/// join whose unit and evidence the lane reads.
///
/// # Errors
/// As [`schedule_backfill`], and a store failure judging the rows.
pub fn schedule_backfill_in_lane(
    vault: &Vault,
    lane: &ScopedRead<'_>,
    principal: EntityId,
    question: EntityId,
    expected_version: u32,
    due_at: u64,
    joins: Vec<GraphQuestionInput>,
) -> Result<ScheduledBackfill> {
    let mut backfill =
        schedule_backfill(vault, principal, question, expected_version, due_at, joins)?;
    if !reads_as_principal(lane) {
        backfill.joins = lane_keeps(lane, backfill.joins, |join| {
            std::iter::once(join.unit)
                .chain(join.evidence.iter().copied())
                .collect()
        })?;
    }
    Ok(backfill)
}

/// [`closed_outcome_windows`] as `lane` reads them (FIX 11827): every window
/// for a full lane; for a narrowed one, each window whose answer the lane
/// reads.
///
/// # Errors
/// As [`closed_outcome_windows`], and a store failure judging the rows.
pub fn closed_outcome_windows_in_lane(
    vault: &Vault,
    lane: &ScopedRead<'_>,
    principal: EntityId,
    question: EntityId,
) -> Result<Vec<OutcomeWindowClose>> {
    let windows = closed_outcome_windows(vault, principal, question)?;
    if reads_as_principal(lane) {
        return Ok(windows);
    }
    lane_keeps(lane, windows, |close| vec![close.answer])
}

/// [`outcome_labels`] as `lane` reads them (FIX 11827): every label for a
/// full lane; for a narrowed one, each label whose answer and fact the lane
/// reads.
///
/// # Errors
/// As [`outcome_labels`], and a store failure judging the rows.
pub fn outcome_labels_in_lane(
    vault: &Vault,
    lane: &ScopedRead<'_>,
    principal: EntityId,
    question: EntityId,
    destination: impl Into<ReadDestination>,
) -> Result<Vec<OutcomeLabel>> {
    let labels = outcome_labels(vault, principal, question, destination)?;
    if reads_as_principal(lane) {
        return Ok(labels);
    }
    lane_keeps(lane, labels, label_rows)
}

/// [`calibration_pairs`] as `lane` reads them (FIX 11827): every pair for a
/// full lane; for a narrowed one, each pair whose rows the lane reads: every
/// row it was derived from but the question itself, which lives in a side
/// table and is no row.
///
/// # Errors
/// As [`calibration_pairs`], and a store failure judging the rows.
pub fn calibration_pairs_in_lane(
    vault: &Vault,
    lane: &ScopedRead<'_>,
    principal: EntityId,
    question: EntityId,
    destination: impl Into<ReadDestination>,
) -> Result<Vec<CalibrationPair>> {
    let pairs = calibration_pairs(vault, principal, question, destination)?;
    if reads_as_principal(lane) {
        return Ok(pairs);
    }
    lane_keeps(lane, pairs, |pair| {
        pair.derived_from
            .iter()
            .copied()
            .filter(|row| *row != question)
            .collect()
    })
}

/// [`project_bound_outcomes`], its count as `lane` reads it (FIX 11827): the
/// projection binds as it binds for anyone; for a narrowed lane the count is
/// of the newly bound labels whose answer and fact the lane reads.
///
/// # Errors
/// As [`project_bound_outcomes`], and a store failure judging the rows.
pub fn project_bound_outcomes_in_lane(
    vault: &Vault,
    lane: &ScopedRead<'_>,
    principal: EntityId,
    question: EntityId,
) -> Result<usize> {
    if reads_as_principal(lane) {
        return project_bound_outcomes(vault, principal, question);
    }
    let bound = super::outcomes::project_bound_labels(vault, principal, question)?;
    Ok(lane_keeps(lane, bound, label_rows)?.len())
}

/// Whether `lane` freezes as its principal's own: a full lane, whose replies
/// are judged on no row.
fn reads_as_principal(lane: &ScopedRead<'_>) -> bool {
    lane.freeze().is_ok_and(|frozen| frozen.is_principal())
}

/// The items `lane` reads every row of, as `rows` names each, in one
/// snapshot.
fn lane_keeps<T>(
    lane: &ScopedRead<'_>,
    items: Vec<T>,
    rows: impl Fn(&T) -> Vec<EntityId>,
) -> Result<Vec<T>> {
    if items.is_empty() {
        return Ok(items);
    }
    let sets: Vec<Vec<EntityId>> = items.iter().map(rows).collect();
    let each = lane.refs_readable_each(&sets)?;
    Ok(items
        .into_iter()
        .zip(each)
        .filter_map(|(item, read)| read.then_some(item))
        .collect())
}

/// The rows one outcome label names: the answer it labels and its fact.
fn label_rows(label: &OutcomeLabel) -> Vec<EntityId> {
    vec![label.answer, label.fact]
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
