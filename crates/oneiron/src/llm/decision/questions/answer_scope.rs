//! OF-506 (FIX 1712, 1857, 11827, 12060, 12171, 12285): a caller reads its
//! own standing question, its answers, and what a refresh, a backfill, its
//! outcome windows, labels and calibration pairs and a projection answer of
//! them, through its own live lane. A question may be saved under one
//! credential and read under a narrower one of the same principal; each item
//! a reply holds (a unit or artifact ask of the question itself included)
//! then stays only while that lane reads every row the item names, the way a
//! listing door leaves out a row whose ref the lane does not read
//! ([`crate::claim::ScopedRead::refs_readable_each`]), and so does each row
//! the question's saved lane names. What the verbs write is unchanged: a
//! refresh, a backfill and a projection run as they ran, and only their
//! replies are judged.
//!
//! A full lane, one that freezes as its principal's own, reads every reply
//! exactly as before: no row is judged for it. Model trials read the stored
//! receipts directly ([`super::answer_records`]) and stay exempt, so a trial
//! never loses an answer to a caller's narrowing. Graph answers and artifact
//! asks pass the same filter, so the union stays one consistent reply.
//! Only the asker reads a question's answers: `store::owned_head` still
//! admits the record's principal alone, so a wider audience would need
//! that gate opened to it before any filter here judges its lane.

use std::collections::BTreeSet;

use super::{
    ArtifactUnits, CalibrationPair, GraphQuestionInput, OutcomeLabel, OutcomeWindowClose,
    QuestionRecord, ScheduledBackfill, calibration_pairs, closed_outcome_windows, outcome_labels,
    project_bound_outcomes, question_answers, read_question, schedule_backfill,
};
use crate::blob_artifact::ArtifactAskUnits;
use crate::claim::ScopedRead;
use crate::receipt::{QuestionAnswer, QuestionAnswersReply, QuestionAnswersRequest};
use crate::settings::ReadDestination;
use crate::{EntityId, Result, Vault};

/// [`read_question`] as `lane`, the caller's own live lane, reads it (FIX
/// 12060, 12171, 12285): the whole record for a full lane; for a narrowed
/// one, the record with each unit, and each artifact ask, whose rows the
/// lane does not read left out, and its saved lane as the lane reads it
/// ([`crate::claim::FrozenReadLane::reader_view`]): its rows as the lane
/// reads them, its world, facet and audience ids as the lane's own bounds
/// cover them, all judged in one snapshot. An artifact ask names its
/// artifact and each file a folder ask reads.
///
/// # Errors
/// As [`read_question`], and a store failure judging the rows.
pub fn read_question_in_lane(
    vault: &Vault,
    lane: &ScopedRead<'_>,
    principal: EntityId,
    id: EntityId,
    version: Option<u32>,
) -> Result<Option<QuestionRecord>> {
    let record = read_question(vault, principal, id, version)?;
    if reads_as_principal(lane) {
        return Ok(record);
    }
    let Some(mut record) = record else {
        return Ok(None);
    };
    let lane_rows = record.read_lane.named_rows();
    let definition = &mut record.definition;
    let sets: Vec<Vec<EntityId>> = definition
        .units
        .iter()
        .map(|unit| vec![*unit])
        .chain(definition.artifacts.iter().map(artifact_ask_rows))
        .chain(lane_rows.iter().map(|row| vec![*row]))
        .collect();
    // The saved lane's scope ids are judged by the lane's own bounds, in the
    // same snapshot (FIX 12285): a base world is no stored row.
    let (each, bound) = lane.refs_readable_each_with_scope_id_bound(&sets)?;
    // One answer per set: units first, then artifact asks, then the saved
    // lane's rows, each in their order.
    let mut each = each.into_iter();
    definition.units.retain(|_| each.next().unwrap_or(false));
    definition
        .artifacts
        .retain(|_| each.next().unwrap_or(false));
    let read: BTreeSet<EntityId> = lane_rows
        .into_iter()
        .filter(|_| each.next().unwrap_or(false))
        .collect();
    record.read_lane = record
        .read_lane
        .reader_view(|row| read.contains(row), &bound);
    Ok(Some(record))
}

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

/// The rows one artifact ask of a question names: its artifact, and each
/// file a folder ask reads.
fn artifact_ask_rows(ask: &ArtifactUnits) -> Vec<EntityId> {
    let files: Vec<EntityId> = match &ask.selection {
        ArtifactAskUnits::FolderItems { items, .. } => items
            .iter()
            .filter_map(|item| EntityId::from_hex(&item.artifact_ref).ok())
            .collect(),
        ArtifactAskUnits::SheetRows { .. } | ArtifactAskUnits::Paragraphs { .. } => Vec::new(),
    };
    std::iter::once(ask.artifact).chain(files).collect()
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
