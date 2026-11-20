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
    QuestionRecord, ScheduledBackfill, project_bound_outcomes, question_answers, read_question,
    schedule_backfill,
};
use crate::blob_artifact::ArtifactAskUnits;
use crate::claim::ScopedRead;
use crate::receipt::{
    QuestionAnswer, QuestionAnswersReply, QuestionAnswersRequest, QuestionOutcomes,
};
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

/// [`closed_outcome_windows`](super::closed_outcome_windows) as `lane` reads
/// them (FIX 11827): every window that still reads as it closed for a full
/// lane, each judged again under its saved lane as the principal's live
/// authority reads it (FIX STORED-OUTCOME-READS-SKIP-SAVED-LANE); for a
/// narrowed one, each of those whose rows the lane reads: the answer and its
/// unit, and for a window that closed observed every row one standing label
/// of its answer was derived from. The windows are read, and their rows
/// judged, in one snapshot of `lane`, a lane of `vault`, opened as its own
/// reads open theirs (FIX QUESTION-OUTCOMES-REPLY-SPANS-SNAPSHOTS).
///
/// # Errors
/// As [`closed_outcome_windows`](super::closed_outcome_windows), and a store
/// failure judging the rows.
pub fn closed_outcome_windows_in_lane(
    vault: &Vault,
    lane: &ScopedRead<'_>,
    principal: EntityId,
    question: EntityId,
) -> Result<Vec<OutcomeWindowClose>> {
    lane.with_grant_read_snapshot(|txn| -> Result<Vec<OutcomeWindowClose>> {
        let windows = super::windows::standing_windows_in_txn(vault, txn, principal, question)?;
        if reads_as_principal_in(lane, txn) {
            return Ok(windows.into_iter().map(|window| window.close).collect());
        }
        if windows.is_empty() {
            return Ok(Vec::new());
        }
        // Each row set a window rests on, every window's in turn.
        let sets: Vec<Vec<EntityId>> = windows
            .iter()
            .flat_map(|window| window.rests_on.iter())
            .map(|rows| rows_beside(question, rows))
            .collect();
        let mut each = lane.refs_readable_each_in(txn, &sets)?.into_iter();
        let mut kept = Vec::new();
        for window in windows {
            let mut read = false;
            for _ in &window.rests_on {
                read |= each.next().unwrap_or(false);
            }
            if read {
                kept.push(window.close);
            }
        }
        Ok(kept)
    })
}

/// `vault.questions.outcomes`' reply as `lane`, a lane of `vault`, reads it:
/// the labels of [`outcome_labels_in_lane`] and the pairs of
/// [`calibration_pairs_in_lane`], both read and judged in one snapshot of
/// the lane, opened as its own reads open theirs, under one judgment of
/// whether it reads as its principal's own (FIX
/// QUESTION-OUTCOMES-REPLY-SPANS-SNAPSHOTS). So a status, value or grant
/// change committed while the reply is read never serves a label beside no
/// pair the same state would pair, nor an item judged in one state and its
/// rows in another.
///
/// # Errors
/// As [`outcome_labels_in_lane`] and [`calibration_pairs_in_lane`].
pub fn question_outcomes_in_lane(
    vault: &Vault,
    lane: &ScopedRead<'_>,
    principal: EntityId,
    question: EntityId,
    destination: impl Into<ReadDestination>,
) -> Result<QuestionOutcomes> {
    let destination = destination.into();
    lane.with_grant_read_snapshot(|txn| -> Result<QuestionOutcomes> {
        let full = reads_as_principal_in(lane, txn);
        Ok(QuestionOutcomes {
            labels: labels_lane_reads_in_txn(
                vault,
                lane,
                txn,
                full,
                principal,
                question,
                &destination,
            )?,
            calibration: pairs_lane_reads_in_txn(
                vault,
                lane,
                txn,
                full,
                principal,
                question,
                &destination,
            )?,
        })
    })
}

/// [`outcome_labels`](super::outcome_labels) as `lane` reads them (FIX
/// 11827): every label that still stands for a full lane, each judged again
/// under its saved lane as the principal's live authority reads it (FIX
/// STORED-OUTCOME-READS-SKIP-SAVED-LANE); for a narrowed one, each of those
/// whose rows the lane reads: every row it was derived from but the question,
/// as a calibration pair's. Read and judged in one snapshot of `lane`, a
/// lane of `vault` ([`question_outcomes_in_lane`] reads them beside the
/// pairs in one).
///
/// # Errors
/// As [`outcome_labels`](super::outcome_labels), and a store failure judging
/// the rows.
pub fn outcome_labels_in_lane(
    vault: &Vault,
    lane: &ScopedRead<'_>,
    principal: EntityId,
    question: EntityId,
    destination: impl Into<ReadDestination>,
) -> Result<Vec<OutcomeLabel>> {
    let destination = destination.into();
    lane.with_grant_read_snapshot(|txn| {
        let full = reads_as_principal_in(lane, txn);
        labels_lane_reads_in_txn(vault, lane, txn, full, principal, question, &destination)
    })
}

/// [`calibration_pairs`](super::calibration_pairs) as `lane` reads them (FIX
/// 11827): every pair for a full lane; for a narrowed one, each pair whose
/// rows the lane reads: every row it was derived from but the question
/// itself, which lives in a side table and is no row. Read and judged in one
/// snapshot of `lane`, a lane of `vault` ([`question_outcomes_in_lane`] reads
/// them beside the labels in one).
///
/// # Errors
/// As [`calibration_pairs`](super::calibration_pairs), and a store failure
/// judging the rows.
pub fn calibration_pairs_in_lane(
    vault: &Vault,
    lane: &ScopedRead<'_>,
    principal: EntityId,
    question: EntityId,
    destination: impl Into<ReadDestination>,
) -> Result<Vec<CalibrationPair>> {
    let destination = destination.into();
    lane.with_grant_read_snapshot(|txn| {
        let full = reads_as_principal_in(lane, txn);
        pairs_lane_reads_in_txn(vault, lane, txn, full, principal, question, &destination)
    })
}

/// [`outcome_labels_in_lane`] in the caller's snapshot `txn` of `lane`,
/// `full` saying whether the lane reads as its principal's own there.
fn labels_lane_reads_in_txn(
    vault: &Vault,
    lane: &ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    full: bool,
    principal: EntityId,
    question: EntityId,
    destination: &ReadDestination,
) -> Result<Vec<OutcomeLabel>> {
    let labels = super::outcomes::outcome_labels_with_rows_in_txn(
        vault,
        txn,
        principal,
        question,
        destination,
    )?;
    let labels = if full {
        labels
    } else {
        lane_keeps_in(lane, txn, labels, |(_, rows)| rows_beside(question, rows))?
    };
    Ok(labels.into_iter().map(|(label, _)| label).collect())
}

/// [`calibration_pairs_in_lane`] in the caller's snapshot `txn` of `lane`,
/// `full` saying whether the lane reads as its principal's own there.
fn pairs_lane_reads_in_txn(
    vault: &Vault,
    lane: &ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    full: bool,
    principal: EntityId,
    question: EntityId,
    destination: &ReadDestination,
) -> Result<Vec<CalibrationPair>> {
    let pairs =
        super::outcomes::calibration_pairs_in_txn(vault, txn, principal, question, destination)?;
    if full {
        return Ok(pairs);
    }
    lane_keeps_in(lane, txn, pairs, |pair| {
        rows_beside(question, &pair.derived_from)
    })
}

/// `rows` but `question`, which lives in a side table and is no row.
fn rows_beside(question: EntityId, rows: &[EntityId]) -> Vec<EntityId> {
    rows.iter()
        .copied()
        .filter(|row| *row != question)
        .collect()
}

/// [`project_bound_outcomes`], its count as `lane` reads it (FIX 11827): the
/// projection binds as it binds for anyone; for a narrowed lane the count is
/// of the newly bound labels that stand and whose rows the lane reads: every
/// row each was derived from but the question, as [`outcome_labels_in_lane`]
/// judges a label (FIX STORED-OUTCOME-READS-SKIP-SAVED-LANE).
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
    Ok(lane_keeps(lane, bound, |(_, rows)| rows_beside(question, rows))?.len())
}

/// Whether `lane` freezes as its principal's own: a full lane, whose replies
/// are judged on no row. A full lane held to a credential whose grant must
/// stand ([`crate::claim::FrozenReadLane::reads_as_principal`]) is one only
/// while that credential holds now (FIX OWN-DEVICE-GRANT-NOT-RECHECKED);
/// otherwise each reply is judged on its rows, and a lapsed credential reads
/// none of them.
fn reads_as_principal(lane: &ScopedRead<'_>) -> bool {
    reads_as_principal_while(lane, || {
        lane.vault()
            .store
            .env
            .read_txn()
            .is_ok_and(|txn| lane.credential_live_in(&txn).unwrap_or(false))
    })
}

/// [`reads_as_principal`], its credential judged in the caller's snapshot
/// `txn`, the one the reply is read in.
fn reads_as_principal_in(lane: &ScopedRead<'_>, txn: &heed::RoTxn<'_>) -> bool {
    reads_as_principal_while(lane, || lane.credential_live_in(txn).unwrap_or(false))
}

/// Whether `lane` freezes as its principal's own, a lane held to a
/// credential whose grant must stand only while `credential_live` says
/// that credential holds.
fn reads_as_principal_while(lane: &ScopedRead<'_>, credential_live: impl FnOnce() -> bool) -> bool {
    match lane.freeze() {
        Ok(frozen) if frozen.is_principal() => true,
        Ok(frozen) if frozen.reads_as_principal() => credential_live(),
        _ => false,
    }
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
    lane.with_grant_read_snapshot(|txn| lane_keeps_in(lane, txn, items, rows))
}

/// [`lane_keeps`] in the caller's snapshot `txn` of `lane`, the one its
/// items were read in.
fn lane_keeps_in<T>(
    lane: &ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    items: Vec<T>,
    rows: impl Fn(&T) -> Vec<EntityId>,
) -> Result<Vec<T>> {
    if items.is_empty() {
        return Ok(items);
    }
    let sets: Vec<Vec<EntityId>> = items.iter().map(rows).collect();
    let each = lane.refs_readable_each_in(txn, &sets)?;
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
