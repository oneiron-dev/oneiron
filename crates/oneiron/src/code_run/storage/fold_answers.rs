//! Recorded fold answers whose words a withdrawal took (FIX 18924).
//!
//! A `describe({fold})` answer copies the fold's accepted summary. The run
//! that asked keeps the answer in its replay record, an action keeps it in
//! its own, and a continuation copies it into its child's. Each answer names
//! the folds it copies the words of ([`FoldWordRef`]), stamped from the
//! ledger that answered it, so this module finds a copy by that name and
//! never by its text. No other table or index records where the copies are.
//!
//! A withdrawal of a fold's words takes every recorded answer that copied
//! them in the withdrawing writer ([`retire_fold_answers_in_txn`]). The call
//! fails with `response_erased` under its own effect, as an erase of its
//! run's actor leaves it, and keeps the folds it named. Its request, seq,
//! times, action digest and row receipt stay, and so do the run's other
//! calls and outputs. A body the answer spilled to is released and retired, and
//! its preview reads erased. Replay then traps on the call: it never takes
//! a fresh ledger answer in its place.
//!
//! A replay write that still carries a withdrawn answer meets the same test
//! in its writer ([`fence_fold_answers_in_txn`]). A room's row is the room's
//! own until close, so its reads and its writes take the test through the
//! room's composed view instead ([`SessionBinding::composed_fold_answers`]).

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};

use heed::{RoTxn, RwTxn};

use super::super::replay::{CodeRunReplayRecord, ResultOccurrence};
use super::records::REPLAY_RECORDS;
use super::replay_bodies::{CODE_RUN_OUTPUT_PREVIEW_ERASED, RESPONSE_ERASED};
use super::response_erase::release_occurrence_in_txn;
use super::routing::SessionBinding;
use crate::code_run::payload::{
    answer_fold_words, keep_erased_fold_words, keep_row_receipt, push_fold_word, row_receipt,
    self_dispatch_outcome_value,
};
use crate::code_run::{FoldAnswer, FoldWordRef, SelfDispatchOutcome, SelfEffect, SelfFailedResult};
use crate::engine_executor::bridge_result_output_path;
use crate::side_table::{Erased, SideKey};
use crate::store::{ManifestDbs, Store};
use crate::{EntityId, Result, Vault};

/// Whether a withdrawal took the words of a fold `answer` copies, as the
/// vault reads now (FIX 18924): a cached action's replay fails such an
/// answer with `response_erased` rather than return it.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn fold_answer_withdrawn(vault: &Vault, answer: &FoldAnswer) -> Result<bool> {
    if answer.words.is_empty() {
        return Ok(false);
    }
    let rtxn = vault.store.env.read_txn()?;
    words_withdrawn(&vault.store, &rtxn, &answer.words)
}

/// One recorded fold answer whose words are withdrawn: its call's place in
/// the record, and the folds it named.
pub(crate) struct WithdrawnFoldAnswer {
    call: usize,
    words: Vec<FoldWordRef>,
}

/// Whether the words of any fold `words` names are withdrawn as read
/// through `dbs`, by the ledger fence's own test. A capsule's bodies take
/// the same test (FIX 18924).
pub(super) fn words_withdrawn(
    dbs: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    words: &[FoldWordRef],
) -> Result<bool> {
    for word in words {
        if crate::compaction::fold_words_withdrawn_in(
            dbs,
            txn,
            word.source_run,
            word.fold,
            &word.sources,
        )? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The fold answers in `record` whose words are withdrawn as read through
/// `dbs`; with `source_run`, only those that name a fold of that run. An
/// answer that names no fold, or whose names do not decode, is kept.
fn withdrawn_answers(
    dbs: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    record: &CodeRunReplayRecord,
    source_run: Option<EntityId>,
) -> Result<Vec<WithdrawnFoldAnswer>> {
    let mut withdrawn = Vec::new();
    for (call, row) in record.bridge_calls.iter().enumerate() {
        if row.effect != SelfEffect::Fold {
            continue;
        }
        let Some(words) = answer_fold_words(&row.outcome) else {
            continue;
        };
        let named = source_run.is_none_or(|run| words.iter().any(|word| word.source_run == run));
        if !words.is_empty() && named && words_withdrawn(dbs, txn, &words)? {
            withdrawn.push(WithdrawnFoldAnswer { call, words });
        }
    }
    Ok(withdrawn)
}

/// The paths of the bodies `answers` spilled to that `record` holds: each
/// at its call's bridge result path.
fn spilled_paths(
    record: &CodeRunReplayRecord,
    answers: &[WithdrawnFoldAnswer],
) -> BTreeSet<String> {
    let paths: BTreeSet<String> = answers
        .iter()
        .filter_map(|answer| record.bridge_calls.get(answer.call))
        .map(|row| bridge_result_output_path(row.seq))
        .collect();
    record
        .outputs
        .iter()
        .filter(|output| paths.contains(&output.path))
        .map(|output| output.path.clone())
        .collect()
}

/// Takes each of `answers` from `record` (FIX 18924): its call fails with
/// `response_erased` under its own effect and keeps the folds it named and
/// the row receipt its outcome kept, and the preview of the body it spilled
/// to reads erased. Every call keeps its request, seq, effect, times and
/// action digest; every other outcome and output stays as it was. The
/// record's decoded-row memos start cold.
///
/// # Errors
///
/// An erased outcome that does not encode.
pub(crate) fn redact_fold_answers(
    record: &mut CodeRunReplayRecord,
    answers: &[WithdrawnFoldAnswer],
) -> Result<()> {
    if answers.is_empty() {
        return Ok(());
    }
    let spilled = spilled_paths(record, answers);
    for answer in answers {
        let Some(row) = record.bridge_calls.get_mut(answer.call) else {
            continue;
        };
        let receipt = row_receipt(&row.outcome);
        row.outcome =
            self_dispatch_outcome_value(&SelfDispatchOutcome::Failed(SelfFailedResult {
                effect: row.effect,
                error: RESPONSE_ERASED.to_owned(),
                code: None,
                disk_floor: None,
            }))?;
        keep_erased_fold_words(&mut row.outcome, &answer.words);
        if let Some(receipt) = receipt {
            keep_row_receipt(&mut row.outcome, &receipt);
        }
    }
    for output in &mut record.outputs {
        if spilled.contains(&output.path) {
            output.preview.text = CODE_RUN_OUTPUT_PREVIEW_ERASED.to_owned();
        }
    }
    record.invalidate_verb_rows();
    Ok(())
}

/// Takes every recorded fold answer whose words are withdrawn here, in the
/// withdrawing writer (FIX 18924); with `source_run`, only the answers that
/// name a fold of that run. Each base replay record is read, a run's own,
/// an action's and a continuation child's alike, and each one holding such
/// an answer is put back with [`redact_fold_answers`]'s form, past the
/// side-row wall. The body each answer spilled to is withdrawn as its run's
/// occurrence, released with its own marks, and its instance retired, or
/// owed to another holder's release. A record that does not decode is left
/// as it is. Each capsule body that copies the words retires first, in the
/// same writer (`replay_capsule::fold_words`), and every checkpoint image
/// whose owners name a withdrawn fold that a reached copy named retires
/// beside them ([`retire_fold_word_images_in_txn`]).
///
/// # Errors
///
/// Storage and custody errors.
pub(crate) fn retire_fold_answers_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    source_run: Option<EntityId>,
) -> Result<()> {
    let mut reached =
        super::replay_capsule::retire_fold_word_capsules_in_txn(store, wtxn, source_run)?;
    let mut records = Vec::new();
    let txn: &RoTxn<'_> = wtxn;
    for row in REPLAY_RECORDS.iter_raw_from(store, txn, &[])? {
        let (key, bytes) = row?;
        let Some(id) = <EntityId as SideKey>::decode_key(&key) else {
            continue;
        };
        let Ok(record) = REPLAY_RECORDS.decode_value(&bytes) else {
            continue;
        };
        let answers = withdrawn_answers(store, txn, &record, source_run)?;
        if !answers.is_empty() {
            records.push((id, record, answers));
        }
    }
    let named = records.iter().flat_map(|(_, _, answers)| answers);
    for word in named.flat_map(|answer| answer.words.iter()) {
        push_fold_word(&mut reached, word.clone());
    }
    retire_fold_word_images_in_txn(store, wtxn, &reached)?;
    if records.is_empty() {
        return Ok(());
    }
    let at = crate::ports::recorded_at_in_txn(store, wtxn)?;
    let mut released: BTreeMap<EntityId, BTreeSet<[u8; 32]>> = BTreeMap::new();
    for (id, record, answers) in records {
        let spilled = spilled_paths(&record, &answers);
        for output in record
            .outputs
            .iter()
            .filter(|output| spilled.contains(&output.path))
        {
            let occurrence = ResultOccurrence::owned(record.run_id, &output.path)?;
            crate::ports::stage_stale_mark_in_txn(store, wtxn, &occurrence.id(), at)?;
            if let Some(digest) = release_occurrence_in_txn(
                store,
                wtxn,
                record.run_id,
                output.path.clone(),
                output.handle.clone(),
            )? {
                released.entry(record.run_id).or_default().insert(digest);
            }
        }
        REPLAY_RECORDS.put_erased(
            store,
            wtxn,
            &id,
            Erased::code_run_fold_answers(record, &answers)?,
        )?;
    }
    for (owner, digests) in released {
        let digests: Vec<[u8; 32]> = digests.into_iter().collect();
        crate::store::erase_bodies_in_txn(store, wtxn, &owner, &digests)?;
    }
    Ok(())
}

/// Retires every checkpoint image whose owners name the words of a fold
/// among `words` that a withdrawal took here (FIX 18924), a historical one
/// too: each instance retires, or is owed to another holder, as an erase of
/// that owner leaves it, and a row still bound to one is carried again
/// under a fresh instance. A fold whose words stand is left as it is.
///
/// # Errors
///
/// Storage and custody errors.
fn retire_fold_word_images_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    words: &[FoldWordRef],
) -> Result<()> {
    let mut retired = BTreeSet::new();
    for word in words {
        let owner = crate::compaction::fold_words_id(word.source_run, word.fold);
        if retired.contains(&owner) || !words_withdrawn(store, wtxn, std::slice::from_ref(word))? {
            continue;
        }
        crate::store::erase_response_owner_in_txn(store, wtxn, &owner)?;
        retired.insert(owner);
    }
    Ok(())
}

/// `record` as its base writer may put it (FIX 18924): a fold answer whose
/// words are withdrawn takes [`redact_fold_answers`]'s form, so a copy read
/// before the withdrawal never writes the words back. The body each such
/// answer spilled to is withdrawn as its run's occurrence; the sourced-output
/// fence that follows in the same writer releases and retires it.
///
/// # Errors
///
/// Storage errors, and an erased outcome that does not encode.
pub(super) fn fence_fold_answers_in_txn<'r>(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    mut record: Cow<'r, CodeRunReplayRecord>,
) -> Result<Cow<'r, CodeRunReplayRecord>> {
    let answers = withdrawn_answers(store, wtxn, &record, None)?;
    if answers.is_empty() {
        return Ok(record);
    }
    let spilled = spilled_paths(&record, &answers);
    if !spilled.is_empty() {
        let at = crate::ports::recorded_at_in_txn(store, wtxn)?;
        for path in &spilled {
            let occurrence = ResultOccurrence::owned(record.run_id, path)?;
            crate::ports::stage_stale_mark_in_txn(store, wtxn, &occurrence.id(), at)?;
        }
    }
    redact_fold_answers(record.to_mut(), &answers)?;
    Ok(record)
}

/// Records reply body occurrence `occurrence`, which copies the words of
/// records `sources`, as a dependent of each of them in its publishing
/// writer (FIX 18924): a withdrawal of one walks to it, as to the fold's
/// own words, and every read of the occurrence then reads it withdrawn. A
/// source already gone or withdrawn here has run its walk, so the
/// occurrence is born withdrawn and takes no dependency row on it.
///
/// # Errors
///
/// Storage errors.
pub(super) fn record_reply_sources_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    occurrence: &EntityId,
    sources: &[EntityId],
) -> Result<()> {
    let mut born_withdrawn = false;
    for source in sources {
        if crate::ports::EntityStoreRead::port_entity_record(store, wtxn, source)?.is_none()
            || crate::ports::withdrawn_in_txn(store, wtxn, source)?
        {
            born_withdrawn = true;
        } else {
            crate::ports::record_derived_edge_in_txn(store, wtxn, occurrence, source)?;
        }
    }
    if born_withdrawn {
        let at = crate::ports::recorded_at_in_txn(store, wtxn)?;
        crate::ports::stage_stale_mark_in_txn(store, wtxn, occurrence, at)?;
    }
    Ok(())
}

impl SessionBinding<'_> {
    /// `record` as the room's composed view may keep it (FIX 18924): each
    /// fold answer whose words a withdrawal in base or in the room took
    /// takes [`redact_fold_answers`]'s form. Base erasure never rewrites a
    /// room's overlay row, so the room's replay reads and writes take this
    /// fence instead.
    ///
    /// # Errors
    ///
    /// Storage errors, and an erased outcome that does not encode.
    pub(super) fn composed_fold_answers<'r>(
        &self,
        mut record: Cow<'r, CodeRunReplayRecord>,
    ) -> Result<Cow<'r, CodeRunReplayRecord>> {
        let answers = self
            .session
            .read_composed(|view, rtxn| withdrawn_answers(view, rtxn, &record, None))?;
        if !answers.is_empty() {
            redact_fold_answers(record.to_mut(), &answers)?;
        }
        Ok(record)
    }

    /// The replay record of run `run_id` as the room reads it, through
    /// [`Self::composed_fold_answers`]'s fence, in one composed snapshot.
    ///
    /// # Errors
    ///
    /// The participant check's refusal, and storage errors.
    pub(super) fn composed_replay_record(
        &self,
        run_id: &EntityId,
    ) -> Result<Option<CodeRunReplayRecord>> {
        self.answered(|| {
            self.session.read_composed(|view, rtxn| {
                let Some(mut record) = REPLAY_RECORDS.get(view, rtxn, run_id)? else {
                    return Ok(None);
                };
                let answers = withdrawn_answers(view, rtxn, &record, None)?;
                redact_fold_answers(&mut record, &answers)?;
                Ok(Some(record))
            })
        })
    }
}
