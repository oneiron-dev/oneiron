//! A withdrawal of fold words over the capsules that copy them (FIX 18924).
//!
//! A capsule names, for its request, its start and its context, the folds
//! whose accepted summaries that body copies. A withdrawal of one fold's
//! words reaches each capsule by those names, never by a fold id read from
//! its text, in the withdrawing writer. Each body it reaches retires: the
//! run's occurrence is released with its own marks, its instance retires,
//! or is owed to another holder's release, and the capsule marks the body
//! erased. A request's pieces that no request the run still keeps for the
//! actor names go too, and so do a start's pieces that no start the run
//! still keeps for the actor names (FIX 4192). Nothing is rewritten: no
//! new start, request or context is written in place of a retired one, so
//! a continuation, a shadow arm and a fork meet the body as erased
//! (`NoCheckpoint`, `SourceErased`). The capsule keeps what the step was,
//! its actor, its route prompt and its other bodies.

use std::collections::{BTreeMap, BTreeSet};

use heed::RwTxn;

use super::super::super::replay::CodeRunRawOutput;
use super::super::super::replay_capsule::{CapsuleRequest, StepReplayCapsule};
use super::super::fold_answers::words_withdrawn;
use super::super::response_erase::release_occurrence_in_txn;
use super::CAPSULES;
use super::pieces::{PieceScope, manifest_pieces_in_txn, release_retired_pieces_in_txn};
use super::start_pieces::{release_unnamed_start_pieces_in_txn, start_manifest_pieces_in_txn};
use crate::code_run::{FoldWordRef, push_fold_word};
use crate::compaction::output::OutputRef;
use crate::side_table::SideKey;
use crate::store::{ManifestDbs, Store};
use crate::{EntityId, Result};

/// A capsule's key: its attempt, lease generation and step.
type CapsuleKey = (EntityId, u64, u64);

/// Which of one capsule's bodies a withdrawal reached.
struct Reached {
    request: bool,
    start: bool,
    context: bool,
}

impl Reached {
    const fn any(&self) -> bool {
        self.request || self.start || self.context
    }
}

/// Whether the withdrawal reaches the body that copies `words`: with
/// `source_run`, only when they name a fold of that run, and only when a
/// fold they name is withdrawn, which is then added to `withdrawn`.
fn reaches(
    dbs: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    words: &[FoldWordRef],
    source_run: Option<EntityId>,
    withdrawn: &mut Vec<FoldWordRef>,
) -> Result<bool> {
    let named = source_run.is_none_or(|run| words.iter().any(|word| word.source_run == run));
    if words.is_empty() || !named {
        return Ok(false);
    }
    let mut reached = false;
    for word in words {
        if words_withdrawn(dbs, txn, std::slice::from_ref(word))? {
            push_fold_word(withdrawn, word.clone());
            reached = true;
        }
    }
    Ok(reached)
}

/// The bodies of `capsule` a withdrawal reaches: each it still keeps whose
/// words name a withdrawn fold.
fn reached_bodies(
    dbs: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    capsule: &StepReplayCapsule,
    source_run: Option<EntityId>,
    withdrawn: &mut Vec<FoldWordRef>,
) -> Result<Reached> {
    let words = &capsule.fold_words;
    let kept_request = matches!(capsule.request, CapsuleRequest::Kept { erased: false, .. });
    let kept_start = capsule.start.as_ref().is_some_and(|start| !start.erased);
    let kept_context = capsule
        .context
        .as_ref()
        .is_some_and(|context| !context.erased);
    Ok(Reached {
        request: kept_request && reaches(dbs, txn, &words.request, source_run, withdrawn)?,
        start: kept_start && reaches(dbs, txn, &words.start, source_run, withdrawn)?,
        context: kept_context && reaches(dbs, txn, &words.context, source_run, withdrawn)?,
    })
}

/// Releases run `run`'s occurrence of `body` at `path`, with its own marks:
/// the digest it held, for the withdrawal to retire.
fn release_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    run: EntityId,
    path: &str,
    body: OutputRef,
) -> Result<Option<[u8; 32]>> {
    let handle = CodeRunRawOutput::of_ref(body).handle;
    release_occurrence_in_txn(store, wtxn, run, path.to_owned(), handle)
}

/// Retires each capsule body that copies the words of a fold a withdrawal
/// took here, in the withdrawing writer (FIX 18924); with `source_run`,
/// only bodies whose words name a fold of that run. Every capsule row is
/// read, a staged one too. Each reached request, start and context is
/// released as its run's occurrence, marked erased on its capsule and its
/// instance retired under the run, or owed to another holder's release; a
/// retired request's pieces no kept request of its run and actor names go
/// with it, and a retired start's pieces no kept start of its run and actor
/// names (FIX 4192). A row that does not decode, and a capsule an actor's
/// erase already took, are left as they are. Returns every withdrawn fold a
/// reached body named, each once.
///
/// # Errors
///
/// Storage and custody errors.
pub(in crate::code_run::storage) fn retire_fold_word_capsules_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    source_run: Option<EntityId>,
) -> Result<Vec<FoldWordRef>> {
    let mut withdrawn = Vec::new();
    let mut reached = Vec::new();
    let txn: &heed::RoTxn<'_> = wtxn;
    for row in CAPSULES.iter_raw_from(store, txn, &[])? {
        let (key, bytes) = row?;
        let Some(key) = <CapsuleKey as SideKey>::decode_key(&key) else {
            continue;
        };
        let Ok(capsule) = CAPSULES.decode_value(&bytes) else {
            continue;
        };
        if capsule.content.actor().is_none() {
            continue;
        }
        let bodies = reached_bodies(store, txn, &capsule, source_run, &mut withdrawn)?;
        if bodies.any() {
            reached.push((key, capsule, bodies));
        }
    }
    let mut held: BTreeMap<EntityId, BTreeSet<[u8; 32]>> = BTreeMap::new();
    let mut pieces: BTreeMap<(EntityId, EntityId), BTreeSet<[u8; 32]>> = BTreeMap::new();
    let mut start_named: BTreeMap<(EntityId, EntityId), BTreeSet<[u8; 32]>> = BTreeMap::new();
    for (key, mut capsule, bodies) in reached {
        let run = capsule.run;
        let mut digests = Vec::new();
        if bodies.request
            && let Some(actor) = capsule.content.actor()
            && let CapsuleRequest::Kept {
                body, path, erased, ..
            } = &mut capsule.request
        {
            let named = pieces.entry((run, actor)).or_default();
            manifest_pieces_in_txn(store, wtxn, *body, named)?;
            digests.extend(release_in_txn(store, wtxn, run, path, *body)?);
            *erased = true;
        }
        if bodies.start
            && let Some(actor) = capsule.content.actor()
            && let Some(start) = &mut capsule.start
        {
            let named = start_named.entry((run, actor)).or_default();
            start_manifest_pieces_in_txn(store, wtxn, start.body, named)?;
            digests.extend(release_in_txn(store, wtxn, run, &start.path, start.body)?);
            start.erased = true;
        }
        if bodies.context
            && let Some(context) = &mut capsule.context
        {
            digests.extend(release_in_txn(
                store,
                wtxn,
                run,
                &context.path,
                context.body,
            )?);
            context.erased = true;
        }
        held.entry(run).or_default().extend(digests);
        CAPSULES.put(store, wtxn, &key, &capsule)?;
    }
    for ((run, actor), named) in pieces {
        let scope = PieceScope { run, actor };
        let released = release_retired_pieces_in_txn(store, wtxn, scope, &named)?;
        held.entry(run).or_default().extend(released);
    }
    for ((run, actor), named) in start_named {
        let scope = PieceScope { run, actor };
        let released = release_unnamed_start_pieces_in_txn(store, wtxn, scope, &named)?;
        held.entry(run).or_default().extend(released);
    }
    for (run, digests) in held {
        let digests: Vec<[u8; 32]> = digests.into_iter().collect();
        crate::store::erase_bodies_in_txn(store, wtxn, &run, &digests)?;
    }
    Ok(withdrawn)
}
