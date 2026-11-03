//! A public model step's failure text, out of its queue row (FIX 10460).
//! Entry: `erase_failure_reasons_in_txn`,
//! `erase_model_step_failure_reasons_in_txn`, `scrub_erased_failure_reason_in_txn`.
//!
//! The public model-step door fails its attempt with the step's error
//! message as the queue's fail reason (`llm/step/public.rs`), a copy the
//! submission's custody scrub (FIX 9929) does not reach: it takes the
//! request and result out of the submission row only. The copy is the
//! queue's, so the queue takes it out: when a submission row's owner (its
//! actor, or a finished step's terminal claim) is erased, the row's
//! reason becomes the one fixed marker an erased task's does (FIX 7618),
//! in the erase's transaction, at both delete doors as the submission
//! scrub runs, and again when a restore's sweep reruns the payload pass.

use std::collections::BTreeSet;

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::model_step_record::MODEL_STEP_ATTEMPT_KIND;
use crate::ports::{DeletionMarker, TombstoneStoreRead};
use crate::store::Store;

use super::super::encoding::{decode_record, encode_record};
use super::super::types::{AttemptId, AttemptRecord};
use super::scrub_erased_task_failure_reason;

/// Replaces `record`'s fail reason with the fixed marker when one of its
/// submission's owners is among `actors`. `false` when the row is no
/// model step, carries no reason, or another's, so an erased row is not
/// written again.
fn scrub_if_owned(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    record: &mut AttemptRecord,
    actors: &BTreeSet<EntityId>,
) -> Result<bool> {
    if record.kind != MODEL_STEP_ATTEMPT_KIND || record.last_error.is_none() {
        return Ok(false);
    }
    let owners = crate::llm::submission_owners_in_txn(store, txn, &record.id)?;
    if !owners.iter().any(|owner| actors.contains(owner)) {
        return Ok(false);
    }
    Ok(scrub_erased_task_failure_reason(&mut record.last_error))
}

/// A second walk for [`super::erase_attempt_payload_actors_in_txn`]: each
/// model-step row one of `actors` owns joins `rewrites` with its reason
/// the marker. A row that does not decode names no owner and stays.
///
/// # Errors
///
/// Storage errors.
pub(super) fn erase_failure_reasons_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    actors: &BTreeSet<EntityId>,
    rewrites: &mut Vec<(Vec<u8>, AttemptRecord)>,
) -> Result<()> {
    for row in store.attempt_records.iter(txn)? {
        let (key, raw) = row?;
        let Ok(id) = AttemptId::from_bytes(&key) else {
            continue;
        };
        let Ok(mut record) = decode_record(&raw, id) else {
            continue;
        };
        if scrub_if_owned(store, txn, &mut record, actors)? {
            rewrites.push((raw.into_owned(), record));
        }
    }
    Ok(())
}

/// The erase of `owner` takes its model steps' failure text out of their
/// queue rows, in the erase's own transaction, at both delete doors as
/// the submission scrub runs (FIX 10460). An archived row's marker
/// follows its row, as does its run's snapshot, as in the payload pass.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn erase_model_step_failure_reasons_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    owner: &EntityId,
) -> Result<()> {
    let actors = BTreeSet::from([*owner]);
    let mut rewrites = Vec::new();
    erase_failure_reasons_in_txn(store, wtxn, &actors, &mut rewrites)?;
    let mut rewritten = Vec::with_capacity(rewrites.len());
    for (before, record) in rewrites {
        let after = encode_record(&record)?;
        store
            .attempt_records
            .put(wtxn, record.id.as_bytes(), &after)?;
        crate::vault_cleanup::refresh_archived_attempt_in_txn(
            store, wtxn, record.id, &before, &after,
        )?;
        rewritten.push((record.id, before, after));
    }
    crate::vault_cleanup::erase_attempt_references_in_txn(store, wtxn, &rewritten)
}

/// The late write's fence for a model-step row one of whose submission's
/// owners bears the permanent hard-delete marker: its reason becomes the
/// marker before it is encoded, as the pass leaves it, so a failure
/// recorded after its owner's erase keeps no copy. Logged without
/// content, never failing the write, as the fences above.
pub(super) fn scrub_erased_failure_reason_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    record: &mut AttemptRecord,
) {
    if record.kind != MODEL_STEP_ATTEMPT_KIND || record.last_error.is_none() {
        return;
    }
    let attempt = crate::entity_id::bytes_to_hex_lower(record.id.as_bytes());
    let owners = match crate::llm::submission_owners_in_txn(store, txn, &record.id) {
        Ok(owners) => owners,
        Err(_) => {
            tracing::warn!(
                attempt = %attempt,
                "attempt payload fence: a model step's submission could not be read"
            );
            return;
        }
    };
    for owner in &owners {
        match store.port_deletion_marked(txn, DeletionMarker::HardDelete, owner) {
            Ok(true) => {
                scrub_erased_task_failure_reason(&mut record.last_error);
                return;
            }
            Ok(false) => {}
            Err(_) => {
                tracing::warn!(
                    attempt = %attempt,
                    "attempt payload fence: a model-step owner's hard-delete marker could not be read"
                );
                return;
            }
        }
    }
}
