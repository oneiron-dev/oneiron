//! A realization's answer and its row's result in one write (FIX 1334).
//!
//! Each part of the answer is a research NOTE whose id is derived from the
//! attempt and the part's place, so the write that lands the parts also
//! names the first as the row's result, and a replay of the durable step
//! after a crash finds the same ids: it never writes a second NOTE.

use crate::attempt_queue::{AttemptQueue, AttemptRecord, AttemptResultRef, SetAttemptResult};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::{Vault, WriteActor};

/// The domain each answer part's NOTE id is derived in.
const NOTE_ID_DOMAIN: &[u8] = b"oneiron.dreamer.task_realize.note.v1";

fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(format!("task realization: {reason}"))
}

/// The NOTE id of part `index` of `record`'s answer: the same at every try.
pub(super) fn part_id(record: &AttemptRecord, index: usize) -> Result<EntityId> {
    EntityId::derive(
        NOTE_ID_DOMAIN,
        &[
            record.id.as_bytes().as_slice(),
            &(index as u64).to_le_bytes(),
        ],
    )
}

/// Lands `parts`, a realization's answer in order, as research NOTEs under
/// `actor`, each continuation linked `Mentions` to the first, and names the
/// first as `record`'s result, all in one write. A part already there is
/// kept as it is. Returns the first part's NOTE.
pub(super) fn land_answer(
    vault: &Vault,
    record: &AttemptRecord,
    actor: WriteActor,
    kind: &str,
    parts: &[&str],
    now: u64,
) -> Result<EntityId> {
    let ids = (0..parts.len())
        .map(|index| part_id(record, index))
        .collect::<Result<Vec<_>>>()?;
    let note = *ids
        .first()
        .ok_or_else(|| invalid("the answer landed no note"))?;
    let result_ref = AttemptResultRef::new(note.to_hex())?;
    let queue = AttemptQueue::new(vault);
    vault.try_with_write_txn_grouped(|txn| -> Result<()> {
        let mut continuations = Vec::new();
        for (&id, part) in ids.iter().zip(parts) {
            if vault.get_entity_type_in_txn(txn, &id)?.is_some() {
                continue;
            }
            vault
                .create_note_in_txn(txn, id, kind, part, actor)
                .map_err(|error| invalid(&format!("result note: {error}")))?;
            if id != note {
                continuations.push(id);
            }
        }
        if !continuations.is_empty() {
            let mut content = crate::federation::ActorContentTxn::new(vault, txn, actor)?;
            let mut batch = vault.batch_in();
            for part in &continuations {
                batch = batch.edge(part, EdgeKind::Mentions, &note, 1.0);
            }
            content.apply_batch(batch)?;
            content.finish()?;
        }
        queue.set_result_in_txn(
            txn,
            SetAttemptResult {
                id: record.id,
                lease_owner: record.lease_owner.clone().unwrap_or_default(),
                attempt_count: record.attempt_count,
                result_ref,
                now,
            },
        )?;
        Ok(())
    })?;
    vault.store.notify_attempt_observers();
    Ok(note)
}
