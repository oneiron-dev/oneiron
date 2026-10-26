//! The records a witnessed reply asserts (OF-063), judged in the writer's one
//! snapshot: every cited and created id is read in bounded chunks (FIX 3419),
//! and a created record's birth is checked against the writer and the run
//! its host bound (FIX 1211).

use super::WitnessAssertions;
use crate::claim::ScopedRead;
use crate::entity_id::EntityId;
use crate::memory::MemoryResult;
use crate::provenance::birth::{row_birth_in_txn, trigger_is_live_in_txn};
use crate::provenance::made_by::MadeByTrigger;
use crate::store::ManifestDbs;

/// Ids judged per readability batch: a work buffer for the scoped reader in
/// the one transaction, never a limit on how many records a reply asserts.
const ASSERTION_READ_CHUNK: usize = 256;

/// The pointer of the first record `assertions` names that `lane` does not
/// read in `txn`, cited before created: a malformed id, a missing row and an
/// unreadable one are one answer. Every id is judged in the one snapshot,
/// chunk by chunk, however many there are. A model stream's continuation
/// terminal judges its own through it too (FIX 3416).
pub(in crate::memory::witness) fn unread_assertion_in(
    lane: &ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    assertions: &WitnessAssertions,
) -> MemoryResult<Option<String>> {
    let lists = [
        ("cited", &assertions.cited),
        ("created", &assertions.created),
    ];
    for (list, records) in lists {
        for (chunk, slice) in records.chunks(ASSERTION_READ_CHUNK).enumerate() {
            let named: Vec<Option<EntityId>> = slice
                .iter()
                .map(|record| EntityId::from_hex(&record.id).ok())
                .collect();
            let ids: Vec<EntityId> = named.iter().flatten().copied().collect();
            let mut readable = lane.entities_readable_in_txn(txn, &ids)?.into_iter();
            for (offset, id) in named.into_iter().enumerate() {
                // A malformed id takes no readable slot: its pointer fails as it is.
                let read = id.is_some() && readable.next().unwrap_or(false);
                if !read {
                    let index = chunk * ASSERTION_READ_CHUNK + offset;
                    return Ok(Some(format!("/assertions/{list}/{index}/id")));
                }
            }
        }
    }
    Ok(None)
}

/// The pointers of the `created` records whose stored birth does not prove
/// `writer` made them in `run`, the code run its host bound, read in `txn`
/// on `dbs` after every asserted record has read (FIX 1211). Proof is the
/// birth's producing actor and its `Run` trigger naming that run, whose
/// durable replay record lives. A writer with no host-bound run proves no
/// creation: its records are not proven, never guessed made. The reply
/// stands either way; this only keeps "created" from reading as proved.
pub(in crate::memory::witness) fn unproven_creations_in(
    dbs: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    assertions: &WitnessAssertions,
    writer: EntityId,
    run: Option<EntityId>,
) -> MemoryResult<Vec<String>> {
    let mut unproven = Vec::new();
    for (index, record) in assertions.created.iter().enumerate() {
        let proven = match (EntityId::from_hex(&record.id), run) {
            (Ok(id), Some(run)) => birth_proves_in(dbs, txn, &id, writer, run)?,
            _ => false,
        };
        if !proven {
            unproven.push(format!("/assertions/created/{index}/id"));
        }
    }
    Ok(unproven)
}

/// Whether `id`'s stored birth names `writer` as its producer and `run` as
/// its trigger, with `run`'s replay record live.
fn birth_proves_in(
    dbs: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    writer: EntityId,
    run: EntityId,
) -> MemoryResult<bool> {
    let Some(birth) = row_birth_in_txn(dbs, txn, id)? else {
        return Ok(false);
    };
    let trigger = MadeByTrigger::Run(run);
    Ok(birth.made_by.process.actor == writer
        && birth.made_by.trigger.as_ref() == Some(&trigger)
        && trigger_is_live_in_txn(dbs, txn, &trigger)?)
}
