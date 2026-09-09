//! Tombstone materialization, savepoint batching, and protected-header handling.

#[cfg(test)]
use std::cell::Cell;

use loro::{LoroDoc, LoroMap};

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::entity_id::EntityId;
use crate::sync::loro_support::{map_get_bytes, tombstone_values_for_id};
use crate::sync::quarantine::{
    self, QuarantineContainer, quarantine_rejected_op, quarantine_rejected_op_in_txn,
    remote_rejection_reason,
};
use crate::sync::queue::scrub_receiver_outbox_on_remote_hard_delete_in_txn;
use crate::{Error, Result, SyncProtocolValidation, Vault};

/// Materialize tombstone changes — apply deletes to LMDB.
///
/// ONE-1133 (ARCH-0038): each tombstone routes through the reason-aware
/// replay primitive [`Vault::apply_replayed_tombstone`], never a bare
/// purge. The VALUE decides the effect: a known-soft `user_delete` value
/// keeps the 25 B shell (SoftErase + D16 refresh); every other shape —
/// hard reasons, legacy 8-byte, reserved 0, unknown bytes, malformed,
/// and non-binary values — hard-purges and, when local state was erased,
/// writes the LOCAL REDACTION_AUDIT receipt and `h:` sweep row.
///
/// A replay failure is the fail-OPEN delete hole: hard-deleted content stays
/// live locally with no retry. It now writes the ARCH-0023b
/// needs-rematerialization marker `rm:w:{window}:{entity_hex}` ("set on
/// Observer B failure", entity-scoped) so maintain/doctor retries it
/// durably (ONE-1124 AC4) — a GDPR SLA breach signal until drained.
///
/// ONE-521 transaction topology: the delta is STAGED first, then applied
/// under exactly ONE top-level write transaction — an N-tombstone delta is
/// one durable commit, not N. Per-tombstone isolation is preserved by LMDB
/// nested transactions used as savepoints (see [`apply_tombstone_batch`]),
/// so one item's failure still cannot take its siblings down. Reason
/// semantics, receipts, markers and wire values are untouched.
pub(super) fn materialize_tombstones_from_delta(
    doc: &LoroDoc,
    delta: &loro::event::MapDelta<'_>,
    vault: &Vault,
    window_key: &str,
    _lease_vault_id: u64,
) -> bool {
    let entities_map = doc.get_map("entities");
    // Staged BEFORE the batch transaction opens: the door gates below are
    // document reads plus their own committing quarantine writes (pre-batch
    // rejections that never enter the batch at all), and the batch must not
    // hold a doc borrow across its savepoints.
    let mut staged = Vec::<TombstoneWork>::new();
    for (key, new_val) in &delta.updated {
        match new_val {
            Some(value) => {
                // New tombstone added
                let id = match EntityId::from_hex(key.as_ref()) {
                    Ok(id) => id,
                    Err(_) => {
                        let payload = match value {
                            loro::ValueOrContainer::Value(loro::LoroValue::Binary(bytes)) => {
                                bytes.to_vec()
                            }
                            _ => Vec::new(),
                        };
                        if let Err(e) = quarantine_rejected_op(
                            vault,
                            window_key,
                            QuarantineContainer::Tombstones,
                            key.as_ref(),
                            &Error::InvalidKey,
                            &payload,
                        ) {
                            tracing::error!(
                                tombstone = %key,
                                error = %e,
                                "observer-b: failed to persist tombstone quarantine record"
                            );
                        }
                        continue;
                    }
                };

                // A non-binary tombstone value has no decodable reason —
                // it replays as the empty value, which decodes HARD
                // (fail-closed: over-purge, never under-delete).
                let raw_value: &[u8] = match value {
                    loro::ValueOrContainer::Value(loro::LoroValue::Binary(blob)) => blob,
                    _ => &[],
                };

                // Protection must not depend on observer callback order.
                // A concurrent engine-authored blob may not have reached
                // LMDB yet, so inspect its envelope directly and quarantine
                // the tombstone before the headerless hard-delete path can
                // mint a permanent `dt:` marker.
                if matches!(vault.read_entity_header(&id), Ok(None))
                    && let Some(entity_blob) = map_get_bytes(&entities_map, &id.to_hex())
                    && let Some(header) = admitted_concurrent_delete_protected_header(&entity_blob)
                {
                    let rejection = Error::MaintenanceKindNotWritable(header.entity_type);
                    if let Err(quarantine_err) = quarantine_rejected_op(
                        vault,
                        window_key,
                        QuarantineContainer::Tombstones,
                        key.as_ref(),
                        &rejection,
                        raw_value,
                    ) {
                        tracing::error!(
                            tombstone = %key,
                            window = %window_key,
                            error = %quarantine_err,
                            "observer-b: failed to quarantine concurrent protected-record tombstone"
                        );
                    }
                    continue;
                }

                staged.push(TombstoneWork {
                    id,
                    crdt_key: key.as_ref().to_string(),
                    raw_value: raw_value.to_vec(),
                    hard: crate::deletion::decode_tombstone_value(raw_value).is_hard(),
                });
            }
            None => {
                // Tombstone REMOVAL delta: no engine version ever emits one
                // — tombstones are permanent (never-downgrade,
                // hard-once-seen), so a removal is a protocol violation by
                // definition. The `dt:` marker gate keeps the local hard
                // delete closed regardless. Quarantine it (x: row,
                // hash+metadata only) and continue. The tombstone is NOT
                // re-asserted here — a doc write inside an observer
                // callback re-enters Loro (handoff §8c.1); instead, for a
                // locally hard-deleted id, the durable `ra:` marker below
                // queues the re-assertion for the safe-commit-point drain
                // (ONE-1156(c), WAVE-C OD-11).
                if let Err(e) = quarantine_rejected_op(
                    vault,
                    window_key,
                    QuarantineContainer::Tombstones,
                    key.as_ref(),
                    &Error::sync_protocol(SyncProtocolValidation::TombstoneRemovalDelta),
                    &[],
                ) {
                    tracing::error!(
                        tombstone = %key,
                        error = %e,
                        "observer-b: failed to persist tombstone-removal quarantine record"
                    );
                }
                // OD-11, HARD-only: a dt:-backed marker carries the
                // faithful 25 B local truth; a soft removal stays
                // quarantine-only (residual R4 — a reconstructed soft
                // value cannot be faithful, and an incorrectly decoded value would
                // HARD-purge a user-kept shell at peers). An unparsable
                // key cannot name a `dt:` row at all — quarantine above
                // already recorded it.
                if let Ok(id) = EntityId::from_hex(key.as_ref())
                    && let Err(marker_err) =
                        quarantine::enqueue_tombstone_reassert_marker(vault, window_key, &id)
                {
                    tracing::error!(
                        tombstone = %key,
                        window = %window_key,
                        error = %marker_err,
                        "observer-b: CRITICAL — failed to enqueue ra: re-assertion marker after tombstone removal"
                    );
                }
            }
        }
    }

    if staged.is_empty() {
        return false;
    }
    // Soft-over-hard `ra:` reassert for staged soft items runs INSIDE
    // apply_tombstone_batch's single parent write txn (ONE-521) — materialize
    // must not open any per-item committing helper over staged work.
    apply_tombstone_batch(vault, window_key, &staged)
}

/// One tombstone staged out of the delta, owned so the batch transaction can
/// apply it without borrowing the Loro event.
#[derive(Debug)]
struct TombstoneWork {
    id: EntityId,
    crdt_key: String,
    raw_value: Vec<u8>,
    hard: bool,
}

/// Which half of an item's savepoint failed. Both leave the item unapplied
/// and both flag the same durable retry marker, but they mean different
/// things to an operator: a failed replay may leave hard-deleted content live
/// locally, while a failed receiver-outbox scrub ALSO rolls that item's purge
/// back rather than leaving the deleted payload sitting in the outbox.
#[derive(Clone, Copy)]
enum TombstoneFailureStage {
    Replay,
    ReceiverScrub,
}

/// Applies every staged tombstone under ONE top-level write transaction
/// (ONE-521).
///
/// Per-item isolation comes from LMDB nested transactions used as savepoints:
/// each item applies into a child of the batch transaction, and the child is
/// committed into the parent only when the replay AND (for a hard tombstone)
/// the receiver-outbox scrub both succeeded. Aborting a child drops exactly
/// that item's writes — earlier and later siblings keep theirs, and the batch
/// still ends in a single durable commit with no per-entity fsync.
///
/// An ITEM failure never aborts the batch: protected-record rejections take
/// the existing `x:` quarantine path and every other failure flags the
/// entity-scoped `rm:` retry marker, both written on the PARENT so they
/// survive the aborted child. Errors are logged after the commit.
///
/// A failure of the parent transaction itself is a batch-level storage
/// failure — nothing was applied, so it is logged once rather than dressed up
/// as partial success. The tombstones stay in the CRDT map, which is both the
/// resurrection gate for entity materialization and the replay source for
/// forward rematerialization, so the work is not lost.
fn apply_tombstone_batch(vault: &Vault, window_key: &str, staged: &[TombstoneWork]) -> bool {
    let mut failures = Vec::<(&TombstoneWork, TombstoneFailureStage, Error)>::new();

    #[cfg(test)]
    note_tombstone_batch_top_level_txn();
    let batch = vault.with_write_txn(|parent| {
        for work in staged {
            let Err((stage, err)) = apply_tombstone_in_savepoint(vault, parent, window_key, work)
            else {
                continue;
            };
            // Item-local bookkeeping on the PARENT — the item's own child is
            // already aborted, and none of this may use `?`: one tombstone's
            // failure must never unwind the batch closure.
            if remote_rejection_reason(&err).is_some() {
                if let Err(quarantine_err) = quarantine_rejected_op_in_txn(
                    vault,
                    parent,
                    window_key,
                    QuarantineContainer::Tombstones,
                    &work.crdt_key,
                    &err,
                    &work.raw_value,
                ) {
                    tracing::error!(
                        tombstone = %work.crdt_key,
                        window = %window_key,
                        error = %quarantine_err,
                        "observer-b: failed to quarantine rejected protected-record tombstone"
                    );
                }
                continue;
            }
            if let Err(marker_err) =
                quarantine::set_remat_marker_in_txn(vault, parent, window_key, &work.id)
            {
                tracing::error!(
                    tombstone = %work.crdt_key,
                    window = %window_key,
                    error = %marker_err,
                    "observer-b: CRITICAL — failed to set rm: marker after tombstone item failure"
                );
            }
            failures.push((work, stage, err));
        }

        // ONE-1156(c) / WAVE-C OD-11, §8c.1 doc residue + ONE-521:
        // a SOFT value arriving over a locally hard-deleted id (`dt:` present)
        // can WIN the Loro map merge — LMDB stays safe (replay never
        // downgrades), but the doc now shows soft to every peer. Re-asserting
        // into the doc here would re-enter Loro; instead enqueue durable
        // `ra:w:{window}:{entity_hex}` (value = the `dt:` row's exact 25 B)
        // for the safe-commit-point drain. No `dt:` ⇒ no marker (helper
        // checks). Soft-only: this batch cannot mint `dt:` for a soft id, so
        // observational result matches the former post-batch ordering when
        // the parent commits. Runs AFTER the per-item savepoint loop, still
        // without `?` — enqueue failure must never unwind/roll back sibling
        // applies (mirrors set_remat_marker_in_txn parent bookkeeping).
        for work in staged.iter().filter(|work| !work.hard) {
            if let Err(marker_err) = quarantine::enqueue_tombstone_reassert_marker_in_txn(
                vault,
                parent,
                window_key,
                &work.id,
            ) {
                tracing::error!(
                    tombstone = %work.crdt_key,
                    window = %window_key,
                    error = %marker_err,
                    "observer-b: CRITICAL — failed to enqueue ra: re-assertion marker for soft-over-hard doc residue"
                );
            }
        }
        Ok(())
    });

    if let Err(e) = batch {
        tracing::error!(
            window = %window_key,
            tombstones = staged.len(),
            error = %e,
            "observer-b: tombstone batch transaction FAILED — NO tombstone in this delta was applied; the CRDT tombstones map keeps gating materialization and remains the replay source"
        );
        return false;
    }

    for (work, stage, err) in &failures {
        match stage {
            TombstoneFailureStage::Replay => tracing::error!(
                tombstone = %work.crdt_key,
                window = %window_key,
                error = %err,
                "observer-b: tombstone replay FAILED — hard-deleted content may still be live; flagged entity-scoped rm: marker for durable retry"
            ),
            TombstoneFailureStage::ReceiverScrub => tracing::error!(
                tombstone = %work.crdt_key,
                window = %window_key,
                error = %err,
                "observer-b: receiver outbox scrub FAILED after hard tombstone replay; the item's purge was rolled back and flagged with an entity-scoped rm: marker for durable retry"
            ),
        }
    }
    true
}

/// Applies one staged tombstone inside a nested write transaction (savepoint)
/// of `parent`, committing the child only when the whole item succeeded.
///
/// A hard tombstone's receiver-outbox scrub runs in the SAME child as its
/// purge, so there is no committed state where the purge landed but its
/// required scrub did not.
fn apply_tombstone_in_savepoint(
    vault: &Vault,
    parent: &mut heed::RwTxn<'_>,
    window_key: &str,
    work: &TombstoneWork,
) -> std::result::Result<(), (TombstoneFailureStage, Error)> {
    let mut child = vault
        .store
        .env
        .nested_write_txn(parent)
        .map_err(|e| (TombstoneFailureStage::Replay, Error::from(e)))?;

    let applied = quarantine::apply_replayed_tombstone_for_sync_in_txn(
        vault,
        &mut child,
        &work.id,
        &work.raw_value,
    );
    let item = match applied {
        Ok(_) if work.hard => {
            scrub_receiver_outbox_on_remote_hard_delete_in_txn(vault, &mut child, window_key)
                .map(|_| ())
                .map_err(|e| (TombstoneFailureStage::ReceiverScrub, e))
        }
        Ok(_) => Ok(()),
        Err(e) => Err((TombstoneFailureStage::Replay, e)),
    };

    match item {
        Ok(()) => child
            .commit()
            .map_err(|e| (TombstoneFailureStage::Replay, Error::from(e))),
        Err(failure) => {
            // Savepoint abort: this item's entity/index/receipt/sweep/outbox
            // writes never reach the parent, while its siblings' do.
            drop(child);
            Err(failure)
        }
    }
}

// Top-level write transactions this delta's tombstone batch opened
// (ONE-521 acceptance). Nested savepoints are deliberately NOT counted —
// they add no durability boundary — and neither are the pre-batch door
// gates' own committing quarantine writes, which reject a tombstone instead
// of materializing it. Thread-local because Loro observer callbacks run
// synchronously on the committing thread, so parallel tests cannot race.

#[cfg(test)]
thread_local! {
    static TOMBSTONE_BATCH_TOP_LEVEL_TXNS: Cell<u32> = const { Cell::new(0) };
}

#[cfg(test)]
fn note_tombstone_batch_top_level_txn() {
    TOMBSTONE_BATCH_TOP_LEVEL_TXNS.with(|count| count.set(count.get().saturating_add(1)));
}

pub(super) fn quarantine_and_neutralize_protected_tombstone_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    tombstones_map: &LoroMap,
    window_key: &str,
    id: &EntityId,
    entity_type: u8,
) -> Result<()> {
    let rejection = Error::MaintenanceKindNotWritable(entity_type);
    let crdt_key = id.to_hex();
    for tombstone in tombstone_values_for_id(tombstones_map, id) {
        quarantine_rejected_op_in_txn(
            vault,
            wtxn,
            window_key,
            QuarantineContainer::Tombstones,
            &crdt_key,
            &rejection,
            &tombstone,
        )?;
    }
    vault.neutralize_delete_protected_marker_in_txn(wtxn, id, entity_type)?;
    Ok(())
}

/// Classifies a concurrent peer envelope for tombstone protection only after
/// running the same deterministic body predicate as replicated type-76
/// ingestion. Other established protected kinds retain their existing
/// classification; type-76 must never gain protection from its header alone.
pub(in crate::sync) fn admitted_concurrent_delete_protected_header(
    blob: &[u8],
) -> Option<EntityMetadataHeader> {
    let header = EntityMetadataHeader::parse(blob)?;
    if !crate::registry::is_delete_protected_engine_record(header.entity_type) {
        return None;
    }
    if header.entity_type == crate::registry::ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT {
        let data = &blob[ENTITY_METADATA_HEADER_LEN..];
        crate::identity_topology::decode_replicated_identity_topology_event_body(data).ok()?;
    }
    Some(header)
}
