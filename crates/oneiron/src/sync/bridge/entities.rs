//! Observer B's entity driver: one batch transaction per delta, each entity through the
//! shared ingest entry, and the `rm:` markers a dead batch leaves behind.

use std::collections::HashSet;

use loro::LoroDoc;

use super::companion_identity::{CompanionCrdtScrub, scrub_local_only_companions_from_crdt};

use crate::Vault;
use crate::entity_id::EntityId;
use crate::sync::ingest::{EntityStep, IngestCtx, ingest_entity_in_savepoint};
use crate::sync::pack_sync;
use crate::sync::quarantine;

/// Materialize entity changes from a Loro MapDelta to LMDB.
///
/// Accumulates all entity ops from the delta into a single LMDB write
/// transaction instead of committing per-entity; each entity runs the shared
/// ingest ladder in its own savepoint.
///
/// Write-gate rejections of REMOTE ops persist a quarantine record (`x:`
/// family, ONE-1124) and never abort the batch; LOCAL failures (the
/// engine's own LMDB errors) propagate fail-closed and abort the txn.
///
/// A whole-txn failure flags the durable entity-scoped
/// `rm:w:{window}:{entity_hex}` needs-remat marker for every op the dead
/// txn had applied (ONE-1147, as the hardened tombstone path does) —
/// the ops stay committed in the CRDT doc, so a bare log would leave a
/// silent LMDB↔CRDT divergence until the next full window recovery.
pub(super) fn materialize_entities_from_delta(
    doc: &LoroDoc,
    delta: &loro::event::MapDelta<'_>,
    vault: &Vault,
    window_key: &str,
    lease_vault_id: u64,
) -> bool {
    let tombstones_map = doc.get_map("tombstones");
    let ingest = IngestCtx::new(vault, window_key, lease_vault_id, &tombstones_map);
    // ONE-1147: ids + op bytes applied into the batch txn, retained outside
    // it — on whole-txn failure there is no surviving per-entity failure
    // point (unlike the tombstone path), so the swallow site below needs
    // the full list to flag retry markers.
    let mut applied_ops: Vec<(EntityId, Vec<u8>)> = Vec::new();
    let mut pending_companion_scrubs = Vec::new();
    let result = vault.with_write_txn(|wtxn| {
        for (key, new_val) in &delta.updated {
            let value = match new_val {
                Some(loro::ValueOrContainer::Value(loro::LoroValue::Binary(blob))) => {
                    Some(&blob[..])
                }
                // Deleted — no action for entities (tombstones carry deletes).
                None => continue,
                // Non-binary value where an entity blob belongs: the ladder
                // refuses it as an undecodable remote op.
                Some(_) => None,
            };
            match ingest_entity_in_savepoint(&ingest, wtxn, key.as_ref(), value)? {
                EntityStep::LocalOnlyCompanion(id) => {
                    pending_companion_scrubs.push(CompanionCrdtScrub::new(key.as_ref(), id));
                }
                step => {
                    if let (Some(id), Some(blob)) = (step.written(), value) {
                        applied_ops.push((id, blob.to_vec()));
                    }
                }
            }
        }
        #[cfg(test)]
        if take_injected_batch_commit_failure() {
            return Err(crate::Error::Io(std::io::Error::other(
                "injected batch commit failure (test hook)",
            )));
        }
        Ok(())
    });

    if result.is_ok()
        && let Err(e) = scrub_local_only_companions_from_crdt(doc, &pending_companion_scrubs)
    {
        tracing::error!(
            error = %e,
            window = %window_key,
            "observer-b: local-only companion CRDT scrub failed after entity batch commit"
        );
    }

    let committed = result.is_ok();
    if let Err(e) = result {
        // ONE-1147: the whole batch txn aborted — every applied op's write
        // (and any quarantine row staged alongside) is lost while the ops
        // stay committed in the CRDT doc. Flag each affected id with the
        // durable entity-scoped rm: marker so the drain re-runs forward
        // remat for this window. Ids whose COMMITTED bytes already equal
        // the op's bytes are skipped: nothing was lost for them, and an
        // at-parity marker could never discharge (discharge requires the
        // actual healing re-write to land — never mere byte-parity, which
        // a failed GDPR purge also exhibits).
        //
        // Layering: markers are BEST-EFFORT durability on an already-failing
        // env — a marker write that itself fails (env down hard) is logged
        // at ERROR and dropped; window recovery's forward remat on the
        // pinned open order remains the backstop.
        let mut seen = HashSet::new();
        let mut marked = 0usize;
        for (id, blob) in &applied_ops {
            // Parity-check BEFORE dedupe: a src/id whose first op is at
            // parity must not shadow a later diverged op for the same id.
            if committed_entity_state_matches(vault, id, blob) || !seen.insert(*id) {
                continue;
            }
            if set_remat_marker_logged(vault, window_key, id) {
                marked += 1;
            }
        }
        tracing::error!(
            error = %e,
            window = %window_key,
            applied_ops = applied_ops.len(),
            marked,
            "observer-b: entity batch commit failed — flagged entity-scoped rm: markers for durable retry"
        );
    }
    committed
}

/// ONE-1147 (best-effort, post-abort): `true` ONLY when the committed
/// entity bytes provably equal the op's bytes — the failed txn lost nothing
/// for this id. Any read error reports `false`: over-marking is the
/// conservative direction (forward remat is idempotent and byte-compares
/// before writing).
pub(super) fn committed_entity_state_matches(vault: &Vault, id: &EntityId, blob: &[u8]) -> bool {
    let Ok(rtxn) = vault.store.env.read_txn() else {
        return false;
    };
    matches!(
        vault.store.entities.get(&rtxn, id.as_bytes()),
        Ok(Some(existing)) if *existing == *blob || pack_sync::pack_echo_equal(&existing, blob)
    )
}

/// Writes one `rm:w:{window}:{entity_hex}` marker in its OWN txn (the
/// failed batch txn is dead). A marker-write failure is logged at ERROR and
/// swallowed. Batch-failure markers carry replay provenance so terminal
/// quarantine can discharge them without clearing delete-safety markers.
/// Window recovery's forward remat remains the backstop (see the batch
/// swallow sites for the layering).
pub(super) fn set_remat_marker_logged(vault: &Vault, window_key: &str, id: &EntityId) -> bool {
    match quarantine::set_replay_remat_marker(vault, window_key, id) {
        Ok(()) => true,
        Err(marker_err) => {
            tracing::error!(
                entity = %id.to_hex(),
                window = %window_key,
                error = %marker_err,
                "observer-b: CRITICAL — failed to set rm: marker after batch commit failure"
            );
            false
        }
    }
}

// Test-only whole-batch commit failure injection for the ONE-1147 rm:
// marker round-trip tests: when armed, the next entity/edge materialization
// batch returns a LOCAL (non-remote-classifiable) error from inside the
// write closure AFTER all ops were applied — the txn aborts exactly like an
// env-level commit failure. Counts down per batch on the current thread
// (Loro observer callbacks fire synchronously on the committing thread).

#[cfg(test)]
thread_local! {
    pub(in crate::sync) static INJECT_BATCH_COMMIT_FAILURES: std::cell::Cell<u32> =
        const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(super) fn take_injected_batch_commit_failure() -> bool {
    INJECT_BATCH_COMMIT_FAILURES.with(|cell| {
        let remaining = cell.get();
        if remaining > 0 {
            cell.set(remaining - 1);
            true
        } else {
            false
        }
    })
}
