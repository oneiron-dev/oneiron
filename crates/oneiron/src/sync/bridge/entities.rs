//! Entity-delta materialization and the per-entity blob writer.

use std::collections::HashSet;

use loro::{LoroDoc, LoroMap};

use super::companion_identity::{
    CompanionCrdtScrub, companion_register_blob_is_local_only, companion_register_sync_admitted,
    ensure_companion_register_kind_for_entity_delta,
    ingest_replicated_identity_topology_event_in_txn, scrub_local_only_companions_from_crdt,
};
use super::tombstones::quarantine_and_neutralize_protected_tombstone_in_txn;

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::companion::ENTITY_TYPE_COMPANION_REGISTER;
use crate::entity_id::EntityId;
use crate::registry::ENTITY_TYPE_AUTHORITY_LOG;
use crate::sync::loro_support::tombstone_map_contains_id;
use crate::sync::quarantine::{
    self, QuarantineContainer, quarantine_rejected_op_in_txn, remote_rejection_reason,
};
use crate::sync::quota;
use crate::{Error, Result, Vault};

/// Materialize entity changes from a Loro MapDelta to LMDB.
///
/// Accumulates all entity ops from the delta into a single LMDB write
/// transaction instead of committing per-entity.
///
/// Write-gate rejections of REMOTE ops persist a quarantine record (`x:`
/// family, ONE-1124) and never abort the batch; LOCAL failures (the
/// engine's own LMDB errors) propagate fail-closed and abort the txn.
///
/// A whole-txn failure flags the durable entity-scoped
/// `rm:w:{window}:{entity_hex}` needs-remat marker for every op the dead
/// txn had applied (ONE-1147, parity with the hardened tombstone path) —
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
    // ONE-1147: ids + op bytes applied into the batch txn, retained outside
    // it — on whole-txn failure there is no surviving per-entity failure
    // point (unlike the tombstone path), so the swallow site below needs
    // the full list to flag retry markers.
    let mut applied_ops: Vec<(EntityId, Vec<u8>)> = Vec::new();
    let mut pending_companion_scrubs = Vec::new();
    let result = ensure_companion_register_kind_for_entity_delta(vault, delta).and_then(|()| {
        vault.with_write_txn(|wtxn| {
        for (key, new_val) in &delta.updated {
            match new_val {
                Some(loro::ValueOrContainer::Value(loro::LoroValue::Binary(blob))) => {
                    // Pre-validate the REMOTE bytes structurally BEFORE any
                    // local read, so a later `CorruptedIndex` bubbling out of
                    // the engine's own rows is never conflated with a bad
                    // remote blob (LOCAL corruption = typed error, never
                    // quarantine-and-continue).
                    let Some(header) = EntityMetadataHeader::parse(blob) else {
                        quarantine_rejected_op_in_txn(
                            vault,
                            wtxn,
                            window_key,
                            QuarantineContainer::Entities,
                            key.as_ref(),
                            &Error::CorruptedIndex("entity metadata"),
                            blob,
                        )?;
                        continue;
                    };
                    let id = match EntityId::from_hex(key.as_ref()) {
                        Ok(id) => id,
                        Err(_) => {
                            quarantine_rejected_op_in_txn(
                                vault,
                                wtxn,
                                window_key,
                                QuarantineContainer::Entities,
                                key.as_ref(),
                                &Error::InvalidKey,
                                blob,
                            )?;
                            continue;
                        }
                    };
                    // ONE-1158: a non-canonical (case-shifted) hex alias key
                    // is a protocol violation — no engine version ever emits
                    // one (`to_hex()` is lowercase). Materializing it would
                    // leave the alias KEY live in the entities map while
                    // tombstone-commit removal deletes only the
                    // canonical-lowercase key: suppressed live-map byte
                    // residue (handoff §8c.2 family). Fail closed at the
                    // door: quarantine, never materialize.
                    if key.as_ref() != id.to_hex() {
                        quarantine_rejected_op_in_txn(
                            vault,
                            wtxn,
                            window_key,
                            QuarantineContainer::Entities,
                            key.as_ref(),
                            &Error::InvalidKey,
                            blob,
                        )?;
                        continue;
                    }
                    // ONE-1133 (ARCH-0038): a tombstone always wins over
                    // concurrent entities-map state. A re-put merged after
                    // the delete must never (re)materialize the body — no
                    // further tombstone event would fire to scrub it. The
                    // check is entity-canonical (a case-shifted hex
                    // tombstone key still names this id). Presence is
                    // value-agnostic (a non-binary tombstone decodes HARD
                    // downstream).
                    let delete_protected =
                        crate::registry::is_delete_protected_engine_record(header.entity_type);
                    if !delete_protected && tombstone_map_contains_id(&tombstones_map, &id) {
                        tracing::debug!(
                            entity = %key,
                            "observer-b: entity update suppressed by tombstone (delete wins)"
                        );
                        continue;
                    }
                    // `dt:` local hard-delete marker gate (ONE-1122),
                    // checked SECOND (LMDB point read) only when the map
                    // says absent: a hostile peer that REMOVES the
                    // tombstone and re-puts the entity key cannot resurrect
                    // the body. A failed marker read fails CLOSED
                    // (suppress); a refusal is the crafted-removal attack
                    // signal, surfaced at WARN.
                    let locally_hard_deleted = if delete_protected {
                        false
                    } else {
                        match vault.local_hard_delete_marker_exists_in_txn(wtxn, &id) {
                            Ok(present) => present,
                            Err(e) => {
                                tracing::warn!(
                                    entity = %key,
                                    error = %e,
                                    "observer-b: dt: marker read failed — failing closed"
                                );
                                true
                            }
                        }
                    };
                    if locally_hard_deleted {
                        tracing::warn!(
                            entity = %key,
                            "observer-b: entity locally hard-deleted (dt: marker), refusing materialization"
                        );
                        continue;
                    }
                    if matches!(companion_register_blob_is_local_only(blob), Ok(true)) {
                        pending_companion_scrubs
                            .push(CompanionCrdtScrub::new(key.as_ref(), id));
                        continue;
                    }
                    let materialize_result = materialize_entity_blob_in_txn(
                        vault,
                        wtxn,
                        &tombstones_map,
                        window_key,
                        key.as_ref(),
                        blob,
                        lease_vault_id,
                    );
                    match materialize_result {
                        Ok(true) => applied_ops.push((id, blob.to_vec())),
                        Ok(false) => {}
                        Err(e) => {
                            if remote_rejection_reason(&e).is_some() {
                                quarantine_rejected_op_in_txn(
                                    vault,
                                    wtxn,
                                    window_key,
                                    QuarantineContainer::Entities,
                                    key.as_ref(),
                                    &e,
                                    blob,
                                )?;
                            } else {
                                // LOCAL failure — fail closed, abort the batch.
                                return Err(e);
                            }
                        }
                    }
                }
                None => {
                    // Deleted — no action for entities (use tombstones instead)
                }
                _ => {
                    // Non-binary value where an entity blob belongs —
                    // undecodable remote op, quarantined (never a bare log).
                    quarantine_rejected_op_in_txn(
                        vault,
                        wtxn,
                        window_key,
                        QuarantineContainer::Entities,
                        key.as_ref(),
                        &Error::InvalidKey,
                        &[],
                    )?;
                }
            }
        }
        #[cfg(test)]
        if take_injected_batch_commit_failure() {
            return Err(Error::Io(std::io::Error::other(
                "injected batch commit failure (test hook)",
            )));
        }
        Ok(())
        })
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
        Ok(Some(existing)) if *existing == *blob
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

pub(super) fn materialize_entity_blob_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    tombstones_map: &LoroMap,
    window_key: &str,
    key: &str,
    blob: &[u8],
    lease_vault_id: u64,
) -> Result<bool> {
    let id = EntityId::from_hex(key).map_err(|_| crate::Error::InvalidKey)?;
    let Some(header) = EntityMetadataHeader::parse(blob) else {
        return Err(crate::Error::CorruptedIndex("entity metadata"));
    };
    let delete_protected = crate::registry::is_delete_protected_engine_record(header.entity_type);

    // Tombstone gate — fires BEFORE the put, never heals after (ARCH-0023b:
    // "If tombstoned in CRDT → never resurrect"; contracts.ts
    // `user_hard_delete`: "Tombstone-first prevents sync resurrection").
    // Hard delete purges LMDB but leaves the stale blob in the live CRDT
    // entities map (`write_crdt_tombstone` only inserts into `tombstones`),
    // so ANY later commit touching this entity key would otherwise
    // rematerialize the purged body into LMDB with no compensating purge —
    // tombstone deltas only fire when the tombstones map CHANGES.
    // Presence is ANY-value (fail closed): non-binary tombstones gate too —
    // and entity-canonical: a case-shifted hex key still names this id.
    if !delete_protected && tombstone_map_contains_id(tombstones_map, &id) {
        tracing::debug!(entity = %key, "observer-b: entity tombstoned in CRDT, skipping put");
        return Ok(false);
    }

    // `dt:` local hard-delete marker gate (ONE-1122): the CRDT tombstones
    // map is MUTABLE remote input — a crafted update can REMOVE a tombstone
    // and re-put the entity key, passing the map check above and resurrecting
    // a hard-deleted body permanently (no tombstone left to re-fire). The
    // dt: row is local-only truth written in the origin purge txn; checked
    // SECOND (LMDB point read) only when the in-memory map says absent.
    // PRESENCE-ONLY — never decode the value. Canonical lowercase hex via
    // the parsed id, so a case-shifted map key cannot dodge the point read.
    if !delete_protected && vault.local_hard_delete_marker_exists_in_txn(wtxn, &id)? {
        tracing::warn!(
            entity = %key,
            "observer-b: entity locally hard-deleted (dt: marker), refusing materialization"
        );
        return Ok(false);
    }

    let data = if blob.len() > ENTITY_METADATA_HEADER_LEN {
        &blob[ENTITY_METADATA_HEADER_LEN..]
    } else {
        &[]
    };

    if header.entity_type == ENTITY_TYPE_COMPANION_REGISTER
        && !companion_register_sync_admitted(data)?
    {
        tracing::warn!(
            entity = %key,
            "observer-b: refused local-only companion register materialization"
        );
        return Ok(false);
    }

    if header.entity_type == crate::registry::ENTITY_TYPE_DIAGNOSTIC {
        return super::diagnostic_ingest::ingest_diagnostic_in_txn(
            vault,
            wtxn,
            &id,
            blob,
            lease_vault_id,
        );
    }

    // ONE-1134 + ONE-1140: REDACTION_AUDIT replay door. Receipts
    // are immutable audit records (contracts.ts `redactionAuditReceipt`;
    // ARCH-0023b audit/guardrail stream class: quarantine divergence, never
    // silent LWW), so before any byte is staged, in pinned order:
    //
    // 1. the body must satisfy the pinned receipt field set, now including
    //    the four-entry att_ verification grammar (ONE-1140 v2) — a blob
    //    that fails receipt decode is a remote rejection (quarantined by
    //    the callers via `remote_rejection_reason`);
    // 2. immutability (UNCHANGED, before any crypto — accepted local bytes
    //    always win): id absent locally → fall through to the origin
    //    predicate; id present with byte-identical envelope → idempotent
    //    no-op (own-receipt CRDT round-trips stay green); id present with
    //    DIVERGENT bytes → typed rejection, LOCAL bytes are kept and the
    //    remote payload is quarantined;
    // 3. NEW id: Ed25519 transcript verification against the embedded
    //    att_pk (ONE-1140 OD-6), and
    // 4. `ls:` lease-binding point read in the SAME txn (OD-3/OD-7: absent
    //    → ReceiptLeaseUnknown; pubkey mismatch → ReceiptAttestationInvalid;
    //    revoked → ReceiptLeaseRevoked; active|expired → accept).
    //
    // All checks run before `put_replicated` stages anything, so a rejected
    // receipt never leaves partial writes in the transaction. A quarantined
    // receipt's bytes remain in the CRDT map, so the next forward
    // rematerialization re-admits it once the lease mirror catches up
    // (OD-10 lazy re-admission — no new scheduling machinery).
    let quota_debit = if header.entity_type == crate::registry::ENTITY_TYPE_REDACTION_AUDIT {
        crate::deletion::validate_redaction_receipt_body(data)?;
        if let Some(existing) = vault.store.entities.get(&*wtxn, id.as_bytes())? {
            if *existing == *blob {
                return Ok(false);
            }
            // ONE-1087 designed exception: the sweep executor's receipt
            // finalization (`sweep_complete_at` None→Some) is LOCAL-LMDB
            // -only, so the CRDT mirror keeps replaying the PRE-finalization
            // bytes forever. That one monotone shape — identical envelope
            // and fields, local Some vs incoming nil — is the own node's
            // stale echo: idempotent skip, never quarantine, never
            // overwrite local. Every other divergence stays on the M4-07
            // quarantine path.
            if crate::deletion::redaction_receipt_is_stale_finalization_echo(&existing, blob) {
                tracing::debug!(
                    entity = %key,
                    "observer-b: stale pre-finalization receipt echo — keeping finalized local"
                );
                return Ok(false);
            }
            return Err(crate::Error::Sync(
                crate::error::SyncError::RedactionReceiptDivergence { id },
            ));
        }
        let pubkey = crate::sync::lease::verify_new_receipt_origin_for_vault_in_txn(
            vault,
            wtxn,
            lease_vault_id,
            &id,
            blob,
        )?;
        quota::try_accept_maintenance_ingest_peer_in_txn(
            vault,
            wtxn,
            quota::peer_key_from_redaction_pubkey(&pubkey),
            crate::unix_seconds_now(),
        )?
    } else if header.entity_type == ENTITY_TYPE_AUTHORITY_LOG {
        if let Some(existing) = vault.store.entities.get(&*wtxn, id.as_bytes())?
            && *existing == *blob
        {
            quarantine_and_neutralize_protected_tombstone_in_txn(
                vault,
                wtxn,
                tombstones_map,
                window_key,
                &id,
                header.entity_type,
            )?;
            return Ok(false);
        }
        let validation = crate::batch::validate_replicated_authority_log_for_local_vault(
            &vault.store,
            wtxn,
            &id,
            data,
        )?;
        let peer_key = if validation.signer_known {
            quota::peer_key_from_authority_key(&validation.signer_key)
        } else {
            quota::peer_key_from_unknown_authority_signer(validation.local_vault_id)
        };
        quota::try_accept_maintenance_ingest_peer_in_txn(
            vault,
            wtxn,
            peer_key,
            crate::unix_seconds_now(),
        )?
    } else if header.entity_type == crate::registry::ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT {
        // ARCH-0055 identity-topology ledger events route through the ONE
        // shared fail-closed ingest door (validation, per-stream quota,
        // seq-clock join, shell-edge reconciliation) — the same door
        // forward rematerialization uses, so no sync entry point admits
        // the byte outside the ruled trust model.
        let materialized = ingest_replicated_identity_topology_event_in_txn(
            vault,
            wtxn,
            &id,
            &header,
            blob,
            data,
            lease_vault_id,
        )?;
        quarantine_and_neutralize_protected_tombstone_in_txn(
            vault,
            wtxn,
            tombstones_map,
            window_key,
            &id,
            header.entity_type,
        )?;
        return Ok(materialized);
    } else {
        None
    };

    // Replicated put: Observer B mirrors whatever the unfiltered CRDT
    // entities map holds, including the engine-authored maintenance band
    // (REDACTION_AUDIT = 120) and reserved-predicate `edge.provenance`
    // truth-Claims. The public gate would warn-skip those, losing GDPR
    // receipts / edge-provenance truth on sync; `put_replicated` admits both
    // engine-authored bands while still validating structure: unknown type
    // bytes, ungrammatical predicates, and malformed CLAIM bodies fail the
    // D18 gate typed, and `edge.provenance` Claims additionally get full
    // value-record + actor-class-evidence validation at the same write
    // chokepoint (ONE-1159) — a D18-valid wrapper around a structurally
    // invalid provenance record is a typed rejection HERE (quarantined by
    // the callers via `remote_rejection_reason`, exactly like a rejected
    // receipt above), no longer a stored Claim that fails closed only at
    // read/supersede time.
    let apply_result = vault
        .batch_in()
        .put_replicated(
            &id,
            header.entity_type,
            crate::temporal::TimeRange {
                start: header.occurred_start,
                end: header.occurred_end,
            },
            header.learned_at,
            data,
        )
        .apply(wtxn);
    if let Err(err) = apply_result {
        if let Some(quota_debit) = quota_debit {
            quota::rollback_maintenance_ingest_debit_in_txn(vault, wtxn, quota_debit)?;
        }
        return Err(err);
    }
    if delete_protected {
        quarantine_and_neutralize_protected_tombstone_in_txn(
            vault,
            wtxn,
            tombstones_map,
            window_key,
            &id,
            header.entity_type,
        )?;
    }
    Ok(true)
}
