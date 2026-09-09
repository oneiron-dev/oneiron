//! Entity pass of forward rematerialization: materialize window entity blobs into LMDB.

use std::collections::{HashMap, HashSet};

use loro::CommitOptions;

use super::super::bridge::{self, BRIDGE_ORIGIN};
use super::super::diagnostic_ingest;
use super::super::egress::push_terminal_quarantine_marker;
use super::super::loro_support::{map_delete, map_for_each_value_bytes, tombstone_map_contains_id};
use super::super::quarantine::{self, QuarantineContainer};
use super::super::quota;
use super::super::reverse::delete_edges_touching_entities;
#[cfg(any(test, feature = "test-hooks"))]
use super::super::test_hooks;
use super::{RematCtx, RematLedger};

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::companion::{
    CompanionExportClassification, ENTITY_TYPE_COMPANION_REGISTER, decode_companion_record_body,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_AUTHORITY_LOG;

/// Run the entity pass: iterate the window `entities` map, replay each blob
/// through its door, then delete local-only companion carriers (tail below).
///
/// Takes the pass's single read txn inside this fn (Trap 3); every
/// `entity_error` aborts the pass and never reaches the match below (Trap 1).
pub(super) fn run(ctx: &RematCtx<'_>, ledger: &mut RematLedger) -> Result<()> {
    let vault = ctx.vault;
    let doc = ctx.doc;
    let window_key = ctx.window_key;
    let lease_vault_id = ctx.lease_vault_id;
    let entities_map = &ctx.entities_map;
    let edges_map = &ctx.edges_map;
    let tombstones_map = &ctx.tombstones_map;
    let marked = &ledger.marked;
    let healed = &mut ledger.healed;
    let terminal_quarantines = &mut ledger.terminal_quarantines;
    let pending_subject_model_dependencies = &mut ledger.pending_subject_model_dependencies;
    let mut count = ledger.count;

    // Entities
    {
        let rtxn = vault.store.env.read_txn()?;
        let mut materialized_blobs = HashMap::<EntityId, Vec<u8>>::new();
        let mut entity_error = None;
        let mut local_only_companion_entity_keys = Vec::<String>::new();
        let mut local_only_companion_entity_ids = HashSet::<EntityId>::new();
        map_for_each_value_bytes(entities_map, |key, blob| {
            if entity_error.is_some() {
                return;
            }

            // ONE-1157: non-Binary value where an entity blob belongs — an
            // undecodable remote op, quarantined exactly like Observer B's
            // non-Binary arm (empty payload: a non-Binary value carries no
            // bytes), never an invisible skip.
            let Some(blob) = blob else {
                if let Err(err) = quarantine::quarantine_rejected_op(
                    vault,
                    window_key.as_str(),
                    QuarantineContainer::Entities,
                    key,
                    &Error::InvalidKey,
                    &[],
                ) {
                    entity_error = Some(err);
                } else {
                    push_terminal_quarantine_marker(
                        terminal_quarantines,
                        QuarantineContainer::Entities,
                        key,
                    );
                }
                return;
            };

            let id = match EntityId::from_hex(key) {
                Ok(id) => id,
                Err(_) => {
                    if let Err(err) = quarantine::quarantine_rejected_op(
                        vault,
                        window_key.as_str(),
                        QuarantineContainer::Entities,
                        key,
                        &Error::InvalidKey,
                        blob,
                    ) {
                        entity_error = Some(err);
                    }
                    return;
                }
            };

            // ONE-1158 (Observer-B parity): a non-canonical (case-shifted)
            // hex alias key is a protocol violation — no engine version
            // ever emits one (`to_hex()` is lowercase). Quarantine instead
            // of materializing: an alias key never enters LMDB
            // materialization (fail closed at the door).
            if key != id.to_hex() {
                if let Err(err) = quarantine::quarantine_rejected_op(
                    vault,
                    window_key.as_str(),
                    QuarantineContainer::Entities,
                    key,
                    &Error::InvalidKey,
                    blob,
                ) {
                    entity_error = Some(err);
                } else {
                    terminal_quarantines.push(id);
                }
                return;
            }

            // Decode the envelope before deletion gates so a concurrent
            // protected engine record (notably type-76) cannot be hidden by
            // a hostile tombstone or a pre-fix `dt:` poison marker.
            let header = match EntityMetadataHeader::parse(blob) {
                Some(header) => header,
                None => {
                    if let Err(err) = quarantine::quarantine_rejected_op(
                        vault,
                        window_key.as_str(),
                        QuarantineContainer::Entities,
                        key,
                        &Error::CorruptedIndex("entity metadata"),
                        blob,
                    ) {
                        entity_error = Some(err);
                    } else {
                        terminal_quarantines.push(id);
                    }
                    return;
                }
            };
            let delete_protected =
                crate::registry::is_delete_protected_engine_record(header.entity_type);

            // Tombstone gate (delete wins): a tombstoned id must never
            // re-materialize from a lingering entities-map body — without
            // this gate every boot would re-put the purged body and the
            // tombstone pass below would purge it again, multiplying
            // receipts forever. Presence is value-agnostic (a non-binary
            // tombstone decodes HARD downstream) AND entity-canonical (a
            // case-shifted hex tombstone key still names this id), and
            // OR'd with the permanent local `dt:` marker so a hostile peer
            // that REMOVES the tombstone from the map cannot resurrect the
            // body either. A failed marker read fails CLOSED (skip).
            if !delete_protected && tombstone_map_contains_id(tombstones_map, &id) {
                return;
            }
            let locally_hard_deleted = !delete_protected
                && match vault.local_hard_delete_marker_exists_in_txn(&rtxn, &id) {
                    Ok(present) => present,
                    Err(e) => {
                        tracing::warn!(
                            entity = %key,
                            error = %e,
                            "forward remat: dt: marker read failed — failing closed"
                        );
                        true
                    }
                };
            if locally_hard_deleted {
                return;
            }

            // Track the local record for most ids: byte-identical →
            // idempotent skip (return). Immutable kinds make this decision later
            // inside their own replay door instead: REDACTION_AUDIT receipts
            // (inside the same write txn as their lease verification and
            // replicated put, so a stale long-lived `rtxn` cannot hide a
            // mid-flight finalized/divergent receipt), ARCH-0055
            // type-76 events (whose door preserves immutable divergence and
            // seq-clock checks on byte-identical replay while short-circuiting
            // before the full-family reconciliation DoS surface), and
            // ONE-1604-D5 AUTHORITY_LOG authority rows (whose door must reach the
            // `dt:` neutralization even on an exact-byte match: a replica
            // whose authority row is already materialized byte-for-byte while
            // a tombstone-first replay left a `dt:` marker behind would
            // otherwise keep that false delete marker forever, and the
            // hard-erase sweep would later scrub append-only authority
            // evidence for an id it believes was erased). DIAGNOSTIC rows
            // also validate their address and occurrence before the in-txn
            // echo check, never through the generic snapshot shortcut.
            let byte_compare_in_door = matches!(
                header.entity_type,
                crate::registry::ENTITY_TYPE_REDACTION_AUDIT
                    | crate::registry::ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT
                    | crate::registry::ENTITY_TYPE_DIAGNOSTIC
                    | ENTITY_TYPE_AUTHORITY_LOG
            );
            if !byte_compare_in_door {
                if let Some(latest) = materialized_blobs.get(&id) {
                    if latest.as_slice() == blob {
                        return;
                    }
                } else {
                    let lmdb_blob = match vault.get_raw_in(&rtxn, &id) {
                        Ok(v) => v,
                        Err(err) => {
                            entity_error = Some(err);
                            return;
                        }
                    };
                    if lmdb_blob.as_deref() == Some(blob) {
                        return;
                    }
                    // SoftErase shell guard: `user_delete` truncates the
                    // local record to the 25 B header shell and writes NO
                    // CRDT record (contracts.ts deleteReasons user_delete:
                    // "Tombstone revision (empty content); keep the message
                    // shell" — cross-device propagation is deferred to
                    // ONE-1090), so the CRDT mirror still carries the
                    // pre-delete body. Replaying that body over the shell
                    // would resurrect deleted content — delete wins.
                    // Interim guard until reason-aware tombstones land in
                    // M4-06.
                    if let Some(local) = &lmdb_blob
                        && local.len() == ENTITY_METADATA_HEADER_LEN
                        && blob.len() > ENTITY_METADATA_HEADER_LEN
                    {
                        tracing::warn!(
                            entity = %id.to_hex(),
                            "forward remat: kept local SoftErase shell over longer CRDT body (reason-aware tombstones land in M4-06)"
                        );
                        return;
                    }
                }
            }

            let data = if blob.len() > ENTITY_METADATA_HEADER_LEN {
                &blob[ENTITY_METADATA_HEADER_LEN..]
            } else {
                &[]
            };
            if header.entity_type == ENTITY_TYPE_COMPANION_REGISTER {
                match decode_companion_record_body(data) {
                    Ok(record)
                        if record.export_classification
                            == CompanionExportClassification::LocalOnly =>
                    {
                        local_only_companion_entity_keys.push(key.to_owned());
                        local_only_companion_entity_ids.insert(id);
                        return;
                    }
                    Ok(_) | Err(_) => {
                        if let Err(err) = vault.ensure_companion_register_kind() {
                            entity_error = Some(err);
                            return;
                        }
                    }
                }
            }
            // ONE-1134 + ONE-1140: the REDACTION_AUDIT replay door
            // #2. Receipts are immutable audit records (contracts.ts
            // `redactionAuditReceipt`; ARCH-0023b audit/guardrail class:
            // quarantine divergence, never silent LWW), pinned door order:
            // * a blob failing the pinned receipt-body validation (incl.
            //   the ONE-1140 v2 att_ verification grammar) is quarantined,
            //   never written;
            // * id present locally with byte-identical/stale-echo bytes →
            //   skip inside the write txn; any other divergence →
            //   quarantine the remote payload and KEEP the local bytes
            //   (before any crypto — accepted local bytes always win);
            // * id absent (NEW receipt) → the ONE-1140 origin predicate:
            //   Ed25519 transcript verification + `ls:` lease-binding read
            //   (OD-6/OD-7). Remote-classified rejections quarantine; a
            //   LOCAL failure (storage, corrupt ls: mirror row) fails
            //   closed. This pass is also the OD-10 lazy re-admission path:
            //   a previously quarantined receipt re-runs the door here
            //   after the lease mirror catches up.
            if header.entity_type == crate::registry::ENTITY_TYPE_REDACTION_AUDIT
                && let Err(err) = crate::deletion::validate_redaction_receipt_body(data)
            {
                if let Err(q_err) = quarantine::quarantine_rejected_op(
                    vault,
                    window_key.as_str(),
                    QuarantineContainer::Entities,
                    key,
                    &err,
                    blob,
                ) {
                    entity_error = Some(q_err);
                } else {
                    terminal_quarantines.push(id);
                }
                return;
            }
            // Replicated put: the CRDT mirror is unfiltered, so the
            // system zone (REDACTION_AUDIT) and reserved-predicate
            // `edge.provenance` truth-Claims reach here on the way back into
            // LMDB. Routing through the public gate would silently drop them
            // on cross-node sync / replay; `put_replicated` admits both
            // engine-authored bands while still running full structural
            // validation (unknown type bytes, ungrammatical predicates, and
            // malformed CLAIM bodies all still fail typed).
            let result = if header.entity_type == crate::registry::ENTITY_TYPE_DIAGNOSTIC {
                vault.with_write_txn(|wtxn| {
                    diagnostic_ingest::ingest_diagnostic_in_txn(
                        vault,
                        wtxn,
                        &id,
                        blob,
                        lease_vault_id,
                    )
                })
            } else if header.entity_type == crate::registry::ENTITY_TYPE_REDACTION_AUDIT {
                #[cfg(any(test, feature = "test-hooks"))]
                if let Err(err) = test_hooks::run_receipt_revocation_race(vault) {
                    entity_error = Some(err);
                    return;
                }
                vault.with_write_txn(|wtxn| {
                    if let Some(local) = vault.store.entities.get(&*wtxn, id.as_bytes())? {
                        if *local == *blob {
                            return Ok(false);
                        }
                        // ONE-1087 designed exception: the sweep's receipt
                        // finalization (`sweep_complete_at` None→Some) is
                        // LOCAL-LMDB-only, so the CRDT mirror replays the
                        // PRE-finalization bytes every boot. That one
                        // monotone shape is the own node's stale echo:
                        // idempotent skip, never an x: row. All other
                        // divergence quarantines.
                        if crate::deletion::redaction_receipt_is_stale_finalization_echo(
                            &local, blob,
                        ) {
                            tracing::debug!(
                                entity = %key,
                                "forward remat: stale pre-finalization receipt echo — keeping finalized local"
                            );
                            return Ok(false);
                        }
                        quarantine::quarantine_rejected_op_in_txn(
                            vault,
                            wtxn,
                            window_key.as_str(),
                            QuarantineContainer::Entities,
                            key,
                            &Error::RedactionReceiptDivergence { id },
                            blob,
                        )?;
                        terminal_quarantines.push(id);
                        return Ok(false);
                    }
                    let pubkey = crate::sync::lease::verify_new_receipt_origin_for_vault_in_txn(
                        vault,
                        wtxn,
                        lease_vault_id,
                        &id,
                        blob,
                    )?;
                    let _quota_debit = quota::try_accept_maintenance_ingest_peer_in_txn(
                        vault,
                        wtxn,
                        quota::peer_key_from_redaction_pubkey(&pubkey),
                        crate::unix_seconds_now(),
                    )?;
                    vault
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
                        .apply(wtxn)?;
                    Ok(true)
                })
            } else if header.entity_type == ENTITY_TYPE_AUTHORITY_LOG {
                vault.with_write_txn(|wtxn| {
                    // ONE-1604-D5: the byte comparison runs inside this
                    // door's own write txn (type-76 parity) so an exact
                    // match still reaches the `dt:` neutralization below.
                    // Returning early here — as the pre-fix shared
                    // byte-compare did — left a tombstone-first replica's
                    // false delete marker permanent, and the hard-erase
                    // sweep would then scrub append-only authority evidence.
                    if let Some(local) = vault.store.entities.get(&*wtxn, id.as_bytes())?
                        && *local == *blob
                    {
                        vault.neutralize_delete_protected_marker_in_txn(
                            wtxn,
                            &id,
                            ENTITY_TYPE_AUTHORITY_LOG,
                        )?;
                        // Still a byte-identical skip for ONE-1147 purposes:
                        // clearing poison is a repair, not a healing write,
                        // so parity alone must not discharge an `rm:` marker.
                        return Ok(false);
                    }
                    let validation =
                        crate::batch::validate_replicated_authority_log_for_local_vault(
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
                    let _quota_debit = quota::try_accept_maintenance_ingest_peer_in_txn(
                        vault,
                        wtxn,
                        peer_key,
                        crate::unix_seconds_now(),
                    )?;
                    vault
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
                        .apply(wtxn)?;
                    // ONE-1604-D1/D5 parity with the bridge arm: a tombstone
                    // that arrived before this row may have minted a `dt:`
                    // marker on the headerless path; it never represented
                    // valid delete authority over a delete-protected kind, so
                    // it must not linger as permanent poison on this ingest
                    // path.
                    vault.neutralize_delete_protected_marker_in_txn(
                        wtxn,
                        &id,
                        ENTITY_TYPE_AUTHORITY_LOG,
                    )?;
                    Ok(true)
                })
            } else if header.entity_type == crate::registry::ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT {
                // ARCH-0055: type-76 ledger events route through the SAME
                // fail-closed single-writer ingest door as Observer B —
                // never the generic LWW arm below, which would silently
                // overwrite an accepted local event with divergent remote
                // bytes and skip validation, the per-stream quota, the
                // seq-clock join, and shell-edge reconciliation. A
                // divergent or malformed remote row classifies as a remote
                // rejection (quarantine-and-continue) at the match below.
                vault.with_write_txn(|wtxn| {
                    bridge::ingest_replicated_identity_topology_event_in_txn(
                        vault,
                        wtxn,
                        &id,
                        &header,
                        blob,
                        data,
                        lease_vault_id,
                    )
                })
            } else {
                vault.with_write_txn(|wtxn| {
                    vault
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
                        .apply(wtxn)?;
                    Ok(true)
                })
            };
            match result {
                Ok(true) => {
                    materialized_blobs.insert(id, blob.to_vec());
                    count += 1;
                    // ONE-1147: an ACTUAL healing write discharges this
                    // entity's needs-remat marker (set by a failed
                    // Observer-B batch). Byte-identical skips above never
                    // reach here — parity alone must not discharge.
                    if marked.contains(&id.to_hex()) {
                        healed.push(id);
                    }
                }
                Ok(false) => {}
                Err(err) if quarantine::remote_rejection_reason(&err).is_some() => {
                    let subject_pending =
                        crate::subject_model::subject_model_dependency_pending(&err);
                    if subject_pending {
                        pending_subject_model_dependencies.insert(id);
                    }
                    let retryable = subject_pending
                        || matches!(err, Error::MaintenanceIngestQuotaExceeded { .. });
                    if let Err(q_err) = quarantine::quarantine_rejected_op(
                        vault,
                        window_key.as_str(),
                        QuarantineContainer::Entities,
                        key,
                        &err,
                        blob,
                    ) {
                        entity_error = Some(q_err);
                    } else if !retryable {
                        terminal_quarantines.push(id);
                    }
                }
                Err(err) => {
                    // LOCAL failure — fail closed.
                    entity_error = Some(err);
                }
            }
        });
        if let Some(err) = entity_error {
            return Err(err);
        }
        if !local_only_companion_entity_keys.is_empty() {
            let mut wrote_doc = false;
            for key in &local_only_companion_entity_keys {
                map_delete(entities_map, key)?;
                wrote_doc = true;
            }
            if delete_edges_touching_entities(edges_map, &local_only_companion_entity_ids)? {
                wrote_doc = true;
            }
            if wrote_doc {
                doc.commit_with(CommitOptions::new().origin(BRIDGE_ORIGIN));
            }
        }
    }
    ledger.count = count;
    Ok(())
}
