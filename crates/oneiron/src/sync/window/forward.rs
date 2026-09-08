//! Forward rematerialization of window state into the CRDT doc.

use std::collections::{HashMap, HashSet};

use super::bridge::{self, BRIDGE_ORIGIN, Materializer};
use super::egress::push_terminal_quarantine_marker;
use super::loro_support::{
    map_delete, map_for_each_tombstone_value, map_for_each_value_bytes, map_get_bytes,
    tombstone_map_contains_id,
};
use super::quarantine::{self, QuarantineContainer};
use super::queue::scrub_receiver_outbox_on_remote_hard_delete_in_txn;
use super::quota;
use super::reverse::delete_edges_touching_entities;
#[cfg(any(test, feature = "test-hooks"))]
use super::test_hooks;
use super::types::WindowKey;

use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EdgeValueFields, EntityMetadataHeader};
use crate::companion::{
    CompanionExportClassification, ENTITY_TYPE_COMPANION_REGISTER, decode_companion_record_body,
};
use crate::deletion::decode_tombstone_value;
use crate::edge::decode_edge_value_for_kind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_AUTHORITY_LOG;
use crate::store::Store;
use loro::{CommitOptions, LoroDoc};

#[expect(clippy::too_many_lines)]
pub fn forward_rematerialize(
    vault: &Vault,
    doc: &LoroDoc,
    materializer: &Materializer,
    window_key: &WindowKey,
) -> Result<u32> {
    let _guard = materializer.lock();
    let lease_vault_id = materializer.lease_vault_id();
    let entities_map = doc.get_map("entities");
    let edges_map = doc.get_map("edges");
    let tombstones_map = doc.get_map("tombstones");

    // Entity-scoped retry markers pending for this window, loaded up front:
    // the entity/edge passes discharge a marker only via an actual healing
    // write (ONE-1147); the tombstone pass only via that entity's own
    // replay success (ONE-1124). Malformed marker rows never match a
    // canonical `to_hex()` and so are never discharged here (fail closed).
    let marked: HashSet<String> = quarantine::pending_remat_entities(vault, window_key.as_str())?
        .into_iter()
        .collect();
    let mut healed: Vec<EntityId> = Vec::new();
    let mut terminal_quarantines: Vec<EntityId> = Vec::new();
    let mut pending_subject_model_dependencies = HashSet::new();

    let mut count = 0u32;

    // Entities
    {
        let rtxn = vault.store.env.read_txn()?;
        let mut materialized_blobs = HashMap::<EntityId, Vec<u8>>::new();
        let mut entity_error = None;
        let mut local_only_companion_entity_keys = Vec::<String>::new();
        let mut local_only_companion_entity_ids = HashSet::<EntityId>::new();
        map_for_each_value_bytes(&entities_map, |key, blob| {
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
                        &mut terminal_quarantines,
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
            if !delete_protected && tombstone_map_contains_id(&tombstones_map, &id) {
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
                    super::diagnostic_ingest::ingest_diagnostic_in_txn(
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
                map_delete(&entities_map, key)?;
                wrote_doc = true;
            }
            if delete_edges_touching_entities(&edges_map, &local_only_companion_entity_ids)? {
                wrote_doc = true;
            }
            if wrote_doc {
                doc.commit_with(CommitOptions::new().origin(BRIDGE_ORIGIN));
            }
        }
    }

    // Edges (endpoint + tombstone filtering, stored-value byte-compare).
    // ARCH-0023b step 5 byte-compares edges too ("write any that differ"):
    // an exists-skip would let a CRDT edge carrying confirmation_status =
    // retracted (value[24] == 3) lose to a stale local Active stamp, and the
    // PPR retracted gate would keep propagating withdrawn provenance.
    {
        enum EdgeRematOutcome {
            Written,
            Unchanged,
            Deferred,
            Quarantined,
        }

        let mut edge_error = None;
        map_for_each_value_bytes(&edges_map, |key, buf| {
            if edge_error.is_some() {
                return;
            }
            // ONE-1157 (edge-pass parity, same gap as the entity pass):
            // non-Binary value where an edge value belongs — quarantined
            // like Observer B's non-Binary edge arm, never an invisible
            // skip.
            let Some(buf) = buf else {
                if let Err(err) = quarantine::quarantine_rejected_op(
                    vault,
                    window_key.as_str(),
                    QuarantineContainer::Edges,
                    key,
                    &Error::InvalidKey,
                    &[],
                ) {
                    edge_error = Some(err);
                } else {
                    push_terminal_quarantine_marker(
                        &mut terminal_quarantines,
                        QuarantineContainer::Edges,
                        key,
                    );
                }
                return;
            };
            let Some((src, kind, tgt)) = bridge::parse_edge_key(key) else {
                if let Err(err) = quarantine::quarantine_rejected_op(
                    vault,
                    window_key.as_str(),
                    QuarantineContainer::Edges,
                    key,
                    &Error::InvalidKey,
                    buf,
                ) {
                    edge_error = Some(err);
                }
                return;
            };

            // Decode BEFORE the tombstone/endpoint gates (mirrors Observer
            // B's ordering in bridge.rs): a malformed value is a remote
            // rejection regardless of endpoint state, and decode has no side
            // effects. Checking endpoints first would silently defer a
            // valid-key malformed edge whose endpoint is absent — no x: row.
            let decoded = match decode_edge_value_for_kind(kind, buf) {
                Ok(decoded) => decoded,
                Err(err) => {
                    if let Err(q_err) = quarantine::quarantine_rejected_op(
                        vault,
                        window_key.as_str(),
                        QuarantineContainer::Edges,
                        key,
                        &err,
                        buf,
                    ) {
                        edge_error = Some(q_err);
                    } else {
                        terminal_quarantines.push(src);
                    }
                    return;
                }
            };

            // Never re-add an edge whose endpoint is tombstoned in the CRDT.
            // ANY-value, entity-canonical presence — a non-binary tombstone
            // gates too, and a case-shifted hex alias still names the id.
            if tombstone_map_contains_id(&tombstones_map, &src)
                || tombstone_map_contains_id(&tombstones_map, &tgt)
            {
                return;
            }

            // The reserved-kind mandate, endpoint readiness, stored-byte
            // comparison, and paired write share ONE LMDB write txn. A
            // separate read check followed by `batch().commit()` would let
            // an intervening undo revoke the mandate before the edge write.
            let result = vault.with_write_txn(|wtxn| {
                if let Err(reserved) = crate::edge::validate_public_edge_kind(kind) {
                    let mandated_at = vault
                        .identity_topology_mandated_shell_edge_in_txn(&*wtxn, &src, kind, &tgt)?;
                    let door_echo = mandated_at.is_some_and(|at| {
                        decoded.created_at == at && kind.default_weight() == Some(decoded.weight)
                    });
                    if !door_echo {
                        quarantine::quarantine_rejected_op_in_txn(
                            vault,
                            wtxn,
                            window_key.as_str(),
                            QuarantineContainer::Edges,
                            key,
                            &reserved,
                            buf,
                        )?;
                        return Ok(EdgeRematOutcome::Quarantined);
                    }
                }

                let src_exists = vault.store.entities.get(&*wtxn, src.as_bytes())?.is_some();
                let tgt_exists = vault.store.entities.get(&*wtxn, tgt.as_bytes())?.is_some();
                if !src_exists || !tgt_exists {
                    return Ok(EdgeRematOutcome::Deferred);
                }

                // ONE-1645 replay door for the FacetOf type table. The batch
                // arm this write lands on (`BatchOp::EdgeWithCreatedAt`) is
                // deliberately UNGATED — a hard abort there would wedge sync
                // permanently (H2) — so the table is enforced HERE, at the
                // remat chokepoint, as a quarantine-and-continue rejection.
                //
                // Without it a federation peer could replay an off-table
                // stamp (e.g. PERSON -> FACET) that no local public writer
                // can write, and it would reach LMDB — where the local query
                // door reads facet adjacency with no admitted-set filter of
                // its own. The federation selector no longer honors such a
                // source (`selector::facet_scope_by_source` mirrors this same
                // table on read), but the LMDB write is still an
                // authorization-boundary bypass via replay: this door is what
                // keeps the shape out of the retrieval truth at all.
                //
                // Ordered AFTER the endpoint-existence check on purpose: a
                // cross-window endpoint that has not arrived yet is a
                // DEFERRAL, not a rejection, and the type table reads
                // endpoint types from the entity rows this check just proved
                // present. Reversing the order would burn a legitimate
                // out-of-order replay as a permanent quarantine.
                //
                // The match is GUARDED (ONE-1124 fail-closed split): only a
                // remote-classifiable error may quarantine. The table also
                // surfaces LOCAL faults — `CorruptedIndex("entity header")`
                // on a stored row it cannot parse, and heed read errors on
                // the type lookups themselves — and those must ABORT the
                // drain. Quarantining one would be doubly wrong: it swallows
                // our own storage defect behind a continue, and the `x:` row
                // it writes is PERMANENT false evidence accusing the peer of
                // a forgery it never sent.
                match crate::batch::validate_facet_of_edge(&vault.store, &*wtxn, src, kind, tgt) {
                    Ok(()) => {}
                    Err(off_table) if quarantine::remote_rejection_reason(&off_table).is_some() => {
                        quarantine::quarantine_rejected_op_in_txn(
                            vault,
                            wtxn,
                            window_key.as_str(),
                            QuarantineContainer::Edges,
                            key,
                            &off_table,
                            buf,
                        )?;
                        return Ok(EdgeRematOutcome::Quarantined);
                    }
                    Err(local) => return Err(local),
                }

                let out_key = Store::encode_edge_key(&src, kind, &tgt);
                let in_key = Store::encode_edge_key(&tgt, kind, &src);
                let out_matches = vault
                    .store
                    .edges_out
                    .get(&*wtxn, &out_key)?
                    .is_some_and(|value| value == buf);
                let in_matches = vault
                    .store
                    .edges_in
                    .get(&*wtxn, &in_key)?
                    .is_some_and(|value| value == buf);
                if out_matches && in_matches {
                    return Ok(EdgeRematOutcome::Unchanged);
                }

                vault
                    .batch_in()
                    .edge_with_value_fields(
                        &src,
                        kind,
                        &tgt,
                        EdgeValueFields::from_decoded(decoded),
                    )
                    .apply(wtxn)?;
                Ok(EdgeRematOutcome::Written)
            });
            match result {
                Ok(EdgeRematOutcome::Written) => {
                    count += 1;
                    // ONE-1147: a healing edge write discharges the SOURCE
                    // entity's needs-remat marker (Observer B's edge batch
                    // swallow site marks lost upserts by source id).
                    if marked.contains(&src.to_hex()) {
                        healed.push(src);
                    }
                }
                Ok(EdgeRematOutcome::Unchanged) => {}
                Ok(EdgeRematOutcome::Deferred) => {
                    // Deferral, not a rejection: cross-window endpoints
                    // arrive later; the edge stays in the CRDT and
                    // re-materializes when its endpoints do.
                    tracing::debug!(
                        edge = %key,
                        "forward remat: edge deferred — endpoint absent"
                    );
                }
                Ok(EdgeRematOutcome::Quarantined) => {
                    // The reserved-kind rejection and its durable evidence
                    // committed in the edge txn above. Keep iterating: one
                    // forged row must not starve the other N-1 edge heals.
                    terminal_quarantines.push(src);
                }
                Err(err) if quarantine::remote_rejection_reason(&err).is_some() => {
                    if let Err(q_err) = quarantine::quarantine_rejected_op(
                        vault,
                        window_key.as_str(),
                        QuarantineContainer::Edges,
                        key,
                        &err,
                        buf,
                    ) {
                        edge_error = Some(q_err);
                    } else {
                        terminal_quarantines.push(src);
                    }
                }
                Err(err) => {
                    // LOCAL failure — fail closed.
                    edge_error = Some(err);
                }
            }
        });
        if let Some(err) = edge_error {
            return Err(err);
        }
    }

    // Tombstones — reason-aware replay (ONE-1133 / ARCH-0038): the VALUE
    // decides the effect, routed through the shared primitive, never a
    // bare purge. Known-soft `user_delete` keeps the 25 B shell (SoftErase
    // + D16 refresh); every other shape hard-purges and — when local state
    // was erased — writes the LOCAL REDACTION_AUDIT receipt and `h:` sweep
    // row. The tombstone-aware iterator visits EVERY value: a non-Binary
    // tombstone replays as the empty slice, which decodes HARD — a
    // malformed remote tombstone must never be skipped (it would leave the
    // entity pass's re-materialized body live forever = durable
    // resurrection). The primitive is idempotent (no receipt when nothing
    // local remains), so this every-boot pass cannot multiply receipts.
    //
    // Retry state is ENTITY-scoped (ONE-1124): `rm:w:{window}:{entity_hex}`
    // is written for the specific entity whose replay failed, and cleared
    // ONLY when that entity's own replay succeeds — an unrelated
    // tombstone's success must never discharge another entity's retry.
    // (`marked` is the up-front snapshot loaded before the entity pass.)
    let mut purge_failures: Vec<EntityId> = Vec::new();
    let mut cleared: Vec<EntityId> = Vec::new();
    let mut receiver_scrub_candidates: Vec<EntityId> = Vec::new();
    let mut tombstone_error: Option<Error> = None;
    map_for_each_tombstone_value(&tombstones_map, |key, value| {
        if tombstone_error.is_some() {
            return;
        }
        let id = match EntityId::from_hex(key) {
            Ok(id) => id,
            Err(_) => {
                if let Err(err) = quarantine::quarantine_rejected_op(
                    vault,
                    window_key.as_str(),
                    QuarantineContainer::Tombstones,
                    key,
                    &Error::InvalidKey,
                    value,
                ) {
                    tombstone_error = Some(err);
                }
                return;
            }
        };

        // The entity pass may have rejected or not yet materialized a
        // concurrent protected record. Its CRDT envelope is still enough
        // to deny delete authority: quarantine the tombstone before the
        // headerless replay path can mint a permanent `dt:` marker.
        if matches!(vault.read_entity_header(&id), Ok(None))
            && let Some(entity_blob) = map_get_bytes(&entities_map, &id.to_hex())
            && let Some(header) = bridge::admitted_concurrent_delete_protected_header(&entity_blob)
        {
            let rejection = Error::MaintenanceKindNotWritable(header.entity_type);
            if let Err(quarantine_err) = quarantine::quarantine_rejected_op(
                vault,
                window_key.as_str(),
                QuarantineContainer::Tombstones,
                key,
                &rejection,
                value,
            ) {
                tombstone_error = Some(quarantine_err);
            } else {
                terminal_quarantines.push(id);
            }
            return;
        }

        let hard_tombstone = decode_tombstone_value(value).is_hard();
        match quarantine::apply_replayed_tombstone_for_sync(vault, &id, value) {
            Ok(outcome) => {
                if outcome.changed_local_state() {
                    count += 1;
                }
                if hard_tombstone {
                    receiver_scrub_candidates.push(id);
                }
                // The goal state for THIS tombstone's reason holds (purge
                // done, already absent, or soft shell kept) — the entity's
                // own retry marker (if flagged) is discharged.
                if marked.contains(&id.to_hex()) {
                    cleared.push(id);
                }
            }
            Err(err) if quarantine::remote_rejection_reason(&err).is_some() => {
                if let Err(quarantine_err) = quarantine::quarantine_rejected_op(
                    vault,
                    window_key.as_str(),
                    QuarantineContainer::Tombstones,
                    key,
                    &err,
                    value,
                ) {
                    tombstone_error = Some(quarantine_err);
                } else {
                    terminal_quarantines.push(id);
                }
            }
            Err(err) => {
                // Replay failure — the tombstoned content may still be
                // live. Flag THIS entity for durable retry; the pass keeps
                // going so one failure cannot starve other tombstones.
                purge_failures.push(id);
                tracing::error!(
                    entity = %id.to_hex(),
                    error = %err,
                    "forward remat: tombstone replay FAILED — hard-deleted content may still be live (GDPR SLA breach signal)"
                );
            }
        }
    });

    // An edge outcome is not proof that its source claim's missing actor or
    // subject arrived. Keep that replay pending; a successful tombstone purge may
    // still discharge it through `cleared`, with delete-safety precedence.
    healed.retain(|id| !pending_subject_model_dependencies.contains(id));
    terminal_quarantines.retain(|id| !pending_subject_model_dependencies.contains(id));
    if !purge_failures.is_empty()
        || !cleared.is_empty()
        || !healed.is_empty()
        || !terminal_quarantines.is_empty()
        || !receiver_scrub_candidates.is_empty()
    {
        let marker_result = vault.with_write_txn(|wtxn| {
            // Clear BEFORE set so set wins: an id that both succeeded and
            // failed in one pass (case-shifted tombstone aliases with
            // divergent reasons) must KEEP its marker — losing it would
            // silently drop a pending hard purge (fail closed). The
            // ONE-1147 `healed` discharges (entity/edge healing writes,
            // structurally disjoint from tombstoned ids — both passes are
            // tombstone-gated). ONE-1167 terminal quarantine may discharge
            // only replay/quarantine-origin markers whose provenance sidecar
            // already proves they are not delete-safety retries; legacy or
            // purge-failure markers stay pending until their own tombstone
            // goal state holds.
            let mut success_seen = HashSet::new();
            // Delete-safety invariant: the `cleared` side has this entity's
            // own tombstone goal state above, while the `healed` side is
            // safe only because tombstone-gating keeps entity/edge healing
            // disjoint from unproven delete-safety `rm:` markers. A
            // tombstoned id cannot reach `healed`; if a refactor weakens
            // that gate or reorders this bookkeeping, the debug assert below
            // catches the healed-clear regression before an unproven purge
            // retry can be silently discharged.
            #[cfg(debug_assertions)]
            for id in &healed {
                let has_unproven_marker = quarantine::unproven_remat_marker_exists_in_txn(
                    vault,
                    wtxn,
                    window_key.as_str(),
                    id,
                )
                .unwrap_or_else(|err| {
                    panic!("delete-safety invariant: failed to read rm: marker state: {err}")
                });
                debug_assert!(
                    !has_unproven_marker,
                    "delete-safety invariant: healed ids must be disjoint from unproven rm: markers"
                );
            }
            for id in healed.iter().chain(cleared.iter()) {
                if !success_seen.insert(*id) {
                    continue;
                }
                quarantine::clear_remat_marker_in_txn(vault, wtxn, window_key.as_str(), id)?;
            }
            let mut terminal_seen = HashSet::new();
            for id in &terminal_quarantines {
                if !terminal_seen.insert(*id) {
                    continue;
                }
                let cleared = quarantine::clear_replay_remat_marker_in_txn(
                    vault,
                    wtxn,
                    window_key.as_str(),
                    id,
                )?;
                if !cleared {
                    tracing::debug!(
                        entity = %id.to_hex(),
                        window = %window_key,
                        "forward remat: terminal quarantine left unproven rm: marker pending"
                    );
                }
            }
            // Delete-safety invariant: `purge_failures` MUST be applied LAST,
            // after healed/cleared clears and terminal-quarantine clears.
            // Tombstone/delete-safety dominance requires a failed purge to win
            // over every clear in this txn: a terminal quarantine may remove
            // replay provenance for non-delete markers, but a simultaneous
            // purge failure must restore the unproven `rm:` retry so the
            // delete-safety provenance is not silently removed.
            for id in &purge_failures {
                quarantine::set_remat_marker_in_txn(vault, wtxn, window_key.as_str(), id)?;
            }
            if !receiver_scrub_candidates.is_empty() {
                scrub_receiver_outbox_on_remote_hard_delete_in_txn(
                    vault,
                    wtxn,
                    window_key.as_str(),
                )?;
            }
            Ok(())
        });
        match marker_result {
            Err(err) if receiver_scrub_candidates.is_empty() => return Err(err),
            Err(err) => {
                tracing::error!(
                    window = %window_key,
                    purge_failures = purge_failures.len(),
                    receiver_scrub_candidates = receiver_scrub_candidates.len(),
                    error = %err,
                    "forward remat: receiver outbox scrub/bookkeeping txn FAILED after hard tombstone replay; flagging entity-scoped rm: markers for durable retry"
                );
                vault.with_write_txn(|wtxn| {
                    for id in purge_failures
                        .iter()
                        .chain(receiver_scrub_candidates.iter())
                    {
                        quarantine::set_remat_marker_in_txn(vault, wtxn, window_key.as_str(), id)?;
                    }
                    Ok(())
                })?;
            }
            Ok(()) => {}
        }
    }
    if let Some(err) = tombstone_error {
        return Err(err);
    }
    if quarantine::pending_remat_windows(vault)?
        .iter()
        .any(|window| window == window_key.as_str())
    {
        // Markers survive the pass when a purge failed above, when a
        // flagged entity has neither a healing write nor a proven non-delete
        // terminal x: row in the loaded doc (stale/cross-window state), or
        // when a marker row no longer parses. Clearing any of them here
        // would vacuously discharge a GDPR retry — keep them (fail closed)
        // and keep ERROR-grade visibility.
        tracing::error!(
            window = %window_key,
            "forward remat: rm: markers still pending after tombstone pass — hard-deleted content may be live (GDPR SLA breach signal)"
        );
    }

    Ok(count)
}
