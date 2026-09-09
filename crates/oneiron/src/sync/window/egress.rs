//! Window egress: packing policy, secret scrub, exports, and mirror replay.

use std::collections::HashSet;

use super::HISTORY_FREE_WINDOW_PREFIX;
use super::bridge::{BRIDGE_ORIGIN, encode_edge_value_for_crdt, format_edge_key};
use super::loro_support::{
    export_snapshot, map_contains_binary, map_delete, map_for_each_value_bytes, map_get_bytes,
    map_insert_bytes, tombstone_map_contains_id,
};
use super::quarantine::{self, QuarantineContainer};
use super::reverse::{
    delete_edges_touching_entities, is_secret_custody_record,
    quarantine_outbound_protected_tombstones, remove_entity_crdt_carriers,
    reverse_remat_skip_redaction_receipt_mirror, skip_companion_register_sync_mirror,
};
use super::types::WindowKey;

use crate::Vault;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use loro::{CommitOptions, ExportMode, LoroDoc, VersionVector};

/// THE SYNC WINDOW-PACKING EGRESS DOOR (ARCH-0052 P6, owner ruling
/// R-20260807-06).
///
/// One of the two surviving off-record egress doors, and the ONLY off-record
/// question any packing path asks. `true` means the id is a live
/// session-overlay member: device-local until an explicit P5 promote, so the
/// packing loop SKIPS it.
///
/// Live membership is the whole predicate. There is no durable row to consult
/// and nothing to scrub out of the CRDT afterwards, because an overlay row
/// never entered base and therefore never entered a window in the first place.
/// The pre-P6 scrub existed only to retract carriers a base-resident turn had
/// already published before it was sealed; a room's turns are never
/// base-resident, so there is nothing to retract.
///
/// A base write COMMISSIONED during a live session — an on-record write after
/// a mode flip, or a promoted turn — is not an overlay member and packs
/// normally. Edge targets are deliberately not re-tested: the K4 taint guard
/// refuses any base edge naming a live overlay member, so `edges_out` over
/// base rows cannot produce one.
pub(super) fn window_packing_excludes_entity(vault: &Vault, id: &EntityId) -> Result<bool> {
    vault.store.off_record_sessions.contains_entity(id)
}

/// Whether this window has ever carried bytes that must not ship in ordinary
/// Loro history.
/// The marker is durable because a scrubbed live doc still retains the old
/// set operation in its ordinary Loro history until shallow-compacted.
pub fn history_free_window_required(vault: &Vault, key: &WindowKey) -> Result<bool> {
    Ok(vault
        .sync_state_get(&format!("{HISTORY_FREE_WINDOW_PREFIX}{key}"))?
        .is_some())
}

/// Durably pins this window to history-free snapshot transport/persistence.
pub fn require_history_free_window(vault: &Vault, key: &WindowKey) -> Result<()> {
    vault.with_write_txn(|wtxn| {
        vault
            .store
            .sync_state
            .put(wtxn, &format!("{HISTORY_FREE_WINDOW_PREFIX}{key}"), &[1u8])?;
        Ok(())
    })
}

/// Removes any SECRET_CUSTODY carrier resident in the window doc and returns
/// whether one was found. ONE-1865 arm-pending seal: the type byte is sealed
/// from the CRDT plane, so a custody body must never ship in an exported
/// update. The write-side mirror (`reverse_rematerialize`) already refuses to
/// insert one; this is the export-side backstop for a carrier that landed
/// before the seal or arrived from a peer. Deleting the row does not erase its
/// prior set-op bytes from ordinary Loro history, so any removal forces the
/// window onto history-free snapshot transport.
///
/// The BODY decides, never the key. A peer chooses its own map keys, so parsing
/// the key first let a custody body filed under a non-canonical key skip the
/// scrub entirely and ship in the export — the key is attacker-controlled, the
/// type byte is not. A malformed key cannot name an entity to scrub by id, so
/// that row is deleted by its raw key and quarantined as the protocol violation
/// it is.
fn scrub_secret_custody_carriers(vault: &Vault, key: &WindowKey, doc: &LoroDoc) -> Result<bool> {
    let entities_map = doc.get_map("entities");
    let edges_map = doc.get_map("edges");
    let mut custody_ids = HashSet::new();
    let mut malformed_key_carriers: Vec<String> = Vec::new();
    map_for_each_value_bytes(&entities_map, |raw_key, maybe_blob| {
        let Some(blob) = maybe_blob else { return };
        if !is_secret_custody_record(blob) {
            return;
        }
        match EntityId::from_hex(raw_key) {
            Ok(id) => {
                custody_ids.insert(id);
            }
            Err(_) => malformed_key_carriers.push(raw_key.to_owned()),
        }
    });
    let mut removed = false;
    for raw_key in &malformed_key_carriers {
        // Quarantine keeps hashed evidence (never the bytes); the delete is
        // what stops the body from reaching an exported update.
        quarantine::quarantine_rejected_op(
            vault,
            key.as_str(),
            QuarantineContainer::Entities,
            raw_key,
            &crate::secret_custody::reject_secret_custody_byte(),
            &map_get_bytes(&entities_map, raw_key).unwrap_or_default(),
        )?;
        map_delete(&entities_map, raw_key)?;
        removed = true;
    }
    for id in &custody_ids {
        removed |= remove_entity_crdt_carriers(&entities_map, &edges_map, id)?;
    }
    if removed {
        doc.commit_with(CommitOptions::new().origin(BRIDGE_ORIGIN));
        require_history_free_window(vault, key)?;
    }
    Ok(removed)
}

/// Exports a full-window response without carrying pre-scrub operation bytes.
/// The peer VV is still decoded first so malformed-VV requests never become a
/// full-export fallback.
pub fn export_window_updates_since(
    vault: &Vault,
    key: &WindowKey,
    doc: &LoroDoc,
    remote_vv: &[u8],
) -> Result<Vec<u8>> {
    VersionVector::decode(remote_vv).map_err(|source| Error::CrdtDecodeError {
        context: "decode version vector",
        source,
    })?;
    let scrubbed = scrub_secret_custody_carriers(vault, key, doc)?;
    if scrubbed || history_free_window_required(vault, key)? || doc.is_shallow() {
        export_history_free_window_snapshot(doc)
    } else {
        super::loro_support::export_updates_since(doc, remote_vv)
    }
}

pub(crate) fn export_history_free_window_snapshot(doc: &LoroDoc) -> Result<Vec<u8>> {
    doc.commit();
    let frontiers = doc.oplog_frontiers();
    doc.export(ExportMode::shallow_snapshot(&frontiers))
        .map_err(|e| {
            Error::sync_engine(
                crate::error::SyncEngineContext::LoroExportShallowSnapshot,
                e,
            )
        })
}

/// Scrubs the live state and chooses ordinary versus shallow snapshot bytes
/// using the durable per-window history-free pin.
pub(in crate::sync) fn export_scrubbed_window_snapshot(
    vault: &Vault,
    key: &WindowKey,
    doc: &LoroDoc,
) -> Result<Vec<u8>> {
    if history_free_window_required(vault, key)? || doc.is_shallow() {
        export_history_free_window_snapshot(doc)
    } else {
        export_snapshot(doc)
    }
}

/// Replays pending-mirror markers (pm:*) for crash recovery.
///
/// A live session-overlay member stays pending: the marker is intentionally
/// not cleared while the room holds the id, so a P5 promote releases the turn
/// to sync through this same ordinary path later.
pub fn replay_pending_mirrors(vault: &Vault, doc: &LoroDoc, window_key: &WindowKey) -> Result<u32> {
    let rtxn = vault.store.env.read_txn()?;
    let prefix = format!("pm:{window_key}:");

    let mut markers: Vec<(String, EntityId)> = Vec::new();

    let iter = vault.store.sync_state.prefix_iter(&rtxn, &prefix)?;
    for entry in iter {
        let (k, _) = entry?;
        let hex = &k[prefix.len()..];
        let parsed_id = EntityId::from_hex(hex);
        if let Ok(id) = parsed_id {
            markers.push((k.to_string(), id));
        }
    }
    drop(rtxn);

    let entities_map = doc.get_map("entities");
    let tombstones_map = doc.get_map("tombstones");
    let edges_map = doc.get_map("edges");

    let mut replayed = 0u32;

    for (marker_key, id) in &markers {
        let hex_id = id.to_hex();

        // Read entity from LMDB
        let raw = match vault.get_raw_unsealed(id)? {
            Some(r) => r,
            None => {
                // Stale marker — clear it
                vault.with_write_txn(|wtxn| {
                    vault.store.sync_state.delete(wtxn, marker_key)?;
                    Ok(())
                })?;
                continue;
            }
        };

        // Defer-sync egress door: a live overlay member is device-local until
        // explicit promotion. Keep the pending marker so the promoted turn can
        // flow through this ordinary path later.
        if window_packing_excludes_entity(vault, id)? {
            continue;
        }

        if skip_companion_register_sync_mirror(&raw)? {
            let mut wrote_doc = false;
            if map_contains_binary(&entities_map, &hex_id) {
                map_delete(&entities_map, &hex_id)?;
                wrote_doc = true;
            }
            if delete_edges_touching_entities(&edges_map, &HashSet::from([*id]))? {
                wrote_doc = true;
            }
            if wrote_doc {
                doc.commit_with(CommitOptions::new().origin(BRIDGE_ORIGIN));
            }
            vault.with_write_txn(|wtxn| {
                vault.store.sync_state.delete(wtxn, marker_key)?;
                Ok(())
            })?;
            continue;
        }

        // Type-classify the local carrier BEFORE granting the CRDT
        // tombstone delete authority. Engine-authored protected rows keep
        // their carrier and quarantine the hostile tombstone; ordinary rows
        // retain the value-agnostic, entity-canonical delete-wins gate.
        let protected_tombstone =
            quarantine_outbound_protected_tombstones(vault, window_key, &tombstones_map, id, &raw)?;
        if !protected_tombstone && tombstone_map_contains_id(&tombstones_map, id) {
            vault.with_write_txn(|wtxn| {
                vault.store.sync_state.delete(wtxn, marker_key)?;
                Ok(())
            })?;
            continue;
        }

        // Byte-compare with existing CRDT value
        if let Some(existing) = map_get_bytes(&entities_map, &hex_id)
            && existing.as_slice() == raw.as_slice()
        {
            // The entity bytes already reached the CRDT, but the marker may
            // cover a crash between the entity insert and its edge inserts
            // (ARCH-0023b step 3 mirrors entity + edges as one unit). Replay
            // any missing `edges_out` entries BEFORE clearing the marker —
            // clearing early would silently drop the un-mirrored edges.
            let mut wrote_edges = false;
            let edges_out = vault.edges_out(id)?;
            for edge in &edges_out {
                // readiness edges are local-only in v1 (ONE-1608 / ARCH-0050
                // R6 L2), exactly as `reverse_rematerialize` below. This
                // marker replay is the OTHER send-side egress: a crash between
                // the entity insert and its edge inserts, or a deferred
                // overlay promotion, would otherwise copy a locally inserted
                // `blocks` row into the replicated edges map. Inbound
                // quarantine and admission aborts stay untouched.
                if edge.kind == EdgeKind::Blocks {
                    continue;
                }
                let edge_key = format_edge_key(id, edge.kind, &edge.target);
                // Never backfill an edge whose TARGET is tombstoned —
                // matching forward remat's both-endpoint filter. A surviving
                // local S→E row (crash between the tombstone CRDT commit and
                // the purge txn, or a failed purge) must not be re-inserted
                // into the replicated edges map (ARCH-0038 active-carrier
                // purge). Plain containment = skip on this branch (legacy
                // values are hard); becomes reason-aware (skip iff the
                // tombstone decodes HARD) once tombstone v2 lands in M4-06.
                if tombstone_map_contains_id(&tombstones_map, &edge.target) {
                    continue;
                }
                if map_contains_binary(&edges_map, &edge_key) {
                    continue;
                }
                let edge_val = encode_edge_value_for_crdt(
                    edge.kind,
                    edge.weight,
                    edge.created_at,
                    edge.vad,
                    edge.provenance,
                )?;
                map_insert_bytes(&edges_map, edge_key.as_str(), &edge_val)?;
                wrote_edges = true;
            }
            if wrote_edges {
                doc.commit_with(CommitOptions::new().origin(BRIDGE_ORIGIN));
                replayed += 1;
            }

            vault.with_write_txn(|wtxn| {
                vault.store.sync_state.delete(wtxn, marker_key)?;
                Ok(())
            })?;
            continue;
        }

        // Mirror to CRDT under bridge origin. Finalized REDACTION_AUDIT
        // receipts are LMDB-local accountability rows; undecodable bytes
        // fail closed using the same gate as reverse remat.
        if reverse_remat_skip_redaction_receipt_mirror(&raw) {
            vault.with_write_txn(|wtxn| {
                vault.store.sync_state.delete(wtxn, marker_key)?;
                Ok(())
            })?;
            continue;
        }
        map_insert_bytes(&entities_map, hex_id.as_str(), raw.as_slice())?;

        let edges_out = vault.edges_out(id)?;
        for edge in &edges_out {
            // Same local-only readiness-edge gate as the byte-equal path
            // above: the full mirror is send-side egress too.
            if edge.kind == EdgeKind::Blocks {
                continue;
            }
            let edge_key = format_edge_key(id, edge.kind, &edge.target);
            // Same tombstoned-target gate as the byte-equal path above:
            // the full mirror must not re-insert edges to deleted targets.
            if tombstone_map_contains_id(&tombstones_map, &edge.target) {
                continue;
            }
            let edge_val = encode_edge_value_for_crdt(
                edge.kind,
                edge.weight,
                edge.created_at,
                edge.vad,
                edge.provenance,
            )?;
            map_insert_bytes(&edges_map, edge_key.as_str(), &edge_val)?;
        }

        doc.commit_with(CommitOptions::new().origin(BRIDGE_ORIGIN));

        // Clear the marker
        vault.with_write_txn(|wtxn| {
            vault.store.sync_state.delete(wtxn, marker_key)?;
            Ok(())
        })?;

        replayed += 1;
    }

    Ok(replayed)
}

/// Forward re-materialization: CRDT→LMDB.
///
/// ARCH-0023b crash-recovery step 5: iterate the `entities`, `edges` and
/// `tombstones` maps, byte-compare against LMDB and write any that differ.
/// Step 3's deletion rule binds here too — "if tombstoned in CRDT → never
/// resurrect": a tombstoned entity's bytes are never written to LMDB (not
/// even transiently), and no edge with a tombstoned endpoint is re-added.
///
/// ONE-1124 silent-skip hygiene: every REMOTE-origin op rejected by a write
/// gate persists a quarantine record (`x:` family) — never a bare skip;
/// the engine's own LMDB read errors propagate as typed errors (fail
/// closed, never quarantine-and-continue); and a tombstone-purge failure
/// flags `rm:w:{window}:{entity_hex}` for durable retry (each marker
/// cleared only when that entity's own purge succeeds).
///
/// ONE-1147: Observer B's entity/edge batch swallow sites flag the same
/// entity-scoped markers on whole-txn failure. This pass discharges such a
/// marker ONLY when it performs the actual healing write for that entity
/// (entity body put, or an edge write whose SOURCE is the marked entity).
/// Byte-parity alone never discharges: a failed GDPR purge also leaves
/// byte-identical state, and a parity-clear would vacuously drop a pending
/// hard-delete retry (fail closed).
///
/// ONE-1157/1158: the entity/edge passes visit EVERY map key: non-Binary
/// values quarantine as protocol violations (ONE-1157, Observer-B parity),
/// and a non-canonical (case-shifted) entities-map alias key quarantines
/// instead of materializing (ONE-1158).
pub(super) fn push_terminal_quarantine_marker(
    terminal_quarantines: &mut Vec<EntityId>,
    container: QuarantineContainer,
    crdt_key: &str,
) {
    if let Some(id) = quarantine::remat_marker_entity_for_quarantine(container, crdt_key) {
        terminal_quarantines.push(id);
    }
}
