//! Window egress: packing policy, local-only scrub, exports, and mirror replay.

use std::collections::HashSet;

use super::bridge::{BRIDGE_ORIGIN, encode_edge_value_for_crdt, format_edge_key};
use super::loro_support::{
    TombstoneIndex, export_snapshot, map_contains_binary, map_delete, map_for_each_tombstone_value,
    map_for_each_value_bytes, map_get_bytes, map_insert_bytes,
};
use super::pack_sync;
use super::quarantine::{self, QuarantineContainer};
use super::reverse::{
    delete_edges_touching_entities, is_delegated_channel_identity_carrier,
    is_unsyncable_secret_custody, quarantine_outbound_protected_tombstones,
    remove_entity_crdt_carriers, reverse_remat_skip_redaction_receipt_mirror,
};
use super::types::WindowKey;
use crate::sync::window_rows::{HISTORY_FREE_WINDOW, OFF_RECORD_PROMOTE_PICKUP, WindowEntityKey};

use crate::Vault;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::sync::local_claims::{
    claim_sync_allowed, local_claim_sync_allowed, withheld_claim_carriers,
};
use loro::{CommitOptions, ExportMode, LoroDoc};

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
///
/// A world flagged device-only (`device_only`, read once per packing pass)
/// keeps its WORLD row, its claims and its NOTEs on this device too.
pub(super) fn window_packing_excludes_entity(
    vault: &Vault,
    device_only: &std::collections::BTreeSet<EntityId>,
    id: &EntityId,
) -> Result<bool> {
    let rtxn = vault.store.env.read_txn()?;
    if crate::origin::lfs::is_lfs_chunk_asset_in_txn(&vault.store, &rtxn, id)?
        || crate::settings::device_only_withholds(&vault.store, &rtxn, device_only, id)?
    {
        return Ok(true);
    }
    vault.store.off_record_sessions.contains_entity(id)
}

/// Whether this window has ever carried bytes that must not ship in ordinary
/// Loro history.
/// The marker is durable because a scrubbed live doc still retains the old
/// set operation in its ordinary Loro history until shallow-compacted.
pub fn history_free_window_required(vault: &Vault, key: &WindowKey) -> Result<bool> {
    let rtxn = vault.store.env.read_txn()?;
    HISTORY_FREE_WINDOW.contains(&vault.store, &rtxn, &key.as_str().to_owned())
}

/// Durably pins this window to history-free snapshot transport/persistence.
pub fn require_history_free_window(vault: &Vault, key: &WindowKey) -> Result<()> {
    vault.with_write_txn_grouped(|wtxn| {
        HISTORY_FREE_WINDOW.put(&vault.store, wtxn, &key.as_str().to_owned(), &[1u8])?;
        Ok(())
    })
}

/// Removes local-only diagnostic and secret-custody carriers from the window
/// doc. Diagnostic observations and secret custody never sync. Neither
/// refused body may ship in an update.
/// The write-side mirror (`reverse_rematerialize`) already refuses to
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
pub(super) fn scrub_local_only_carriers(
    vault: &Vault,
    key: &WindowKey,
    doc: &LoroDoc,
) -> Result<bool> {
    let entities_map = doc.get_map("entities");
    let edges_map = doc.get_map("edges");
    let mut custody_ids = HashSet::new();
    let mut malformed_key_carriers: Vec<String> = Vec::new();
    let mut pad_carriers: Vec<(String, Vec<u8>)> = Vec::new();
    map_for_each_value_bytes(&entities_map, |raw_key, maybe_blob| {
        let Some(blob) = maybe_blob else { return };
        if crate::world_keys::pad_body_world(blob).is_some() {
            pad_carriers.push((raw_key.to_owned(), blob.to_vec()));
            return;
        }
        let lfs_chunk = EntityId::from_hex(raw_key)
            .ok()
            .is_some_and(|id| crate::origin::lfs::is_lfs_chunk_blob(&id, blob));
        if crate::batch::EntityMetadataHeader::parse(blob).is_none_or(|h| {
            !matches!(
                h.entity_type,
                crate::registry::ENTITY_TYPE_SECRET_CUSTODY
                    | crate::registry::ENTITY_TYPE_DIAGNOSTIC
            ) && !is_delegated_channel_identity_carrier(blob)
        }) && !lfs_chunk
        {
            return;
        }
        match EntityId::from_hex(raw_key) {
            Ok(id) if id.to_hex() == raw_key => {
                custody_ids.insert(id);
            }
            _ => malformed_key_carriers.push(raw_key.to_owned()),
        }
    });
    // A destroyed world's pad that landed late leaves the window whatever its
    // key; a live world's pad keeps replicating with the base rows.
    if !pad_carriers.is_empty() {
        let txn = vault.store.env.read_txn()?;
        for (raw_key, blob) in pad_carriers {
            if !crate::world_keys::late_pad_in_txn(&vault.store, &txn, &blob)? {
                continue;
            }
            match EntityId::from_hex(&raw_key) {
                Ok(id) if id.to_hex() == raw_key => {
                    custody_ids.insert(id);
                }
                _ => malformed_key_carriers.push(raw_key),
            }
        }
    }
    // Pin before touching the live map. If storage fails, the carrier stays
    // visible to the next scrub instead of leaving unpinned private history.
    if !custody_ids.is_empty() || !malformed_key_carriers.is_empty() {
        require_history_free_window(vault, key)?;
    }
    let mut removed = false;
    for raw_key in &malformed_key_carriers {
        // Quarantine keeps hashed evidence (never the bytes); the delete is
        // what stops the body from reaching an exported update.
        let blob = map_get_bytes(&entities_map, raw_key).unwrap_or_default();
        let rejection = if is_delegated_channel_identity_carrier(&blob) {
            Error::Record(crate::error::RecordError::InvalidChannelIdentityBody(
                "delegated ChannelIdentity rows are local custody facts and cannot be replicated",
            ))
        } else if crate::batch::EntityMetadataHeader::parse(&blob)
            .is_some_and(|header| header.entity_type == crate::registry::ENTITY_TYPE_DIAGNOSTIC)
        {
            Error::InvalidKey
        } else if crate::world_keys::pad_body_world(&blob).is_some() {
            Error::InvalidConfig("a destroyed world's key pad cannot rejoin a window".into())
        } else {
            crate::secret_custody::reject_secret_custody_byte()
        };
        quarantine::quarantine_rejected_op(
            vault,
            key.as_str(),
            QuarantineContainer::Entities,
            raw_key,
            &rejection,
            &blob,
        )?;
        map_delete(&entities_map, raw_key)?;
        removed = true;
    }
    for id in &custody_ids {
        removed |= remove_entity_crdt_carriers(&entities_map, &edges_map, id)?;
    }
    if removed {
        crate::sync::row_birth::drop_orphan_births(doc)?;
        doc.commit_with(CommitOptions::new().origin(BRIDGE_ORIGIN));
    }
    Ok(removed)
}

/// Scrubs local-only claims without retaining their old set operations in
/// any subsequent exported snapshot or delta.
pub(super) fn scrub_local_claim_carriers(
    vault: &Vault,
    key: &WindowKey,
    doc: &LoroDoc,
) -> Result<bool> {
    let entities = doc.get_map("entities");
    let edges = doc.get_map("edges");
    let rtxn = vault.store.env.read_txn()?;
    let (mut keys, mut ids) = withheld_claim_carriers(vault, &rtxn, &entities, &edges)?;
    // The stored row decides here, not the carrier: a peer's carrier of
    // another type at the id of a CLAIM deleted here goes with the CLAIM's
    // shell (or under it, for a retained shell). Each such carrier at an id
    // deleted here marks first, as every local removal does.
    let mut deleted_carriers = Vec::new();
    let mut failure = None;
    map_for_each_value_bytes(&entities, |raw_key, blob| {
        let (Ok(id), Some(carrier)) = (EntityId::from_hex(raw_key), blob) else {
            return;
        };
        if failure.is_some() || !ids.contains(&id) {
            return;
        }
        let deleted =
            crate::ports::EntityStoreRead::port_entity_with_raw(&vault.store, &rtxn, &id, |raw| {
                crate::deletion::row_deletion_marked(&vault.store, &rtxn, &id, Some(raw))
            })
            .and_then(|verdict| match verdict {
                Some(marked) => Ok(marked),
                None => crate::deletion::row_deletion_marked(&vault.store, &rtxn, &id, None),
            });
        match deleted {
            Ok(true) => deleted_carriers.push((id, carrier.to_vec())),
            Ok(false) => {}
            Err(error) => failure = Some(error),
        }
    });
    if let Some(error) = failure {
        return Err(error);
    }
    // An exact UserDelete shell with a matching local deletion address is a
    // portable active carrier, not a malformed claim. Its world witness is
    // emitted beside it so a fresh replica can prove residence without an
    // erased body. A different-world or unproven shell remains withheld.
    let mut retained = Vec::new();
    if key.world().is_some() {
        let tombstones = TombstoneIndex::build(&doc.get_map("tombstones"));
        for id in &ids {
            if crate::ports::EntityStoreRead::port_entity_with_raw(
                &vault.store,
                &rtxn,
                id,
                |raw| {
                    crate::sync::types::retained_world_shell_belongs_to_window(
                        vault,
                        &rtxn,
                        doc,
                        &tombstones,
                        id,
                        raw,
                        key,
                        false,
                    )
                },
            )?
            .unwrap_or(false)
            {
                retained.push(*id);
            }
        }
    }
    drop(rtxn);
    super::tombstones::mark_removed_carriers_first(
        vault,
        super::tombstones::CarrierRemoval::LocalClaimScrub,
        &deleted_carriers,
    )?;
    for id in &retained {
        ids.remove(id);
        keys.retain(|raw_key| EntityId::from_hex(raw_key).ok().as_ref() != Some(id));
    }
    if !retained.is_empty() {
        let witnesses = doc.get_map("retained_claim_worlds");
        let world = key.world().expect("retained witness needs a world");
        let mut changed = false;
        for id in retained {
            // Local UserDelete removes the live CRDT entity carrier while
            // retaining its 25-byte LMDB shell. Recreate that exact shell
            // beside its validated witness; without it the next peer gets an
            // orphan witness and cannot recover the retained graph.
            if let Some(raw) = vault.get_raw_unsealed(&id)?
                && map_get_bytes(&entities, &id.to_hex()).as_deref() != Some(raw.as_slice())
            {
                map_insert_bytes(&entities, &id.to_hex(), &raw)?;
                changed = true;
            }
            if map_get_bytes(&witnesses, &id.to_hex()).as_deref()
                != Some(world.as_bytes().as_slice())
            {
                map_insert_bytes(&witnesses, &id.to_hex(), world.as_bytes())?;
                changed = true;
            }
        }
        if changed {
            doc.commit_with(CommitOptions::new().origin(BRIDGE_ORIGIN));
        }
    }
    if keys.is_empty() && ids.is_empty() {
        return Ok(false);
    }
    // Pin before deleting anything: if persistence fails, a retry must not
    // mistake an already-scrubbed live map for history that is safe to export.
    require_history_free_window(vault, key)?;
    map_for_each_value_bytes(&entities, |raw_key, _| {
        if EntityId::from_hex(raw_key).is_ok_and(|id| ids.contains(&id)) {
            keys.push(raw_key.to_owned());
        }
    });
    keys.sort_unstable();
    keys.dedup();
    let mut removed = !keys.is_empty();
    for raw_key in keys {
        map_delete(&entities, &raw_key)?;
    }
    removed |= delete_edges_touching_entities(&edges, &ids)?;
    if removed {
        crate::sync::row_birth::drop_orphan_births(doc)?;
        doc.commit_with(CommitOptions::new().origin(BRIDGE_ORIGIN));
    }
    Ok(removed)
}

/// The entity carriers of `doc` (map key and id) whose rows this vault's own
/// markers hold deleted while the window's tombstone map no longer names
/// them: a delete a peer withdrew, putting the body back. This vault refused
/// the restore, so it must not hand the carrier on either; a receiver that
/// never saw the delete would make the row live.
pub(in crate::sync) fn withdrawn_delete_carriers(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    doc: &LoroDoc,
) -> Result<Vec<(String, EntityId)>> {
    let mut deleted = Vec::new();
    let mut failure = None;
    map_for_each_value_bytes(&doc.get_map("entities"), |raw_key, _| {
        let Ok(id) = EntityId::from_hex(raw_key) else {
            return;
        };
        if failure.is_some() {
            return;
        }
        let marked =
            crate::ports::EntityStoreRead::port_entity_with_raw(&vault.store, rtxn, &id, |raw| {
                crate::deletion::row_deletion_marked(&vault.store, rtxn, &id, Some(raw))
            })
            .and_then(|verdict| match verdict {
                Some(marked) => Ok(marked),
                None => crate::deletion::row_deletion_marked(&vault.store, rtxn, &id, None),
            });
        match marked {
            Ok(true) => deleted.push((raw_key.to_owned(), id)),
            Ok(false) => {}
            Err(error) => failure = Some(error),
        }
    });
    if let Some(error) = failure {
        return Err(error);
    }
    if deleted.is_empty() {
        return Ok(deleted);
    }
    let mut tombstoned = HashSet::new();
    map_for_each_tombstone_value(&doc.get_map("tombstones"), |raw_key, _| {
        if let Ok(id) = EntityId::from_hex(raw_key) {
            tombstoned.insert(id);
        }
    });
    deleted.retain(|(_, id)| !tombstoned.contains(id));
    Ok(deleted)
}

/// Scrubs every [`withdrawn_delete_carriers`] entry from the live document.
/// The window is pinned history-free first, so neither the body nor the
/// withdrawal's operations ship. Returns whether it pinned.
///
/// A carrier only a blob-artifact release fences (H125) is dropped with an
/// ordinary delete and does not pin: nobody withdrew a delete there, the bytes
/// went because no live artifact holds them. Their old set operation stays in
/// Loro history until the sweep's shallow compaction, as for any deleted row.
/// A pin would answer every later version request with a snapshot rooted at
/// this vault's newest operation, which a peer even one change behind cannot
/// apply.
pub(super) fn scrub_withdrawn_delete_carriers(
    vault: &Vault,
    key: &WindowKey,
    doc: &LoroDoc,
) -> Result<bool> {
    let (withdrawn, pin) = {
        let rtxn = vault.store.env.read_txn()?;
        let withdrawn = withdrawn_delete_carriers(vault, &rtxn, doc)?;
        let mut pin = false;
        for (_, id) in &withdrawn {
            if !crate::blob_artifact::release_fenced_only(&vault.store, &rtxn, id)? {
                pin = true;
                break;
            }
        }
        (withdrawn, pin)
    };
    if withdrawn.is_empty() {
        return Ok(false);
    }
    if pin {
        require_history_free_window(vault, key)?;
    }
    let entities = doc.get_map("entities");
    let carriers: Vec<_> = withdrawn
        .iter()
        .filter_map(|(raw_key, id)| map_get_bytes(&entities, raw_key).map(|carrier| (*id, carrier)))
        .collect();
    super::tombstones::mark_removed_carriers_first(
        vault,
        super::tombstones::CarrierRemoval::WithdrawnDeleteScrub,
        &carriers,
    )?;
    for (raw_key, _) in &withdrawn {
        map_delete(&entities, raw_key)?;
    }
    crate::sync::row_birth::drop_orphan_births(doc)?;
    doc.commit_with(CommitOptions::new().origin(BRIDGE_ORIGIN));
    Ok(pin)
}

/// Remove attribution carriers defeated by permanent author-redaction facts.
/// Check both local LMDB and the document: a redaction newly received in this
/// window may not yet have been materialized, while its earlier attribution
/// is already in Loro history. Even an empty live map needs the history-free
/// pin once a redaction exists, because a prior delete does not erase Loro ops.
pub(super) fn scrub_redacted_attribution_carriers(
    vault: &Vault,
    key: &WindowKey,
    doc: &LoroDoc,
) -> Result<bool> {
    let entities = doc.get_map("entities");
    let mut redacted = {
        let rtxn = vault.store.env.read_txn()?;
        crate::identity_topology::redacted_keys_in_txn(&vault.store, &rtxn)?
    };
    map_for_each_value_bytes(&entities, |_, blob| {
        if let Some(key) = blob.and_then(crate::identity_topology::redaction_carrier_key) {
            redacted.insert(key);
        }
    });
    if redacted.is_empty() {
        return Ok(false);
    }
    // Pin BEFORE deletion. A failed durable pin cannot leave a scrubbed doc
    // eligible for an ordinary delta carrying old personal bytes.
    require_history_free_window(vault, key)?;
    let mut keys = Vec::new();
    map_for_each_value_bytes(&entities, |map_key, blob| {
        if blob
            .and_then(crate::identity_topology::attribution_carrier_key)
            .is_some_and(|key| redacted.contains(&key))
        {
            keys.push(map_key.to_owned());
        }
    });
    for map_key in &keys {
        map_delete(&entities, map_key)?;
    }
    if !keys.is_empty() {
        crate::sync::row_birth::drop_orphan_births(doc)?;
        doc.commit_with(CommitOptions::new().origin(BRIDGE_ORIGIN));
    }
    Ok(!keys.is_empty())
}

/// The window's state with no history at all: a snapshot rooted at its newest operation, for local
/// persistence only. Nothing exports it: every snapshot a peer or a promotion receives is cut and
/// checked by [`super::history_free`].
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

/// Scrubs the live state and persists it: a pinned window keeps only the history
/// [`super::history_free::HistoryCheck`] ships where a root allows it, every other window all
/// it holds.
pub(in crate::sync) fn export_scrubbed_window_snapshot(
    vault: &Vault,
    key: &WindowKey,
    doc: &LoroDoc,
) -> Result<Vec<u8>> {
    crate::sync::note::refresh(vault, doc, key)?;
    scrub_local_claim_carriers(vault, key, doc)?;
    scrub_local_only_carriers(vault, key, doc)?;
    scrub_redacted_attribution_carriers(vault, key, doc)?;
    scrub_withdrawn_delete_carriers(vault, key, doc)?;
    super::withdrawn::scrub_withdrawn_generation_carriers(vault, key, doc)?;
    // FIX 1794: an erased room's or thread's side rows leave the window.
    crate::sync::room_facts::scrub_room_facts(vault, doc)?;
    // A persisted or returned snapshot carries the same project history as
    // a delta does (Astra #1434 r9 F5).
    if super::project_history::carry_project_history(vault, doc)? {
        doc.commit_with(CommitOptions::new().origin(BRIDGE_ORIGIN));
    }
    if history_free_window_required(vault, key)? {
        let check = super::history_free::HistoryCheck::read(vault, key, doc)?;
        super::history_free::persisted_history_free_snapshot(doc, &check)
    } else {
        // A shallow doc's snapshot keeps its own root.
        export_snapshot(doc)
    }
}

/// Replays pending-mirror markers (pm:*) for crash recovery.
///
/// A live session-overlay member stays pending: the marker is intentionally
/// not cleared while the room holds the id, so a P5 promote releases the turn
/// to sync through this same ordinary path later.
pub fn replay_pending_mirrors(vault: &Vault, doc: &LoroDoc, window_key: &WindowKey) -> Result<u32> {
    replay_mirrors(vault, doc, window_key, &mut Markers::ClearNow)
}

/// [`replay_pending_mirrors`] into a detached copy of the window: the markers it would clear are
/// returned instead, for the transaction that persists the copy's outcome to clear. Work refused
/// before that transaction leaves every marker for the next open.
pub(super) fn replay_pending_mirrors_kept(
    vault: &Vault,
    doc: &LoroDoc,
    window_key: &WindowKey,
) -> Result<Vec<WindowEntityKey>> {
    let mut done = Vec::new();
    replay_mirrors(vault, doc, window_key, &mut Markers::Collect(&mut done))?;
    Ok(done)
}

/// What a replay does with a marker whose mirror it settled.
enum Markers<'a> {
    ClearNow,
    Collect(&'a mut Vec<WindowEntityKey>),
}

impl Markers<'_> {
    fn settle(&mut self, vault: &Vault, marker: &WindowEntityKey) -> Result<()> {
        match self {
            Self::ClearNow => vault.with_write_txn_grouped(|wtxn| {
                OFF_RECORD_PROMOTE_PICKUP.delete(&vault.store, wtxn, marker)?;
                Ok(())
            }),
            Self::Collect(done) => {
                done.push(marker.clone());
                Ok(())
            }
        }
    }
}

fn replay_mirrors(
    vault: &Vault,
    doc: &LoroDoc,
    window_key: &WindowKey,
    settled: &mut Markers<'_>,
) -> Result<u32> {
    let rtxn = vault.store.env.read_txn()?;

    // A key that does not decode to a hex entity id is silently skipped here
    // (not a fail-closed refusal): best-effort crash-recovery replay, not a
    // fail-closed read of engine-authored truth.
    let markers: Vec<(WindowEntityKey, EntityId)> = OFF_RECORD_PROMOTE_PICKUP
        .iter_from(&vault.store, &rtxn, format!("{window_key}:").as_bytes())?
        .filter_map(Result::ok)
        .map(|(key, _)| {
            let entity = key.entity;
            (key, entity)
        })
        .collect();
    drop(rtxn);

    scrub_local_claim_carriers(vault, window_key, doc)?;
    scrub_redacted_attribution_carriers(vault, window_key, doc)?;
    let redacted_authors = {
        let rtxn = vault.store.env.read_txn()?;
        crate::identity_topology::redacted_keys_in_txn(&vault.store, &rtxn)?
    };
    let entities_map = doc.get_map("entities");
    let tombstones = TombstoneIndex::build(&doc.get_map("tombstones"));
    let edges_map = doc.get_map("edges");
    let device_only = super::device_only::canonical_withheld_worlds(vault, window_key)?;

    let mut replayed = 0u32;

    for (marker_key, id) in &markers {
        let hex_id = id.to_hex();

        // Read entity from LMDB
        let raw = match vault.get_raw_unsealed(id)? {
            Some(r) => r,
            None => {
                // Stale marker — clear it
                settled.settle(vault, marker_key)?;
                continue;
            }
        };

        if !super::types::entity_belongs_to_window(&raw, window_key) {
            return Err(crate::Error::InvalidConfig(
                "pending mirror outside window residence".into(),
            ));
        }

        // Defer-sync egress door: a live overlay member is device-local until
        // explicit promotion. Keep the pending marker so the promoted turn can
        // flow through this ordinary path later.
        if window_packing_excludes_entity(vault, &device_only, id)? {
            continue;
        }

        if !claim_sync_allowed(&raw)
            || is_unsyncable_secret_custody(&raw)
            || is_delegated_channel_identity_carrier(&raw)
        {
            let wrote_doc = remove_entity_crdt_carriers(&entities_map, &edges_map, id)?;
            if wrote_doc {
                require_history_free_window(vault, window_key)?;
                doc.commit_with(CommitOptions::new().origin(BRIDGE_ORIGIN));
            }
            settled.settle(vault, marker_key)?;
            continue;
        }

        if crate::identity_topology::attribution_carrier_key(&raw)
            .is_some_and(|key| redacted_authors.contains(&key))
        {
            settled.settle(vault, marker_key)?;
            continue;
        }

        // Type-classify the local carrier BEFORE granting the CRDT
        // tombstone delete authority. Engine-authored protected rows keep
        // their carrier and quarantine the hostile tombstone; ordinary rows
        // retain the value-agnostic, entity-canonical delete-wins gate.
        let protected_tombstone =
            quarantine_outbound_protected_tombstones(vault, window_key, &tombstones, id, &raw)?;
        if !protected_tombstone && tombstones.contains(id) {
            settled.settle(vault, marker_key)?;
            continue;
        }

        // Canonical outbound bytes for pack rows (origin handle/generation);
        // non-pack rows mirror byte-exactly. A corrupt local pack row fails
        // closed here, never quarantined as remote.
        let outbound = pack_sync::canonical_outbound_blob(&raw)?.unwrap_or_else(|| raw.clone());
        // Byte-compare with existing CRDT value. Pack carriers compare
        // canonical-to-canonical, with a canonical/local echo fallback so a
        // stale pre-canonical carrier does not rewrite every boot.
        if let Some(existing) = map_get_bytes(&entities_map, &hex_id)
            && (existing.as_slice() == outbound.as_slice()
                || pack_sync::pack_echo_equal(&raw, &existing))
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
                if !super::types::edge_belongs_to_window(vault, id, &edge.target, window_key)?
                    || !local_claim_sync_allowed(vault, &edge.target)?
                    || tombstones.contains(&edge.target)
                    || window_packing_excludes_entity(vault, &device_only, &edge.target)?
                {
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
            // The same crash window can fall between the entity and its
            // Rule A birth.
            if crate::sync::row_birth::mirror_local_birth(vault, doc, id)? {
                wrote_edges = true;
            }
            if wrote_edges {
                doc.commit_with(CommitOptions::new().origin(BRIDGE_ORIGIN));
                replayed += 1;
            }

            settled.settle(vault, marker_key)?;
            continue;
        }

        // Mirror to CRDT under bridge origin. Finalized REDACTION_AUDIT
        // receipts are LMDB-local accountability rows; undecodable bytes
        // fail closed using the same gate as reverse remat.
        if reverse_remat_skip_redaction_receipt_mirror(&raw) {
            settled.settle(vault, marker_key)?;
            continue;
        }
        map_insert_bytes(&entities_map, hex_id.as_str(), outbound.as_slice())?;

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
            if !super::types::edge_belongs_to_window(vault, id, &edge.target, window_key)?
                || !local_claim_sync_allowed(vault, &edge.target)?
                || tombstones.contains(&edge.target)
                || window_packing_excludes_entity(vault, &device_only, &edge.target)?
            {
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
        // Rule A: the birth rides in the same bridge commit as its row.
        crate::sync::row_birth::mirror_local_birth(vault, doc, id)?;

        doc.commit_with(CommitOptions::new().origin(BRIDGE_ORIGIN));

        // Clear the marker
        settled.settle(vault, marker_key)?;

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
