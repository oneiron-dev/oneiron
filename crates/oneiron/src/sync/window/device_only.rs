//! Export-time withholding for worlds flagged device-only.
//!
//! Rows in a device-local world never leave the device that holds the flag
//! (DEC-0005). Packing skips them, but a row packed while its world was
//! still portable stays resident in the stored window. Every claim of a world,
//! and every edge naming one, lives in that world's own windows
//! (`edge_worlds_match`), so an export door reads the flag when it runs and
//! ships nothing from a flagged world's window. The stored window is never
//! rewritten: clearing the flag ships it again on the next export.
//!
//! Cutting rows out of an export instead would need removal operations, and a
//! receiver materializes a bare edge removal as the deletion of its own stored
//! edge; that removal would also flow back here. For the same reason another
//! window that carries a row the flag keeps (the WORLD row, a NOTE in the
//! world, a claim or an edge naming any of them) is withheld whole too. Loro
//! history keeps a carrier a later write removed, so a delta or raw update
//! whose operations insert one is withheld as well. An export to a receiver
//! that holds nothing of the window falls back to its history-free snapshot;
//! one that holds part of it gets nothing.

use std::collections::{BTreeSet, HashSet};
use std::sync::Arc;

use heed::RoTxn;
use loro::json::{JsonOpContent, JsonSchema, MapOp};
use loro::{ContainerID, ContainerType, LoroDoc, LoroMap, LoroValue, VersionVector};

use super::super::bridge::parse_edge_key;
use super::super::loro_support::{export_updates_from, json_covers_blob, map_for_each_value_bytes};
use super::super::manager::WindowManager;
use super::super::types::WindowKey;
use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::entity_id::EntityId;
use crate::error::Result;

/// Whether `key` is a window of a world flagged device-only on this device,
/// read against the flag as it stands now.
pub(in crate::sync) fn window_is_device_only(vault: &Vault, key: &WindowKey) -> Result<bool> {
    let Some(world) = key.world() else {
        return Ok(false);
    };
    let rtxn = vault.store.env.read_txn()?;
    Ok(crate::settings::device_only_worlds_in(&vault.store, &rtxn)?.contains(&world))
}

/// Whether a full-window send of `doc` ships nothing now: the window belongs
/// to a flagged world, or it carries a row a flagged world keeps or an edge
/// naming one.
pub(in crate::sync) fn window_withheld(
    vault: &Vault,
    key: &WindowKey,
    doc: &LoroDoc,
) -> Result<bool> {
    carries_device_only(vault, &flagged_worlds(vault)?.1, key, doc)
}

/// What a raw send of window bytes may do, against the flag as it stands now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UpdateVerdict {
    /// No world is flagged, or the bytes carry no device-only row.
    Portable,
    /// A device-only world keeps the bytes here: its window, a carrier the
    /// window holds now, or one the bytes' own operations insert.
    Withheld,
    /// The bytes could not be read in full. They are never sent, and a queue
    /// row holding them is never cleared unsent.
    Uninspectable,
}

/// Inspections a raw verdict makes before it gives up on a flag set that
/// keeps moving under it.
const FLAG_PASSES: usize = 3;

/// The verdict on raw `update` bytes of window `window_key`, made at the
/// door that sends them. The bytes are read themselves: whole when they
/// stand alone (a snapshot, a selector's synthetic update), otherwise as the
/// operation range the live window must hold in full.
///
/// Opening and reading the window takes time, and a flag may be committed
/// meanwhile. Bytes are portable only if the flag generation read after the
/// inspection is the one the inspection ran against; otherwise they are
/// inspected again under the new flag set. That read and the acceptance hold
/// the vault's device-only flag lock, which a flag commit takes too, so a flag
/// committed before the verdict accepts is always seen. No read transaction
/// is held across the inspection or the send.
pub fn raw_update_verdict(
    manager: &Arc<WindowManager>,
    window_key: &str,
    update: &[u8],
) -> UpdateVerdict {
    let verdict = (|| -> Result<UpdateVerdict> {
        let vault = manager.vault();
        let accepting = vault.device_only_acceptance();
        let (mut generation, mut flagged) = flagged_worlds(vault)?;
        if flagged.is_empty() {
            return Ok(UpdateVerdict::Portable);
        }
        drop(accepting);
        for _ in 0..FLAG_PASSES {
            let verdict = inspect_raw_update(manager, &flagged, window_key, update)?;
            if verdict != UpdateVerdict::Portable {
                return Ok(verdict);
            }
            let accepting = vault.device_only_acceptance();
            let (now, now_flagged) = flagged_worlds(vault)?;
            if now == generation || now_flagged.is_empty() {
                return Ok(UpdateVerdict::Portable);
            }
            drop(accepting);
            (generation, flagged) = (now, now_flagged);
        }
        Ok(UpdateVerdict::Uninspectable)
    })();
    verdict.unwrap_or_else(|error| {
        tracing::warn!(window_key, %error, "raw window update not inspectable");
        UpdateVerdict::Uninspectable
    })
}

fn inspect_raw_update(
    manager: &Arc<WindowManager>,
    flagged: &BTreeSet<EntityId>,
    window_key: &str,
    update: &[u8],
) -> Result<UpdateVerdict> {
    let Some(key) = WindowKey::try_new(window_key) else {
        return Ok(UpdateVerdict::Uninspectable);
    };
    if key.world().is_some_and(|world| flagged.contains(&world)) {
        return Ok(UpdateVerdict::Withheld);
    }
    let vault = manager.vault();
    #[cfg(any(test, feature = "test-hooks"))]
    super::test_hooks::run_device_only_flag_race(vault)?;
    let window = manager.open_window(&key)?;
    if carries_device_only(vault, flagged, &key, &window.doc)? {
        return Ok(UpdateVerdict::Withheld);
    }
    bytes_verdict(vault, flagged, &key, &window.doc, update)
}

fn bytes_verdict(
    vault: &Vault,
    flagged: &BTreeSet<EntityId>,
    key: &WindowKey,
    live: &LoroDoc,
    update: &[u8],
) -> Result<UpdateVerdict> {
    let Ok(meta) = LoroDoc::decode_import_blob_meta(update, true) else {
        return Ok(UpdateVerdict::Uninspectable);
    };
    let alone = LoroDoc::new();
    let withheld = if alone
        .import(update)
        .is_ok_and(|status| status.pending.is_none())
    {
        // Its state, then every operation it holds (a shallow snapshot's
        // state carries what its history no longer does).
        let history = alone.export_json_updates(&VersionVector::default(), &alone.oplog_vv());
        carries_device_only(vault, flagged, key, &alone)?
            || history_inserts_device_only(vault, flagged, &history)?
    } else {
        if meta.mode.is_snapshot() {
            return Ok(UpdateVerdict::Uninspectable);
        }
        let history = live.export_json_updates(&meta.partial_start_vv, &meta.partial_end_vv);
        if !json_covers_blob(&history, &meta) {
            return Ok(UpdateVerdict::Uninspectable);
        }
        history_inserts_device_only(vault, flagged, &history)?
    };
    Ok(if withheld {
        UpdateVerdict::Withheld
    } else {
        UpdateVerdict::Portable
    })
}

/// Whether an export of `doc` to a receiver at `remote` ships nothing now:
/// the window is withheld, or the delta past `remote` inserts a device-only
/// carrier and the receiver already holds part of the window. Loro installs
/// a history-free checkpoint only into an empty doc; a nonempty one would
/// keep the checkpoint's later operations pending.
pub fn export_withheld(
    vault: &Vault,
    key: &WindowKey,
    doc: &LoroDoc,
    remote: &VersionVector,
) -> Result<bool> {
    Ok(window_withheld(vault, key, doc)?
        || (!remote.is_empty() && delta_carries_device_only(vault, doc, remote)?))
}

/// Whether the delta of `doc` past `from` inserts a row a flagged world keeps
/// or an edge naming one, even one a later write removed. Such a delta must
/// not ship; the window's history-free snapshot carries only what it holds now.
pub(super) fn delta_carries_device_only(
    vault: &Vault,
    doc: &LoroDoc,
    from: &VersionVector,
) -> Result<bool> {
    let (_, flagged) = flagged_worlds(vault)?;
    if flagged.is_empty() {
        return Ok(false);
    }
    // The export commits a pending edit too, so read it into the range.
    doc.commit();
    history_inserts_device_only(
        vault,
        &flagged,
        &doc.export_json_updates(from, &doc.oplog_vv()),
    )
}

/// The flag generation and the flagged worlds, read in one transaction.
fn flagged_worlds(vault: &Vault) -> Result<(u64, BTreeSet<EntityId>)> {
    let rtxn = vault.store.env.read_txn()?;
    Ok((
        crate::settings::device_only_generation_in(&vault.store, &rtxn)?,
        crate::settings::device_only_worlds_in(&vault.store, &rtxn)?,
    ))
}

fn carries_device_only(
    vault: &Vault,
    flagged: &BTreeSet<EntityId>,
    key: &WindowKey,
    doc: &LoroDoc,
) -> Result<bool> {
    if flagged.is_empty() {
        return Ok(false);
    }
    if key.world().is_some_and(|world| flagged.contains(&world)) {
        return Ok(true);
    }
    // The body decides first; the stored row decides too, so a carrier whose
    // body names another world cannot ship a stored private row's id.
    let mut carried = false;
    let mut ids = BTreeSet::new();
    map_for_each_value_bytes(&doc.get_map("entities"), |key, blob| {
        carried |= blob.is_some_and(|raw| claim_in(raw, flagged));
        ids.extend(EntityId::from_hex(key).ok());
    });
    map_for_each_value_bytes(&doc.get_map("edges"), |key, _| {
        if let Some((src, _, tgt)) = parse_edge_key(key) {
            ids.extend([src, tgt]);
        }
    });
    Ok(carried || stored_withheld_among(vault, flagged, ids)?)
}

/// Read from `history` (taken before any read transaction opens: taking it
/// commits a pending edit, which runs the window's observers).
fn history_inserts_device_only(
    vault: &Vault,
    flagged: &BTreeSet<EntityId>,
    history: &JsonSchema,
) -> Result<bool> {
    let entities = ContainerID::new_root("entities", ContainerType::Map);
    let edges = ContainerID::new_root("edges", ContainerType::Map);
    let mut ids = BTreeSet::new();
    for op in history.changes.iter().flat_map(|change| &change.ops) {
        let JsonOpContent::Map(MapOp::Insert { key, value }) = &op.content else {
            continue;
        };
        if op.container == entities {
            if let LoroValue::Binary(blob) = value
                && claim_in(&blob[..], flagged)
            {
                return Ok(true);
            }
            ids.extend(EntityId::from_hex(key).ok());
        } else if op.container == edges
            && let Some((src, _, tgt)) = parse_edge_key(key)
        {
            ids.extend([src, tgt]);
        }
    }
    stored_withheld_among(vault, flagged, ids)
}

/// Whether a flagged world keeps any of `ids` by its stored row: the WORLD
/// itself, a CLAIM of it (erased or purged ones included), a NOTE in it, or
/// an epoch SUMMARY born in it or written from a row it keeps.
fn stored_withheld_among(
    vault: &Vault,
    flagged: &BTreeSet<EntityId>,
    ids: BTreeSet<EntityId>,
) -> Result<bool> {
    let rtxn = vault.store.env.read_txn()?;
    for id in ids {
        if crate::settings::device_only_withholds(&vault.store, &rtxn, flagged, &id)? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The export of a withheld window: an empty document's update, so no
/// operation of the live window (pending, concurrent or committed) rides it.
pub(super) fn withheld_window_update() -> Result<Vec<u8>> {
    export_updates_from(&LoroDoc::new(), &VersionVector::default())
}

/// Ids among `entities` and the endpoints of `edges` (wherever those rows
/// live) that a device-only world keeps on this device. A CLAIM carrier
/// naming a flagged world is withheld whatever its key or stored row says.
/// Read inside the caller's export transaction.
pub(in crate::sync) fn device_only_ids(
    vault: &Vault,
    rtxn: &RoTxn<'_>,
    entities: &LoroMap,
    edges: &LoroMap,
) -> Result<HashSet<EntityId>> {
    let flagged = crate::settings::device_only_worlds_in(&vault.store, rtxn)?;
    let mut withheld = HashSet::new();
    if flagged.is_empty() {
        return Ok(withheld);
    }
    let mut ids = BTreeSet::new();
    map_for_each_value_bytes(entities, |key, blob| {
        if let Ok(id) = EntityId::from_hex(key) {
            if blob.is_some_and(|raw| claim_in(raw, &flagged)) {
                withheld.insert(id);
            }
            ids.insert(id);
        }
    });
    map_for_each_value_bytes(edges, |key, _| {
        if let Some((src, _, tgt)) = parse_edge_key(key) {
            ids.extend([src, tgt]);
        }
    });
    for id in ids {
        if !withheld.contains(&id)
            && crate::settings::device_only_withholds(&vault.store, rtxn, &flagged, &id)?
        {
            withheld.insert(id);
        }
    }
    Ok(withheld)
}

/// Whether a carried CLAIM body names a flagged world. A body that cannot be
/// read names no world anyone can check, so it counts as one.
fn claim_in(raw: &[u8], flagged: &BTreeSet<EntityId>) -> bool {
    EntityMetadataHeader::parse(raw)
        .is_some_and(|header| header.entity_type == crate::registry::ENTITY_TYPE_CLAIM)
        && raw.len() > ENTITY_METADATA_HEADER_LEN
        && crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)
            .ok()
            .is_none_or(|body| body.world.is_some_and(|world| flagged.contains(&world)))
}
