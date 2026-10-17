//! History-free window transport: what a window pinned history-free, or already shallow, ships
//! to a peer that asks with its version vector.
//!
//! Such a window used to answer every version request with a snapshot rooted at its newest
//! operation. A peer holding part of the window imports that as an update, and every operation
//! past the peer's own version then waits forever on history the snapshot left out. The export
//! door now answers in one of two typed ways:
//!
//! - [`WindowExport::Update`], ordinary Loro history past the requester's version, when the
//!   requester holds the window's shallow root and any connection baseline, and every operation in
//!   that range passes [`HistoryCheck`];
//! - [`WindowExport::Replacement`], a history-free snapshot the requester installs in place of its
//!   window and never merges.
//!
//! The pin exists because a scrub cannot erase an operation from Loro history. The check makes
//! that exact: after the scrubs run, an operation may ship only if it carries nothing the live
//! state no longer holds for a reason that keeps it off the wire.

use std::collections::{BTreeMap, BTreeSet};

use loro::json::{JsonOpContent, MapOp};
use loro::{
    CommitOptions, ContainerID, ContainerType, ExportMode, Frontiers, LoroDoc, LoroValue,
    VersionVector,
};

use super::super::local_claims::claim_sync_allowed;
use super::super::loro_support::{
    TombstoneIndex, export_snapshot, export_updates_since, map_for_each_tombstone_value,
    map_for_each_value_bytes,
};
use super::super::types::WindowKey;
use super::bridge::BRIDGE_ORIGIN;
use super::egress::{
    history_free_window_required, scrub_local_claim_carriers, scrub_local_only_carriers,
    scrub_redacted_attribution_carriers, scrub_withdrawn_delete_carriers,
};
use super::reverse::{is_delegated_channel_identity_carrier, is_unsyncable_secret_custody};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result, SyncEngineContext, SyncError, SyncProtocolValidation};

/// What a full-window version-vector export sends.
#[derive(Debug)]
pub enum WindowExport {
    /// Loro update bytes the receiver merges into its window.
    Update(Vec<u8>),
    /// A history-free snapshot the receiver installs in place of its window.
    Replacement(Vec<u8>),
}

impl WindowExport {
    /// The bytes either way. Only for a receiver that holds nothing of the window, where
    /// installing a replacement and importing it are the same act; every other receiver must
    /// tell the two apart.
    pub fn into_bytes(self) -> Vec<u8> {
        match self {
            Self::Update(bytes) | Self::Replacement(bytes) => bytes,
        }
    }
}

/// Decides whether a range of a pinned window's history, or the state at a snapshot's root, may
/// ship.
///
/// An entity-map value is held back when its body is one a scrub keeps off the wire (a custody,
/// diagnostic, delegated-identity or LFS chunk carrier, a claim no replay door accepts, an
/// attribution of a redacted author), whatever the live state holds. A scrub removes keys (a hard
/// or withdrawn delete, a dropped NOTE) or rewrites values in place (a NOTE proposal's redacted
/// explainer, a deleted entity's retained shell), and the bytes it took out stay in history and
/// in an old root's state. So a value whose key is gone is held back, unless a soft tombstone
/// took the entity out without erasing its body; and only the live value ships of a NOTE
/// workflow map (a refresh rewrites its rows from the vault's own state), a tombstoned entity, or
/// any map this check does not know. An overwritten edge, world witness or untombstoned entity
/// ships, as for an unpinned window: an ordinary edit took it out, and a window with concurrent
/// edits has no clean root without it. Tombstone values and removals always ship. An operation on
/// anything but a root map never ships.
pub(crate) struct HistoryCheck {
    redacted: BTreeSet<(EntityId, [u8; 32])>,
    /// Entities whose CRDT tombstone is soft while this vault holds them deleted.
    erased: BTreeSet<EntityId>,
    /// The exact header-only shells of user-deleted world claims the window keeps beside their
    /// world witness, as the egress claim scrub proves them: carriers no claim door decodes, yet
    /// the live state of the window.
    retained_shells: BTreeSet<(EntityId, Vec<u8>)>,
    /// The worlds whose keys this replica destroyed, among those the window's
    /// pads name: such a pad's bytes never ship, live or in history.
    late_pad_worlds: BTreeSet<EntityId>,
    /// The newest withdrawn generation of each artifact that has one: a body of it or older
    /// that is not its keyframe never ships, live or in history.
    withdrawn: BTreeMap<EntityId, u64>,
}

impl HistoryCheck {
    /// Reads the facts the check needs, before any write transaction opens.
    pub(crate) fn read(vault: &Vault, key: &WindowKey, doc: &LoroDoc) -> Result<Self> {
        let rtxn = vault.store.env.read_txn()?;
        let mut redacted = crate::identity_topology::redacted_keys_in_txn(&vault.store, &rtxn)?;
        map_for_each_value_bytes(&doc.get_map("entities"), |_, blob| {
            if let Some(key) = blob.and_then(crate::identity_topology::redaction_carrier_key) {
                redacted.insert(key);
            }
        });
        let mut soft = Vec::new();
        map_for_each_tombstone_value(&doc.get_map("tombstones"), |key, value| {
            if let Ok(id) = EntityId::from_hex(key)
                && !crate::deletion::decode_tombstone_value(value).is_hard()
            {
                soft.push(id);
            }
        });
        let mut erased = BTreeSet::new();
        for id in soft {
            let marked = match crate::ports::EntityStoreRead::port_entity_with_raw(
                &vault.store,
                &rtxn,
                &id,
                |raw| crate::deletion::row_deletion_marked(&vault.store, &rtxn, &id, Some(raw)),
            )? {
                Some(marked) => marked,
                None => crate::deletion::row_deletion_marked(&vault.store, &rtxn, &id, None)?,
            };
            if marked {
                erased.insert(id);
            }
        }
        let mut pad_worlds = BTreeSet::new();
        map_for_each_value_bytes(&doc.get_map("entities"), |_, blob| {
            if let Some(Ok(world)) = blob.and_then(crate::world_keys::pad_body_world) {
                pad_worlds.insert(world);
            }
        });
        let entities_root = ContainerID::new_root("entities", ContainerType::Map);
        for op in doc
            .export_json_updates(&VersionVector::default(), &doc.oplog_vv())
            .changes
            .iter()
            .flat_map(|change| &change.ops)
        {
            if op.container == entities_root
                && let JsonOpContent::Map(MapOp::Insert {
                    value: LoroValue::Binary(blob),
                    ..
                }) = &op.content
                && let Some(Ok(world)) = crate::world_keys::pad_body_world(blob)
            {
                pad_worlds.insert(world);
            }
        }
        // A shallow doc's own root holds state no retained operation carries:
        // a pad only there still names its world (Docs Q27).
        let shallow_root = doc.shallow_since_frontiers();
        if !shallow_root.is_empty() {
            let at_root = doc.fork();
            if at_root.checkout(&shallow_root).is_ok() {
                map_for_each_value_bytes(&at_root.get_map("entities"), |_, blob| {
                    if let Some(Ok(world)) = blob.and_then(crate::world_keys::pad_body_world) {
                        pad_worlds.insert(world);
                    }
                });
            } else {
                tracing::warn!(window = %key, "history check: shallow root unreadable");
            }
        }
        let mut late_pad_worlds = BTreeSet::new();
        for world in pad_worlds {
            if crate::world_keys::world_keys_destroyed_in_txn(&vault.store, &rtxn, world)? {
                late_pad_worlds.insert(world);
            }
        }
        let mut retained_shells = BTreeSet::new();
        if key.world().is_some() {
            let mut shells = Vec::new();
            map_for_each_value_bytes(&doc.get_map("entities"), |raw_key, blob| {
                if let Some(blob) = blob
                    && blob.len() == crate::batch::ENTITY_METADATA_HEADER_LEN
                    && let Ok(id) = EntityId::from_hex(raw_key)
                    && id.to_hex() == raw_key
                {
                    shells.push((id, blob.to_vec()));
                }
            });
            let tombstones = TombstoneIndex::build(&doc.get_map("tombstones"));
            for (id, blob) in shells {
                if crate::sync::types::retained_world_shell_belongs_to_window(
                    vault,
                    &rtxn,
                    doc,
                    &tombstones,
                    &id,
                    &blob,
                    key,
                    false,
                )? {
                    retained_shells.insert((id, blob));
                }
            }
        }
        let withdrawn = crate::deletion::withdrawn_generation_cutoffs_in_txn(&vault.store, &rtxn)?;
        Ok(Self {
            redacted,
            erased,
            retained_shells,
            late_pad_worlds,
            withdrawn,
        })
    }

    /// Whether every operation of `doc` past `from` may ship as ordinary history.
    pub(crate) fn ships_past(&self, doc: &LoroDoc, from: &VersionVector) -> bool {
        // The export commits a pending edit too, so read it into the range.
        doc.commit();
        let history = doc.export_json_updates(from, &doc.oplog_vv());
        history
            .changes
            .iter()
            .flat_map(|change| &change.ops)
            .all(|op| {
                let ContainerID::Root {
                    name,
                    container_type: ContainerType::Map,
                } = &op.container
                else {
                    return false;
                };
                match &op.content {
                    JsonOpContent::Map(MapOp::Delete { .. }) => true,
                    JsonOpContent::Map(MapOp::Insert { key, value }) => {
                        self.insert_ships(doc, name, key, value)
                    }
                    _ => false,
                }
            })
    }

    /// Whether `doc`'s state at `frontiers`, the root a snapshot would carry, holds only what
    /// may ship. A shallow snapshot encodes its root's state whole beside the operations past it,
    /// so a value a scrub took out after the root would ride along.
    pub(crate) fn root_ships(&self, doc: &LoroDoc, frontiers: &Frontiers) -> bool {
        if frontiers.is_empty() {
            return true;
        }
        let at_root = doc.fork();
        if at_root.checkout(frontiers).is_err() {
            return false;
        }
        let LoroValue::Map(roots) = at_root.get_value() else {
            return false;
        };
        roots.iter().all(|(name, root)| {
            let LoroValue::Container(ContainerID::Root {
                container_type: ContainerType::Map,
                ..
            }) = root
            else {
                return false;
            };
            let mut ships = true;
            at_root.get_map(name.as_str()).for_each(|key, value| {
                ships &= match value {
                    loro::ValueOrContainer::Value(value) => {
                        self.insert_ships(doc, name, key, &value)
                    }
                    loro::ValueOrContainer::Container(_) => false,
                };
            });
            ships
        })
    }

    fn insert_ships(&self, doc: &LoroDoc, map: &str, key: &str, value: &LoroValue) -> bool {
        if matches!(value, LoroValue::Container(_)) {
            return false;
        }
        if map == "entities"
            && let LoroValue::Binary(blob) = value
            && self.withheld_body(key, blob)
        {
            return false;
        }
        if map == "tombstones" {
            return true;
        }
        match doc.get_map(map).get(key) {
            Some(loro::ValueOrContainer::Value(live)) if live == *value => true,
            Some(loro::ValueOrContainer::Value(_)) => match map {
                "entities" => {
                    EntityId::from_hex(key).is_ok_and(|id| id.to_hex() == key)
                        && super::super::loro_support::map_get_bytes(
                            &doc.get_map("tombstones"),
                            key,
                        )
                        .is_none()
                }
                "edges" | "retained_claim_worlds" => true,
                _ => false,
            },
            Some(loro::ValueOrContainer::Container(_)) => false,
            None => {
                map == "entities"
                    && EntityId::from_hex(key)
                        .is_ok_and(|id| id.to_hex() == key && !self.erased.contains(&id))
                    && soft_tombstoned(doc, key)
            }
        }
    }

    fn withheld_body(&self, key: &str, blob: &[u8]) -> bool {
        is_unsyncable_secret_custody(blob)
            || is_delegated_channel_identity_carrier(blob)
            || (!claim_sync_allowed(blob)
                && !EntityId::from_hex(key)
                    .is_ok_and(|id| self.retained_shells.contains(&(id, blob.to_vec()))))
            || EntityId::from_hex(key)
                .is_ok_and(|id| crate::origin::lfs::is_lfs_chunk_blob(&id, blob))
            || crate::identity_topology::attribution_carrier_key(blob)
                .is_some_and(|author| self.redacted.contains(&author))
            || crate::world_keys::pad_body_world(blob).is_some_and(|world| {
                world.is_err() || world.is_ok_and(|world| self.late_pad_worlds.contains(&world))
            })
            || EntityId::from_hex(key)
                .is_ok_and(|id| super::withdrawn::withdrawn_body(&self.withdrawn, &id, blob))
    }
}

/// Whether the canonical tombstone of `key` is a soft delete.
fn soft_tombstoned(doc: &LoroDoc, key: &str) -> bool {
    super::super::loro_support::map_get_bytes(&doc.get_map("tombstones"), key)
        .is_some_and(|value| !crate::deletion::decode_tombstone_value(&value).is_hard())
}

/// The version of the state at a shallow root: `start` excludes the root's own operations.
pub(super) fn root_state(start: &VersionVector, frontiers: &Frontiers) -> VersionVector {
    let mut state = start.clone();
    for id in frontiers.iter() {
        let end = id.counter + 1;
        if state.get(&id.peer).is_none_or(|counter| *counter < end) {
            state.insert(id.peer, end);
        }
    }
    state
}

/// A history-free snapshot of `doc`. It keeps the doc's own root (all of its history, for a full
/// doc) when `check` ships that root's state and everything past it, else roots at the newest
/// operation; either way the root never comes before `baseline`. Loro may root a snapshot earlier
/// than asked when branches run concurrent with the requested root, so the root actually encoded
/// is the one checked. `check` is `None` for a window that is not pinned: its history ships as it
/// would to a peer that holds the root.
pub(crate) fn history_free_snapshot(
    doc: &LoroDoc,
    check: Option<&HistoryCheck>,
    baseline: Option<&VersionVector>,
) -> Result<Vec<u8>> {
    doc.commit();
    let admits = |start: &VersionVector, frontiers: &Frontiers| {
        baseline.is_none_or(|floor| root_state(start, frontiers).includes_vv(floor))
            && check.is_none_or(|check| {
                check.root_ships(doc, frontiers) && check.ships_past(doc, start)
            })
    };
    let own_root = doc.shallow_since_vv().to_vv();
    if admits(&own_root, &doc.shallow_since_frontiers()) {
        return export_snapshot(doc);
    }
    let (bytes, start, frontiers) = newest_rooted_snapshot(doc)?;
    if admits(&start, &frontiers) {
        return Ok(bytes);
    }
    Err(root_unavailable())
}

/// The history-free snapshot a pinned window is persisted as: [`history_free_snapshot`] when a
/// root passes `check`, else the snapshot rooted at its newest operation, as before the check
/// existed. Persistence never fails for want of a clean root; no export ships the stored root
/// without checking it again.
pub(crate) fn persisted_history_free_snapshot(
    doc: &LoroDoc,
    check: &HistoryCheck,
) -> Result<Vec<u8>> {
    match history_free_snapshot(doc, Some(check), None) {
        Err(Error::Sync(SyncError::SyncProtocolError {
            context: SyncProtocolValidation::HistoryFreeRootUnavailable,
        })) => newest_rooted_snapshot(doc).map(|(bytes, _, _)| bytes),
        other => other,
    }
}

fn root_unavailable() -> Error {
    Error::Sync(SyncError::SyncProtocolError {
        context: SyncProtocolValidation::HistoryFreeRootUnavailable,
    })
}

/// A snapshot of `doc` rooted at its newest operation, with the root Loro actually encoded: the
/// version operations start after, and the root's frontiers.
fn newest_rooted_snapshot(doc: &LoroDoc) -> Result<(Vec<u8>, VersionVector, Frontiers)> {
    doc.commit();
    let bytes = doc
        .export(ExportMode::shallow_snapshot(&doc.oplog_frontiers()))
        .map_err(|e| Error::sync_engine(SyncEngineContext::LoroExportShallowSnapshot, e))?;
    let meta = LoroDoc::decode_import_blob_meta(&bytes, false).map_err(|source| {
        Error::Sync(SyncError::CrdtDecodeError {
            context: "decode history-free snapshot root",
            source,
        })
    })?;
    Ok((bytes, meta.partial_start_vv, meta.start_frontiers))
}

/// The replacement an empty receiver gets of a window whose history inserted something a
/// device-only world keeps: rooted at the newest operation, as long as neither the state at that
/// root nor what the snapshot retains past it carries such a row, or anything `check` holds
/// back, and the root is not before `baseline`.
fn device_only_history_snapshot(
    vault: &Vault,
    key: &WindowKey,
    doc: &LoroDoc,
    check: Option<&HistoryCheck>,
    baseline: Option<&VersionVector>,
    withhold: super::Withhold<'_>,
) -> Result<Vec<u8>> {
    let (bytes, start, frontiers) = newest_rooted_snapshot(doc)?;
    let root_kept = if frontiers.is_empty() {
        false
    } else {
        let at_root = doc.fork();
        at_root.checkout(&frontiers).is_err()
            || super::device_only::window_withheld_for(vault, key, &at_root, withhold)?
    };
    let clean = baseline.is_none_or(|floor| root_state(&start, &frontiers).includes_vv(floor))
        && check
            .is_none_or(|check| check.root_ships(doc, &frontiers) && check.ships_past(doc, &start))
        && !root_kept
        && !super::device_only::delta_carries_device_only_for(vault, doc, &start, withhold)?;
    if clean {
        Ok(bytes)
    } else {
        Err(root_unavailable())
    }
}

/// Whether `update` builds on operations `doc`'s own shallow root cut away. No update brings
/// such a document level; its holder needs, or must make its peer take, a replacement. An update
/// that merely arrives ahead of history `doc` has not received yet is not one: the version
/// exchange brings that.
pub fn update_reaches_below_root(doc: &LoroDoc, update: &[u8]) -> bool {
    doc.is_shallow()
        && matches!(
            doc.fork().import(update),
            Err(loro::LoroError::ImportUpdatesThatDependsOnOutdatedVersion)
        )
}

/// The floor a residence connection promoting `doc` now gets: the version of the state at the
/// root of the history-free snapshot the home would serve it at this moment. Loro roots a
/// snapshot at the newest version every operation is ordered against, so the floor is a root a
/// later replacement can always be cut at, unless an operation concurrent with it arrives.
pub fn promotion_baseline(doc: &LoroDoc) -> Result<VersionVector> {
    let (_, start, frontiers) = newest_rooted_snapshot(doc)?;
    Ok(root_state(&start, &frontiers))
}

/// THE full-window version-vector export door: every arm that answers a peer's version vector
/// with window state (owner client and server, request and response, residence promotion) calls
/// this, so one policy decides between history and a replacement.
///
/// The peer VV is decoded first, so a malformed vector never becomes a full-export fallback. A
/// window of a world flagged device-only, or one carrying such a world's claim or an edge naming
/// one, ships nothing, against the flag as it stands now. So does a delta that inserts one, to a
/// receiver that already holds part of the window; an empty receiver gets the newest-rooted
/// replacement.
///
/// `baseline` is a promoted residence connection's floor: a vector that does not cover it gets a
/// replacement rooted at or after it, never older history.
pub fn export_window_since(
    vault: &Vault,
    key: &WindowKey,
    doc: &LoroDoc,
    remote_vv: &[u8],
    baseline: Option<&VersionVector>,
) -> Result<WindowExport> {
    export_window_since_for(
        vault,
        key,
        doc,
        remote_vv,
        baseline,
        super::Withhold::Unknown,
    )
}

/// [`export_window_since`] for the machine the export serves: the worlds
/// `withhold` names are kept off it, and a private world it may read keeps
/// flowing to it (OF-534 G6).
pub fn export_window_since_for(
    vault: &Vault,
    key: &WindowKey,
    doc: &LoroDoc,
    remote_vv: &[u8],
    baseline: Option<&VersionVector>,
    withhold: super::Withhold<'_>,
) -> Result<WindowExport> {
    let remote = VersionVector::decode(remote_vv).map_err(|source| {
        Error::Sync(SyncError::CrdtDecodeError {
            context: "decode version vector",
            source,
        })
    })?;
    if super::device_only::export_withheld_for(vault, key, doc, &remote, withhold)? {
        return super::device_only::withheld_window_update().map(WindowExport::Update);
    }
    let Scrubbed {
        check,
        device_only_history,
    } = scrub_for_export(vault, key, doc, &remote, withhold)?;
    if device_only_history {
        return device_only_history_snapshot(vault, key, doc, check.as_ref(), baseline, withhold)
            .map(WindowExport::Replacement);
    }
    let holds_floor = remote.includes_vv(&doc.shallow_since_vv().to_vv())
        && baseline.is_none_or(|floor| remote.includes_vv(floor));
    if holds_floor
        && check
            .as_ref()
            .is_none_or(|check| check.ships_past(doc, &remote))
    {
        return export_updates_since(doc, remote_vv).map(WindowExport::Update);
    }
    history_free_snapshot(doc, check.as_ref(), baseline).map(WindowExport::Replacement)
}

/// [`export_window_since`] for a connection with no promotion baseline.
pub fn export_window_updates_since(
    vault: &Vault,
    key: &WindowKey,
    doc: &LoroDoc,
    remote_vv: &[u8],
) -> Result<WindowExport> {
    export_window_since(vault, key, doc, remote_vv, None)
}

/// The replacement a peer asks for outright ([`crate::sync::transport::window_sub_tags::REPLACEMENT_REQUEST`]):
/// the history-free snapshot the export door would send a peer behind the floor, after the same
/// withholding and scrubs. `None` for a window withheld as device-only, which ships nothing.
pub fn export_window_replacement(
    vault: &Vault,
    key: &WindowKey,
    doc: &LoroDoc,
    baseline: Option<&VersionVector>,
) -> Result<Option<Vec<u8>>> {
    export_window_replacement_for(vault, key, doc, baseline, super::Withhold::Unknown)
}

/// [`export_window_replacement`] for the machine the export serves.
pub fn export_window_replacement_for(
    vault: &Vault,
    key: &WindowKey,
    doc: &LoroDoc,
    baseline: Option<&VersionVector>,
    withhold: super::Withhold<'_>,
) -> Result<Option<Vec<u8>>> {
    let nothing = VersionVector::default();
    if super::device_only::export_withheld_for(vault, key, doc, &nothing, withhold)? {
        return Ok(None);
    }
    let Scrubbed {
        check,
        device_only_history,
    } = scrub_for_export(vault, key, doc, &nothing, withhold)?;
    if device_only_history {
        return device_only_history_snapshot(vault, key, doc, check.as_ref(), baseline, withhold)
            .map(Some);
    }
    history_free_snapshot(doc, check.as_ref(), baseline).map(Some)
}

/// The snapshot a residence promotion ships to the machine `withhold` names: the replacement the
/// export door would cut, rooted no earlier than the window's newest root, so it carries no
/// history, after the same withholding, scrubs and history check. `None` for a window withheld
/// from that machine; typed `HistoryFreeRootUnavailable` when no root passes the check, never the
/// stored fallback root.
pub fn export_promotion_snapshot(
    vault: &Vault,
    key: &WindowKey,
    doc: &LoroDoc,
    withhold: super::Withhold<'_>,
) -> Result<Option<Vec<u8>>> {
    let newest = promotion_baseline(doc)?;
    export_window_replacement_for(vault, key, doc, Some(&newest), withhold)
}

/// What the export scrubs left.
struct Scrubbed {
    /// The check a pinned window's history must pass; `None` for a window not pinned.
    check: Option<HistoryCheck>,
    /// Whether an empty receiver's range carries an insert a device-only world keeps.
    device_only_history: bool,
}

/// Refreshes NOTE carriers and runs every egress scrub over `doc`, as each export does.
fn scrub_for_export(
    vault: &Vault,
    key: &WindowKey,
    doc: &LoroDoc,
    remote: &VersionVector,
    withhold: super::Withhold<'_>,
) -> Result<Scrubbed> {
    crate::sync::note::refresh(vault, doc, key)?;
    let secret_scrubbed = scrub_local_only_carriers(vault, key, doc)?;
    let claims_scrubbed = scrub_local_claim_carriers(vault, key, doc)?;
    let authors_scrubbed = scrub_redacted_attribution_carriers(vault, key, doc)?;
    let withdrawn_scrubbed = scrub_withdrawn_delete_carriers(vault, key, doc)?;
    let generations_scrubbed =
        super::withdrawn::scrub_withdrawn_generation_carriers(vault, key, doc)?;
    let rooms_scrubbed = crate::sync::room_turns::scrub_deleted_room_turns(vault, doc, Some(key))?;
    // FIX 1794: and their side rows, with an erased thread's facts.
    let room_facts_scrubbed = crate::sync::room_facts::scrub_room_facts(vault, doc, Some(key))?;
    // FIX 853: and the document quote pins of an erased message or reply.
    let document_pins_scrubbed =
        crate::sync::document_pins::scrub_document_pins(vault, doc, Some(key))?;
    // Every update and replacement ships each held revision of a PROJECT row the window
    // carries, whatever month it was learned in (Astra #1434 F2).
    if super::project_history::carry_project_history(vault, doc)? {
        doc.commit_with(CommitOptions::new().origin(BRIDGE_ORIGIN));
    }
    let check = if secret_scrubbed
        || claims_scrubbed
        || authors_scrubbed
        || withdrawn_scrubbed
        || generations_scrubbed
        || rooms_scrubbed
        || room_facts_scrubbed
        || document_pins_scrubbed
        || history_free_window_required(vault, key)?
    {
        Some(HistoryCheck::read(vault, key, doc)?)
    } else {
        None
    };
    Ok(Scrubbed {
        check,
        device_only_history: remote.is_empty()
            && super::device_only::delta_carries_device_only_for(vault, doc, remote, withhold)?,
    })
}
