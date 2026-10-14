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

use std::collections::BTreeSet;

use loro::json::{JsonOpContent, MapOp};
use loro::{ContainerID, ContainerType, ExportMode, Frontiers, LoroDoc, LoroValue, VersionVector};

use super::super::local_claims::claim_sync_allowed;
use super::super::loro_support::{
    export_snapshot, export_updates_since, map_for_each_tombstone_value, map_for_each_value_bytes,
};
use super::super::types::WindowKey;
use super::egress::{
    export_history_free_window_snapshot, history_free_window_required, scrub_local_claim_carriers,
    scrub_local_only_carriers, scrub_redacted_attribution_carriers,
    scrub_withdrawn_delete_carriers,
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

/// Decides whether a range of a pinned window's history may ship as ordinary operations.
///
/// An entity-map insert is held back when its body is one a scrub keeps off the wire (a custody,
/// diagnostic, delegated-identity or LFS chunk carrier, a claim no replay door accepts, an
/// attribution of a redacted author), whatever the live state holds. Any root-map insert is held
/// back when its key is gone from the live map, unless a soft tombstone took the entity out: a
/// scrub, a hard delete, a withdrawn delete and a dropped NOTE proposal all remove keys, and the
/// bytes they removed stay in history. An overwritten value and a removal ship as for an unpinned
/// window. An operation on anything but a root map never ships.
pub(crate) struct HistoryCheck {
    redacted: BTreeSet<(EntityId, [u8; 32])>,
    /// Entities whose CRDT tombstone is soft while this vault holds them deleted.
    erased: BTreeSet<EntityId>,
}

impl HistoryCheck {
    /// Reads the facts the check needs, before any write transaction opens.
    pub(crate) fn read(vault: &Vault, doc: &LoroDoc) -> Result<Self> {
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
            let raw = vault.store.entities.get(&rtxn, id.as_bytes())?;
            if crate::deletion::row_deletion_marked(&vault.store, &rtxn, &id, raw.as_deref())? {
                erased.insert(id);
            }
        }
        Ok(Self { redacted, erased })
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
        if map == "tombstones" || doc.get_map(map).get(key).is_some() {
            return true;
        }
        map == "entities"
            && EntityId::from_hex(key)
                .is_ok_and(|id| id.to_hex() == key && !self.erased.contains(&id))
            && soft_tombstoned(doc, key)
    }

    fn withheld_body(&self, key: &str, blob: &[u8]) -> bool {
        is_unsyncable_secret_custody(blob)
            || is_delegated_channel_identity_carrier(blob)
            || !claim_sync_allowed(blob)
            || EntityId::from_hex(key)
                .is_ok_and(|id| crate::origin::lfs::is_lfs_chunk_blob(&id, blob))
            || crate::identity_topology::attribution_carrier_key(blob)
                .is_some_and(|author| self.redacted.contains(&author))
    }
}

/// Whether the canonical tombstone of `key` is a soft delete.
fn soft_tombstoned(doc: &LoroDoc, key: &str) -> bool {
    super::super::loro_support::map_get_bytes(&doc.get_map("tombstones"), key)
        .is_some_and(|value| !crate::deletion::decode_tombstone_value(&value).is_hard())
}

/// The version of the state at a shallow root: `start` excludes the root's own operations.
fn root_state(start: &VersionVector, frontiers: &Frontiers) -> VersionVector {
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
/// doc) when `check` ships everything past that root, else roots at the newest operation; either
/// way the root never comes before `baseline`. Loro may root a snapshot earlier than asked when
/// branches run concurrent with the requested root, so the root actually encoded is the one
/// checked. `check` is `None` for a window that is not pinned: its history ships as it would to a
/// peer that holds the root.
pub(crate) fn history_free_snapshot(
    doc: &LoroDoc,
    check: Option<&HistoryCheck>,
    baseline: Option<&VersionVector>,
) -> Result<Vec<u8>> {
    doc.commit();
    let admits = |start: &VersionVector, frontiers: &Frontiers| {
        baseline.is_none_or(|floor| root_state(start, frontiers).includes_vv(floor))
            && check.is_none_or(|check| check.ships_past(doc, start))
    };
    let own_root = doc.shallow_since_vv().to_vv();
    if admits(&own_root, &doc.shallow_since_frontiers()) {
        return export_snapshot(doc);
    }
    let bytes = doc
        .export(ExportMode::shallow_snapshot(&doc.oplog_frontiers()))
        .map_err(|e| Error::sync_engine(SyncEngineContext::LoroExportShallowSnapshot, e))?;
    let meta = LoroDoc::decode_import_blob_meta(&bytes, false).map_err(|source| {
        Error::Sync(SyncError::CrdtDecodeError {
            context: "decode history-free snapshot root",
            source,
        })
    })?;
    if admits(&meta.partial_start_vv, &meta.start_frontiers) {
        return Ok(bytes);
    }
    Err(Error::Sync(SyncError::SyncProtocolError {
        context: SyncProtocolValidation::HistoryFreeRootUnavailable,
    }))
}

/// Whether `doc` cannot take `update` as history because the update builds on operations
/// `doc` does not hold: ones its own shallow root cut away, or ones it never had. No update
/// brings such a document level; its holder needs, or must make its peer take, a replacement.
pub fn update_needs_replacement(doc: &LoroDoc, update: &[u8]) -> bool {
    match doc.fork().import(update) {
        Ok(status) => status.pending.is_some(),
        Err(loro::LoroError::ImportUpdatesThatDependsOnOutdatedVersion) => true,
        Err(_) => false,
    }
}

/// The floor a residence connection promoting `doc` now gets: the version of the state at the
/// root of the history-free snapshot the home would serve it at this moment. Loro roots a
/// snapshot at the newest version every operation is ordered against, so the floor is a root a
/// later replacement can always be cut at, unless an operation concurrent with it arrives.
pub fn promotion_baseline(doc: &LoroDoc) -> Result<VersionVector> {
    let bytes = export_history_free_window_snapshot(doc)?;
    let meta = LoroDoc::decode_import_blob_meta(&bytes, false).map_err(|source| {
        Error::Sync(SyncError::CrdtDecodeError {
            context: "decode promotion snapshot root",
            source,
        })
    })?;
    Ok(root_state(&meta.partial_start_vv, &meta.start_frontiers))
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
    let remote = VersionVector::decode(remote_vv).map_err(|source| {
        Error::Sync(SyncError::CrdtDecodeError {
            context: "decode version vector",
            source,
        })
    })?;
    if super::device_only::export_withheld(vault, key, doc, &remote)? {
        return super::device_only::withheld_window_update().map(WindowExport::Update);
    }
    let check = match scrub_for_export(vault, key, doc, &remote)? {
        Scrubbed::DeviceOnlyHistory => {
            return export_history_free_window_snapshot(doc).map(WindowExport::Replacement);
        }
        Scrubbed::Pinned(check) => Some(check),
        Scrubbed::Unpinned => None,
    };
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
    let nothing = VersionVector::default();
    if super::device_only::export_withheld(vault, key, doc, &nothing)? {
        return Ok(None);
    }
    let check = match scrub_for_export(vault, key, doc, &nothing)? {
        Scrubbed::DeviceOnlyHistory => return export_history_free_window_snapshot(doc).map(Some),
        Scrubbed::Pinned(check) => Some(check),
        Scrubbed::Unpinned => None,
    };
    history_free_snapshot(doc, check.as_ref(), baseline).map(Some)
}

/// What the export scrubs left: whether the window is pinned history-free (with the check its
/// history must pass), or carries device-only history an empty receiver must not get.
enum Scrubbed {
    Unpinned,
    Pinned(HistoryCheck),
    DeviceOnlyHistory,
}

/// Refreshes NOTE carriers and runs every egress scrub over `doc`, as each export does.
fn scrub_for_export(
    vault: &Vault,
    key: &WindowKey,
    doc: &LoroDoc,
    remote: &VersionVector,
) -> Result<Scrubbed> {
    crate::sync::note::refresh(vault, doc, key)?;
    let secret_scrubbed = scrub_local_only_carriers(vault, key, doc)?;
    let claims_scrubbed = scrub_local_claim_carriers(vault, key, doc)?;
    let authors_scrubbed = scrub_redacted_attribution_carriers(vault, key, doc)?;
    let withdrawn_scrubbed = scrub_withdrawn_delete_carriers(vault, key, doc)?;
    if remote.is_empty() && super::device_only::delta_carries_device_only(vault, doc, remote)? {
        return Ok(Scrubbed::DeviceOnlyHistory);
    }
    if secret_scrubbed
        || claims_scrubbed
        || authors_scrubbed
        || withdrawn_scrubbed
        || history_free_window_required(vault, key)?
    {
        return HistoryCheck::read(vault, doc).map(Scrubbed::Pinned);
    }
    Ok(Scrubbed::Unpinned)
}
