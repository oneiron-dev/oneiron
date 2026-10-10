//! Loro-native helpers for the sync layer.
//!
//! ARCH-0023b makes Loro the production CRDT engine. These helpers keep the
//! repeated binary-value and encoding error handling in one place while all
//! call sites still use native `LoroDoc` / `LoroMap` handles.

use loro::{ExportMode, LoroDoc, LoroMap, LoroValue, ValueOrContainer, VersionVector};

use crate::entity_id::EntityId;
use crate::error::{Error, Result, SyncEngineContext, SyncError};

pub(crate) fn map_insert_bytes(map: &LoroMap, key: &str, value: &[u8]) -> Result<()> {
    map.insert(key, value)
        .map_err(|e| Error::sync_engine(SyncEngineContext::LoroMapInsert, e))
}

pub(crate) fn map_get_bytes(map: &LoroMap, key: &str) -> Option<Vec<u8>> {
    match map.get(key)? {
        ValueOrContainer::Value(LoroValue::Binary(bytes)) => Some(bytes.to_vec()),
        _ => None,
    }
}

pub(crate) fn map_delete(map: &LoroMap, key: &str) -> Result<()> {
    map.delete(key)
        .map_err(|e| Error::sync_engine(SyncEngineContext::LoroMapDelete, e))
}

pub(crate) fn map_contains_binary(map: &LoroMap, key: &str) -> bool {
    matches!(
        map.get(key),
        Some(ValueOrContainer::Value(LoroValue::Binary(_)))
    )
}

/// Presence check for tombstone maps: ANY value or container under the key
/// counts as present (fail closed). Entities/edges maps must keep using
/// the Binary-only helpers.
fn map_contains_key(map: &LoroMap, key: &str) -> bool {
    map.get(key).is_some()
}

/// Reads a tombstones-map value for decode: a Binary value yields its
/// bytes; a PRESENT non-Binary value (string/int/container/…) yields the
/// EMPTY vec — which `decode_tombstone_value` decodes as HARD (fail
/// closed); an absent key yields `None`. Entities/edges maps must keep
/// using [`map_get_bytes`].
fn map_get_tombstone_value(map: &LoroMap, key: &str) -> Option<Vec<u8>> {
    match map.get(key)? {
        ValueOrContainer::Value(LoroValue::Binary(bytes)) => Some(bytes.to_vec()),
        _ => Some(Vec::new()),
    }
}

/// Entity-canonical presence check for tombstone maps. Map keys are raw
/// remote strings and `EntityId::from_hex` accepts BOTH hex casings while
/// `to_hex` emits lowercase — so an exact lowercase get is blind to a
/// crafted UPPERCASE-hex tombstone key and a delete-wins gate would fail
/// OPEN. Fast path: the canonical lowercase key. On miss: scan the map and
/// treat ANY key that parses to the same `EntityId` as present (fail
/// closed). The scan-on-miss is acceptable because tombstone maps are
/// small — deletes are rare. Entities/edges maps must keep using the
/// Binary-only helpers.
pub(crate) fn tombstone_map_contains_id(map: &LoroMap, id: &EntityId) -> bool {
    if map_contains_key(map, &id.to_hex()) {
        return true;
    }
    let mut present = false;
    map.for_each(|key, _| {
        if !present && EntityId::from_hex(key).is_ok_and(|parsed| parsed == *id) {
            present = true;
        }
    });
    present
}

/// Collects the tombstones-map values of EVERY key aliasing `id` — the
/// canonical lowercase key plus any case-shifted hex alias — each read
/// under the tombstone value rule (Binary passes its bytes; a PRESENT
/// non-Binary value yields the EMPTY vec, which decodes HARD downstream).
/// Same small-map scan-on-alias rationale as [`tombstone_map_contains_id`].
pub(crate) fn tombstone_values_for_id(map: &LoroMap, id: &EntityId) -> Vec<Vec<u8>> {
    let canonical = id.to_hex();
    let mut values = Vec::new();
    if let Some(value) = map_get_tombstone_value(map, &canonical) {
        values.push(value);
    }
    map.for_each(|key, value| {
        if key != canonical && EntityId::from_hex(key).is_ok_and(|parsed| parsed == *id) {
            values.push(match value {
                ValueOrContainer::Value(LoroValue::Binary(bytes)) => bytes.to_vec(),
                _ => Vec::new(),
            });
        }
    });
    values
}

pub(crate) fn map_for_each_bytes(map: &LoroMap, mut f: impl FnMut(&str, &[u8])) {
    map.for_each(|key, value| {
        if let ValueOrContainer::Value(LoroValue::Binary(bytes)) = value {
            f(key, &bytes);
        }
    });
}

/// Entities/edges-map iterator with FULL value visibility (ONE-1157): visits
/// EVERY key. Binary values pass their bytes through as `Some`; any
/// non-Binary value (string/int/container/…) yields `None` so the caller can
/// quarantine the op as a protocol violation — parity with Observer B's
/// non-Binary `_ =>` arms in `bridge.rs`, which persist an `x:` row instead
/// of skipping. The Binary-only [`map_for_each_bytes`] leaves a non-Binary
/// op invisible to replay: no x: row, no log — a silent drop.
pub(super) fn map_for_each_value_bytes(map: &LoroMap, mut f: impl FnMut(&str, Option<&[u8]>)) {
    map.for_each(|key, value| match value {
        ValueOrContainer::Value(LoroValue::Binary(bytes)) => f(key, Some(&bytes)),
        _ => f(key, None),
    });
}

/// [`map_for_each_value_bytes`] that visits the Binary values `later` selects
/// only after every other key, so a row checked against a sibling row in the
/// same map never depends on key order.
pub(super) fn map_for_each_value_bytes_deferring(
    map: &LoroMap,
    later: impl Fn(&[u8]) -> bool,
    mut f: impl FnMut(&str, Option<&[u8]>),
) {
    let mut deferred = Vec::new();
    map.for_each(|key, value| match value {
        ValueOrContainer::Value(LoroValue::Binary(bytes)) if later(&bytes) => {
            deferred.push((key.to_owned(), bytes));
        }
        ValueOrContainer::Value(LoroValue::Binary(bytes)) => f(key, Some(&bytes)),
        _ => f(key, None),
    });
    for (key, bytes) in &deferred {
        f(key, Some(bytes));
    }
}

/// Tombstone-map iterator: visits EVERY key. Binary values pass their bytes
/// through; any non-Binary value (string/int/container/…) yields the EMPTY
/// slice, which `decode_tombstone_value` decodes as HARD — fail closed,
/// mirroring Observer B's non-binary tombstone arm in `bridge.rs`. A
/// malformed remote tombstone must never be invisible to replay.
/// Entities/edges maps use [`map_for_each_value_bytes`], which surfaces
/// non-Binary values as `None` for quarantine instead (ONE-1157).
pub(crate) fn map_for_each_tombstone_value(map: &LoroMap, mut f: impl FnMut(&str, &[u8])) {
    map.for_each(|key, value| match value {
        ValueOrContainer::Value(LoroValue::Binary(bytes)) => f(key, &bytes),
        _ => f(key, &[]),
    });
}

#[cfg(test)]
pub(crate) fn export_all_updates(doc: &LoroDoc) -> Result<Vec<u8>> {
    doc.export(ExportMode::all_updates())
        .map_err(|e| Error::sync_engine(SyncEngineContext::LoroExportAllUpdates, e))
}

/// The single delta-export entry point for the sync wire (ONE-1127).
///
/// Decodes the peer's binary `VersionVector::encode()` bytes and exports only
/// the updates the peer is missing (`ExportMode::updates`). Malformed VV
/// bytes return `crate::error::SyncError::CrdtDecodeError` — fail-closed, NEVER treated as an
/// empty VV (an empty-VV fallback would silently ship the full history).
pub fn export_updates_since(doc: &LoroDoc, remote_vv: &[u8]) -> Result<Vec<u8>> {
    let vv = VersionVector::decode(remote_vv).map_err(|source| {
        Error::Sync(SyncError::CrdtDecodeError {
            context: "decode version vector",
            source,
        })
    })?;

    export_updates_from(doc, &vv)
}

/// Exports the update delta since `vv` (the ops `doc` has that `vv` does
/// not cover). The delete path uses this to capture a tombstone-commit
/// delta for the delete-bearing offline-queue row (ONE-1135).
pub(crate) fn export_updates_from(doc: &LoroDoc, vv: &VersionVector) -> Result<Vec<u8>> {
    doc.export(ExportMode::updates(vv))
        .map_err(|e| Error::sync_engine(SyncEngineContext::LoroExportUpdates, e))
}

pub(crate) fn export_snapshot(doc: &LoroDoc) -> Result<Vec<u8>> {
    doc.export(ExportMode::Snapshot)
        .map_err(|e| Error::sync_engine(SyncEngineContext::LoroExportSnapshot, e))
}

pub(crate) fn import_doc(doc: &LoroDoc, bytes: &[u8]) -> Result<()> {
    doc.import(bytes).map_err(|source| {
        Error::Sync(SyncError::CrdtDecodeError {
            context: "import update",
            source,
        })
    })?;
    Ok(())
}

pub(crate) fn doc_version_vector(doc: &LoroDoc) -> Vec<u8> {
    doc.oplog_vv().encode()
}

pub(crate) fn doc_from_snapshot(bytes: &[u8]) -> Result<LoroDoc> {
    LoroDoc::from_snapshot(bytes).map_err(|source| {
        Error::Sync(SyncError::CrdtDecodeError {
            context: "from snapshot",
            source,
        })
    })
}

/// Deep value without empty root maps: `get_map` registers a root on the
/// local doc at first read, so an empty root is not replicated state.
#[cfg(test)]
pub(crate) fn replicated_deep_value(doc: &LoroDoc) -> LoroValue {
    match doc.get_deep_value() {
        LoroValue::Map(roots) => LoroValue::Map(
            roots
                .iter()
                .filter(|(_, value)| !matches!(value, LoroValue::Map(map) if map.is_empty()))
                .map(|(name, value)| (name.clone(), value.clone()))
                .collect(),
        ),
        other => other,
    }
}
