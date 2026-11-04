//! Loro byte-map operations and document codecs used by storage readers.

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

/// Copies `source`'s root map `name` of byte rows into `target`, and
/// commits. Copies nothing when `source` holds no such root: looking a root
/// up by name creates it.
pub(crate) fn copy_binary_root_map(source: &LoroDoc, target: &LoroDoc, name: &str) -> Result<()> {
    if !matches!(source.get_value(), LoroValue::Map(roots) if roots.contains_key(name)) {
        return Ok(());
    }
    let mut rows = Vec::new();
    source.get_map(name).for_each(|key, value| {
        if let ValueOrContainer::Value(LoroValue::Binary(bytes)) = value {
            rows.push((key.to_owned(), bytes.to_vec()));
        }
    });
    let map = target.get_map(name);
    for (key, bytes) in rows {
        map_insert_bytes(&map, &key, &bytes)?;
    }
    target.commit();
    Ok(())
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
pub(crate) fn map_for_each_value_bytes(map: &LoroMap, mut f: impl FnMut(&str, Option<&[u8]>)) {
    map.for_each(|key, value| match value {
        ValueOrContainer::Value(LoroValue::Binary(bytes)) => f(key, Some(&bytes)),
        _ => f(key, None),
    });
}

/// [`map_for_each_value_bytes`] that visits the Binary values `later` selects
/// only after every other key, so a row checked against a sibling row in the
/// same map never depends on key order.
pub(crate) fn map_for_each_value_bytes_deferring(
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

/// Whether `operations`, read from a doc over `meta`'s range, hold every
/// operation the import blob counts. Loro clips a JSON range below a
/// shallow root without saying so.
pub(crate) fn json_covers_blob(
    operations: &loro::json::JsonSchema,
    meta: &loro::ImportBlobMetadata,
) -> bool {
    let expected = meta
        .partial_end_vv
        .iter()
        .try_fold(0_usize, |sum, (peer, end)| {
            let start = meta.partial_start_vv.get(peer).copied().unwrap_or(0);
            sum.checked_add(usize::try_from(end.checked_sub(start)?).ok()?)
        });
    let inspected = operations
        .changes
        .iter()
        .flat_map(|change| &change.ops)
        .try_fold(0_usize, |sum, op| sum.checked_add(op.content.op_len()));
    expected.is_some() && expected == inspected
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

/// The entity carriers `ids` hold in `doc`, read before a local path removes
/// them, so `sync::window::mark_removed_carriers_first` can mark the task of
/// an authority fact among them that this vault never admitted: removing its
/// carrier before ingest saw it would otherwise read as a fact never made.
pub(crate) fn entity_carriers(doc: &LoroDoc, ids: &[EntityId]) -> Vec<(EntityId, Vec<u8>)> {
    let entities = doc.get_map("entities");
    ids.iter()
        .filter_map(|id| map_get_bytes(&entities, &id.to_hex()).map(|carrier| (*id, carrier)))
        .collect()
}
