//! Loro-native helpers for the sync layer.
//!
//! ARCH-0023b makes Loro the production CRDT engine. These helpers keep the
//! repeated binary-value and encoding error handling in one place while all
//! call sites still use native `LoroDoc` / `LoroMap` handles.

use loro::{ExportMode, LoroDoc, LoroMap, LoroValue, ValueOrContainer, VersionVector};

use crate::error::{Error, Result, SyncEngineContext};
use crate::types::EntityId;

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
pub(crate) fn map_contains_key(map: &LoroMap, key: &str) -> bool {
    map.get(key).is_some()
}

/// Reads a tombstones-map value for decode: a Binary value yields its
/// bytes; a PRESENT non-Binary value (string/int/container/…) yields the
/// EMPTY vec — which `decode_tombstone_value` decodes as HARD (fail
/// closed); an absent key yields `None`. Entities/edges maps must keep
/// using [`map_get_bytes`].
pub(crate) fn map_get_tombstone_value(map: &LoroMap, key: &str) -> Option<Vec<u8>> {
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
pub(crate) fn map_for_each_value_bytes(map: &LoroMap, mut f: impl FnMut(&str, Option<&[u8]>)) {
    map.for_each(|key, value| match value {
        ValueOrContainer::Value(LoroValue::Binary(bytes)) => f(key, Some(&bytes)),
        _ => f(key, None),
    });
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
/// bytes return `Error::CrdtDecodeError` — fail-closed, NEVER treated as an
/// empty VV (an empty-VV fallback would silently ship the full history).
pub fn export_updates_since(doc: &LoroDoc, remote_vv: &[u8]) -> Result<Vec<u8>> {
    let vv = VersionVector::decode(remote_vv).map_err(|source| Error::CrdtDecodeError {
        context: "decode version vector",
        source,
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
    doc.import(bytes).map_err(|source| Error::CrdtDecodeError {
        context: "import update",
        source,
    })?;
    Ok(())
}

pub(crate) fn doc_version_vector(doc: &LoroDoc) -> Vec<u8> {
    doc.oplog_vv().encode()
}

pub(crate) fn doc_from_snapshot(bytes: &[u8]) -> Result<LoroDoc> {
    LoroDoc::from_snapshot(bytes).map_err(|source| Error::CrdtDecodeError {
        context: "from snapshot",
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use loro::{CommitOptions, ContainerTrait};
    use std::sync::{Arc, Mutex};

    #[test]
    fn native_loro_map_ops() {
        let doc = LoroDoc::new();
        let map = doc.get_map("test");

        map_insert_bytes(&map, "key1", b"hello").unwrap();
        map.insert("text", "not-binary").unwrap();
        doc.commit();

        assert!(map_contains_binary(&map, "key1"));
        assert_eq!(map_get_bytes(&map, "key1").unwrap(), b"hello");
        assert!(!map_contains_binary(&map, "text"));
        assert!(!map_contains_binary(&map, "missing"));

        // Fail-closed presence: ANY value counts, only absence is absent.
        assert!(map_contains_key(&map, "key1"));
        assert!(map_contains_key(&map, "text"));
        assert!(!map_contains_key(&map, "missing"));

        map.delete("key1").unwrap();
        doc.commit();

        assert!(!map_contains_binary(&map, "key1"));
        assert!(!map_contains_key(&map, "key1"));
    }

    #[test]
    fn native_loro_map_for_each_bytes() {
        let doc = LoroDoc::new();
        let map = doc.get_map("test");

        map_insert_bytes(&map, "a", b"1").unwrap();
        map_insert_bytes(&map, "b", b"2").unwrap();
        doc.commit();

        let mut entries = Vec::new();
        map_for_each_bytes(&map, |k, v| {
            entries.push((k.to_string(), v.to_vec()));
        });
        entries.sort_by(|a, b| a.0.cmp(&b.0));

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0], ("a".to_string(), b"1".to_vec()));
        assert_eq!(entries[1], ("b".to_string(), b"2".to_vec()));
    }

    /// The tombstone helpers must see EVERY value shape (fail closed):
    /// presence is value-agnostic, and non-Binary values read/iterate as the
    /// EMPTY slice so the downstream decode resolves HARD. The Binary-only
    /// helpers stay blind to non-binary values (entities/edges semantics).
    #[test]
    fn tombstone_helpers_see_non_binary_values() {
        let doc = LoroDoc::new();
        let map = doc.get_map("tombstones");

        map_insert_bytes(&map, "bin", b"payload").unwrap();
        map.insert("text", "deleted").unwrap();
        map.insert("num", 7).unwrap();
        map.insert_container("child", loro::LoroMap::new()).unwrap();
        doc.commit();

        // Presence: ANY value or container counts; absent stays absent.
        for key in ["bin", "text", "num", "child"] {
            assert!(map_contains_key(&map, key), "{key} must count as present");
        }
        assert!(!map_contains_key(&map, "missing"));

        // Binary-only helpers keep ignoring non-binary values.
        assert!(map_contains_binary(&map, "bin"));
        assert!(!map_contains_binary(&map, "text"));
        assert!(!map_contains_binary(&map, "child"));

        // Value reads: Binary bytes pass through; present non-Binary reads
        // as EMPTY (decodes HARD); absent is None.
        assert_eq!(map_get_tombstone_value(&map, "bin").unwrap(), b"payload");
        assert_eq!(
            map_get_tombstone_value(&map, "text").unwrap(),
            Vec::<u8>::new()
        );
        assert_eq!(
            map_get_tombstone_value(&map, "child").unwrap(),
            Vec::<u8>::new()
        );
        assert!(map_get_tombstone_value(&map, "missing").is_none());

        // Iterator: every key visited, non-Binary as the empty slice.
        let mut entries = Vec::new();
        map_for_each_tombstone_value(&map, |k, v| {
            entries.push((k.to_string(), v.to_vec()));
        });
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(
            entries,
            vec![
                ("bin".to_string(), b"payload".to_vec()),
                ("child".to_string(), Vec::new()),
                ("num".to_string(), Vec::new()),
                ("text".to_string(), Vec::new()),
            ]
        );
    }

    /// M4 fix wave: tombstone probes must be entity-canonical — map keys
    /// are raw remote strings, `EntityId::from_hex` is case-insensitive,
    /// and `to_hex` emits lowercase, so an UPPERCASE-hex alias must read
    /// as present (and yield its value) for the same id.
    #[test]
    fn tombstone_helpers_canonicalize_hex_casing() {
        let id = EntityId::from_bytes_unchecked([0xAB; 16]);
        let other = EntityId::from_bytes_unchecked([0xCD; 16]);
        let upper = id.to_hex().to_uppercase();
        assert_ne!(upper, id.to_hex());

        let doc = LoroDoc::new();
        let map = doc.get_map("tombstones");
        map_insert_bytes(&map, &upper, b"hard-bytes").unwrap();
        doc.commit();

        assert!(
            tombstone_map_contains_id(&map, &id),
            "an uppercase alias must count as present for the same id"
        );
        assert!(!tombstone_map_contains_id(&map, &other));
        assert_eq!(
            tombstone_values_for_id(&map, &id),
            vec![b"hard-bytes".to_vec()]
        );
        assert!(tombstone_values_for_id(&map, &other).is_empty());

        // A non-Binary value under the canonical key joins the alias value;
        // it reads as the EMPTY vec (decodes HARD downstream).
        map.insert(id.to_hex().as_str(), "soft-ish").unwrap();
        doc.commit();
        assert!(tombstone_map_contains_id(&map, &id));
        let values = tombstone_values_for_id(&map, &id);
        assert_eq!(values.len(), 2, "canonical + alias both visited");
        assert!(values.contains(&Vec::new()));
        assert!(values.contains(&b"hard-bytes".to_vec()));
    }

    #[test]
    fn native_loro_snapshot_roundtrip() {
        let doc = LoroDoc::new();
        let map = doc.get_map("entities");
        map_insert_bytes(&map, "entity1", b"data").unwrap();
        doc.commit();

        let snapshot = export_snapshot(&doc).unwrap();
        let doc2 = doc_from_snapshot(&snapshot).unwrap();
        let map2 = doc2.get_map("entities");

        assert_eq!(map_get_bytes(&map2, "entity1").unwrap(), b"data");
    }

    #[test]
    fn native_loro_version_vector_roundtrip() {
        let doc = LoroDoc::new();
        let map = doc.get_map("test");
        map_insert_bytes(&map, "k", b"v").unwrap();
        doc.commit();

        let vv = doc_version_vector(&doc);
        assert!(!vv.is_empty());

        let decoded = VersionVector::decode(&vv);
        assert!(decoded.is_ok());
    }

    #[test]
    fn native_loro_delta_sync() {
        let doc_a = LoroDoc::new();
        let map_a = doc_a.get_map("data");
        map_insert_bytes(&map_a, "x", b"1").unwrap();
        doc_a.commit();

        let all = export_all_updates(&doc_a).unwrap();

        let doc_b = LoroDoc::new();
        import_doc(&doc_b, &all).unwrap();
        let map_b = doc_b.get_map("data");
        assert_eq!(map_get_bytes(&map_b, "x").unwrap(), b"1");

        map_insert_bytes(&map_a, "y", b"2").unwrap();
        doc_a.commit();

        let vv_b = doc_version_vector(&doc_b);
        let delta = export_updates_since(&doc_a, &vv_b).unwrap();
        import_doc(&doc_b, &delta).unwrap();

        assert_eq!(map_get_bytes(&map_b, "y").unwrap(), b"2");
    }

    #[test]
    fn native_loro_subscribe_local_updates() {
        let doc = LoroDoc::new();
        let received = Arc::new(Mutex::new(Vec::new()));
        let received_clone = received.clone();

        let _sub = doc.subscribe_local_update(Box::new(move |bytes| {
            received_clone.lock().unwrap().push(bytes.to_vec());
            true
        }));

        let map = doc.get_map("test");
        map_insert_bytes(&map, "k", b"v").unwrap();
        doc.commit();

        let updates = received.lock().unwrap();
        assert!(!updates.is_empty());
    }

    #[test]
    fn native_loro_commit_with_origin() {
        let doc = LoroDoc::new();
        let origins = Arc::new(Mutex::new(Vec::new()));
        let origins_clone = origins.clone();

        let map = doc.get_map("test");
        let _sub = doc.subscribe(
            &map.id(),
            Arc::new(move |event| {
                origins_clone.lock().unwrap().push(event.origin.to_string());
            }),
        );

        map_insert_bytes(&map, "k", b"v").unwrap();
        doc.commit_with(CommitOptions::new().origin("bridge"));

        let recorded = origins.lock().unwrap();
        assert!(recorded.iter().any(|o| o == "bridge"));
    }
}
