//! Loro-native helpers for the sync layer.
//!
//! ARCH-0023b makes Loro the production CRDT engine. These helpers keep the
//! repeated binary-value and encoding error handling in one place while all
//! call sites still use native `LoroDoc` / `LoroMap` handles.

#[cfg(test)]
use loro::VersionVector;
use loro::{ExportMode, LoroDoc, LoroMap, LoroValue, ValueOrContainer};

use crate::error::{Error, Result};

pub(crate) fn map_insert_bytes(map: &LoroMap, key: &str, value: &[u8]) -> Result<()> {
    map.insert(key, value)
        .map_err(|e| Error::SyncProtocolError(e.to_string()))
}

pub(crate) fn map_get_bytes(map: &LoroMap, key: &str) -> Option<Vec<u8>> {
    match map.get(key)? {
        ValueOrContainer::Value(LoroValue::Binary(bytes)) => Some(bytes.to_vec()),
        _ => None,
    }
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

#[cfg(test)]
pub(crate) fn export_all_updates(doc: &LoroDoc) -> Result<Vec<u8>> {
    doc.export(ExportMode::all_updates())
        .map_err(|e| Error::SyncProtocolError(e.to_string()))
}

#[cfg(test)]
pub(crate) fn export_updates_since(doc: &LoroDoc, remote_vv: &[u8]) -> Result<Vec<u8>> {
    let vv = VersionVector::decode(remote_vv).map_err(|source| Error::CrdtDecodeError {
        context: "decode version vector",
        source,
    })?;

    doc.export(ExportMode::updates(&vv))
        .map_err(|e| Error::SyncProtocolError(e.to_string()))
}

pub(crate) fn export_snapshot(doc: &LoroDoc) -> Result<Vec<u8>> {
    doc.export(ExportMode::Snapshot)
        .map_err(|e| Error::SyncProtocolError(e.to_string()))
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

        map.delete("key1").unwrap();
        doc.commit();

        assert!(!map_contains_binary(&map, "key1"));
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
