//! Loro implementation of the `CrdtEngine` traits.
//!
//! Maps the engine-agnostic `CrdtDoc` / `CrdtMap` interfaces onto
//! `loro::LoroDoc` and `loro::LoroMap`.

use std::sync::Arc;

use loro::{
    CommitOptions, ContainerTrait, ExportMode, LoroDoc, LoroMap, LoroValue, ValueOrContainer,
    VersionVector,
};


use super::engine::{CrdtDoc, CrdtMap, MapChange, Subscription};
use crate::error::{Error, Result};

// ─── LoroDocument ───────────────────────────────────────────────────────────

/// Thin wrapper around `LoroDoc` implementing `CrdtDoc`.
///
/// `LoroDoc` is internally `Arc`-based (clone is reference clone), so
/// this wrapper is cheap to share.
pub struct LoroDocument(pub LoroDoc);

impl CrdtDoc for LoroDocument {
    type Map = LoroMapHandle;

    fn new() -> Self {
        LoroDocument(LoroDoc::new())
    }

    fn get_or_create_map(&self, name: &str) -> LoroMapHandle {
        let map = self.0.get_map(name);
        LoroMapHandle {
            doc: self.0.clone(),
            map,
        }
    }

    // ── Sync ────────────────────────────────────────────────────────────

    fn export_all_updates(&self) -> Result<Vec<u8>> {
        self.0
            .export(ExportMode::all_updates())
            .map_err(|e| Error::SyncProtocolError(e.to_string()))
    }

    fn export_updates_since(&self, remote_vv: &[u8]) -> Result<Vec<u8>> {
        let vv = VersionVector::decode(remote_vv)
            .map_err(|e| Error::CrdtDecodeError(format!("decode version vector: {e}")))?;
        self.0
            .export(ExportMode::updates(&vv))
            .map_err(|e| Error::SyncProtocolError(e.to_string()))
    }

    fn export_snapshot(&self) -> Result<Vec<u8>> {
        self.0
            .export(ExportMode::Snapshot)
            .map_err(|e| Error::SyncProtocolError(e.to_string()))
    }

    fn import(&self, bytes: &[u8]) -> Result<()> {
        self.0
            .import(bytes)
            .map_err(|e| Error::CrdtDecodeError(e.to_string()))?;
        Ok(())
    }

    fn version_vector(&self) -> Vec<u8> {
        self.0.oplog_vv().encode()
    }

    // ── Commit ──────────────────────────────────────────────────────────

    fn commit(&self) {
        self.0.commit();
    }

    fn commit_with_origin(&self, origin: &str) {
        self.0
            .commit_with(CommitOptions::new().origin(origin));
    }

    // ── Persistence ─────────────────────────────────────────────────────

    fn encode_full_state(&self) -> Vec<u8> {
        self.0
            .export(ExportMode::Snapshot)
            .unwrap_or_default()
    }

    fn from_snapshot(bytes: &[u8]) -> Result<Self> {
        let doc = LoroDoc::from_snapshot(bytes)
            .map_err(|e| Error::CrdtDecodeError(e.to_string()))?;
        Ok(LoroDocument(doc))
    }

    // ── Observation ─────────────────────────────────────────────────────

    fn subscribe_local_updates(
        &self,
        cb: Box<dyn Fn(&[u8]) -> bool + Send + Sync>,
    ) -> Subscription {
        let sub = self.0.subscribe_local_update(Box::new(move |bytes| cb(bytes)));
        Subscription::new(sub)
    }
}

// ─── LoroMapHandle ──────────────────────────────────────────────────────────

/// A handle to a `LoroMap` container plus its parent `LoroDoc` (needed for
/// subscriptions, which attach to the doc via container ID).
pub struct LoroMapHandle {
    doc: LoroDoc,
    pub(super) map: LoroMap,
}

impl CrdtMap for LoroMapHandle {
    fn insert(&self, key: &str, value: &[u8]) -> Result<()> {
        self.map
            .insert(key, value)
            .map_err(|e| Error::SyncProtocolError(e.to_string()))?;
        Ok(())
    }

    fn get(&self, key: &str) -> Option<Vec<u8>> {
        match self.map.get(key)? {
            ValueOrContainer::Value(LoroValue::Binary(b)) => Some(b.to_vec()),
            _ => None,
        }
    }

    fn remove(&self, key: &str) -> Result<()> {
        self.map
            .delete(key)
            .map_err(|e| Error::SyncProtocolError(e.to_string()))?;
        Ok(())
    }

    fn contains_key(&self, key: &str) -> bool {
        self.map.get(key).is_some()
    }

    fn for_each(&self, f: &mut dyn FnMut(&str, &[u8])) {
        self.map.for_each(|key, voc| {
            if let ValueOrContainer::Value(LoroValue::Binary(b)) = voc {
                f(key, &b);
            }
        });
    }

    fn subscribe_changes(
        &self,
        cb: Arc<dyn Fn(Vec<MapChange>) + Send + Sync>,
    ) -> Subscription {
        let sub = self.doc.subscribe(
            &self.map.id(),
            Arc::new(move |event| {
                let mut changes = Vec::new();
                for container_diff in &event.events {
                    if let Some(map_delta) = container_diff.diff.as_map() {
                        for (key, new_val) in &map_delta.updated {
                            let key = key.to_string();
                            match new_val {
                                Some(ValueOrContainer::Value(LoroValue::Binary(b))) => {
                                    // Loro MapDelta doesn't distinguish insert vs update —
                                    // we report all as Inserted (the bridge only cares
                                    // about the new value).
                                    changes.push(MapChange::Inserted {
                                        key,
                                        value: b.to_vec(),
                                    });
                                }
                                None => {
                                    // Deleted — no old_value available from Loro.
                                    changes.push(MapChange::Removed {
                                        key,
                                        old_value: Vec::new(),
                                    });
                                }
                                _ => {
                                    // Non-binary value or container — ignore.
                                }
                            }
                        }
                    }
                }
                if !changes.is_empty() {
                    cb(changes);
                }
            }),
        );
        Subscription::new(sub)
    }
}

// We need Send + Sync for both types (LoroDoc and LoroMap are Send+Sync per docs.rs).
// Compiler should verify this automatically via the trait bounds.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loro_doc_basic_map_ops() {
        let doc = LoroDocument::new();
        let map = doc.get_or_create_map("test");

        map.insert("key1", b"hello").unwrap();
        doc.commit();

        assert!(map.contains_key("key1"));
        assert_eq!(map.get("key1").unwrap(), b"hello");
        assert!(!map.contains_key("missing"));
        assert!(map.get("missing").is_none());

        map.remove("key1").unwrap();
        doc.commit();

        assert!(!map.contains_key("key1"));
    }

    #[test]
    fn loro_doc_for_each() {
        let doc = LoroDocument::new();
        let map = doc.get_or_create_map("test");

        map.insert("a", b"1").unwrap();
        map.insert("b", b"2").unwrap();
        doc.commit();

        let mut entries = Vec::new();
        map.for_each(&mut |k, v| {
            entries.push((k.to_string(), v.to_vec()));
        });
        entries.sort_by(|a, b| a.0.cmp(&b.0));

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0], ("a".to_string(), b"1".to_vec()));
        assert_eq!(entries[1], ("b".to_string(), b"2".to_vec()));
    }

    #[test]
    fn loro_doc_snapshot_roundtrip() {
        let doc = LoroDocument::new();
        let map = doc.get_or_create_map("entities");
        map.insert("entity1", b"data").unwrap();
        doc.commit();

        let snapshot = doc.export_snapshot().unwrap();
        let doc2 = LoroDocument::from_snapshot(&snapshot).unwrap();
        let map2 = doc2.get_or_create_map("entities");

        assert_eq!(map2.get("entity1").unwrap(), b"data");
    }

    #[test]
    fn loro_doc_version_vector_roundtrip() {
        let doc = LoroDocument::new();
        let map = doc.get_or_create_map("test");
        map.insert("k", b"v").unwrap();
        doc.commit();

        let vv = doc.version_vector();
        assert!(!vv.is_empty());

        // Should be decodable
        let decoded = VersionVector::decode(&vv);
        assert!(decoded.is_ok());
    }

    #[test]
    fn loro_doc_delta_sync() {
        let doc_a = LoroDocument::new();
        let map_a = doc_a.get_or_create_map("data");
        map_a.insert("x", b"1").unwrap();
        doc_a.commit();

        // Export all from A
        let all = doc_a.export_all_updates().unwrap();

        // Import into B
        let doc_b = LoroDocument::new();
        doc_b.import(&all).unwrap();
        let map_b = doc_b.get_or_create_map("data");
        assert_eq!(map_b.get("x").unwrap(), b"1");

        // A makes more changes
        map_a.insert("y", b"2").unwrap();
        doc_a.commit();

        // B gets delta from A since B's version
        let vv_b = doc_b.version_vector();
        let delta = doc_a.export_updates_since(&vv_b).unwrap();
        doc_b.import(&delta).unwrap();

        assert_eq!(map_b.get("y").unwrap(), b"2");
    }

    #[test]
    fn loro_doc_subscribe_local_updates() {
        use std::sync::Mutex;

        let doc = LoroDocument::new();
        let received = Arc::new(Mutex::new(Vec::new()));
        let received_clone = received.clone();

        let _sub = doc.subscribe_local_updates(Box::new(move |bytes| {
            received_clone.lock().unwrap().push(bytes.to_vec());
            true
        }));

        let map = doc.get_or_create_map("test");
        map.insert("k", b"v").unwrap();
        doc.commit();

        let updates = received.lock().unwrap();
        assert!(!updates.is_empty());
    }

    #[test]
    fn loro_doc_commit_with_origin() {
        use std::sync::Mutex;
        use loro::ContainerTrait;

        let doc = LoroDocument::new();
        let origins = Arc::new(Mutex::new(Vec::new()));
        let origins_clone = origins.clone();

        let map = doc.get_or_create_map("test");
        let _sub = doc.0.subscribe(
            &map.map.id(),
            Arc::new(move |event| {
                origins_clone
                    .lock()
                    .unwrap()
                    .push(event.origin.to_string());
            }),
        );

        map.insert("k", b"v").unwrap();
        doc.commit_with_origin("bridge");

        let recorded = origins.lock().unwrap();
        assert!(recorded.iter().any(|o| o == "bridge"));
    }
}
