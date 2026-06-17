//! CRDT Doc schema creation for the sync layer.
//!
//! Defines the root doc and window doc schemas per ARCH-023 Part 2.

use std::collections::BTreeSet;

use loro::{Container, LoroDoc, LoroMap, ValueOrContainer};

use super::loro_support::{map_get_bytes, map_insert_bytes};
use super::types::{WindowKey, parse_window_key_str};

pub(crate) const SCHEMA_VERSION: i64 = 1;

pub fn schema_version_bytes() -> [u8; 8] {
    SCHEMA_VERSION.to_le_bytes()
}

const ROOT_WINDOWS_KEY: &str = "windows";
const WINDOW_PRESENT_MARKER: &[u8] = b"1";

/// Creates a new root Doc with the standard schema.
///
/// The root doc holds a `meta` map with vault metadata and window list,
/// plus the `leases` device-lease registry map (ONE-1140, OD-3 —
/// server-write-only by the existing client-root-update rejection; each
/// entry is `client_id_hex` → the pinned 58 B lease record).
pub fn create_root_doc(_user_id: &str, vault_id: &str, windows: &[WindowKey]) -> LoroDoc {
    let doc = LoroDoc::new();
    let meta = doc.get_map("meta");

    map_insert_bytes(&meta, "vault_id", vault_id.as_bytes()).unwrap();
    map_insert_bytes(&meta, "schema_version", &schema_version_bytes()).unwrap();
    init_window_list(&doc, windows);

    let _leases = doc.get_map(super::lease::ROOT_LEASES_MAP);

    doc.commit();
    doc
}

/// Creates a new window Doc with the standard 3-map schema.
///
/// Window docs contain `entities`, `edges`, and `tombstones` maps.
pub fn create_window_doc(_user_id: &str, _key: &WindowKey) -> LoroDoc {
    let doc = LoroDoc::new();

    // Ensure the three maps exist (get_map lazily creates them).
    let _entities = doc.get_map("entities");
    let _edges = doc.get_map("edges");
    let _tombstones = doc.get_map("tombstones");

    doc.commit();
    doc
}

/// Reads the window list from a root doc's `meta.windows` field.
pub fn read_window_list(doc: &LoroDoc) -> Vec<WindowKey> {
    let meta = doc.get_map("meta");
    if let Some(windows) = window_list_map(&meta) {
        return read_window_map(&windows);
    }

    read_legacy_window_bytes(&meta)
}

/// Adds a new window key to a root doc's `meta.windows` field.
pub fn add_window_to_root(doc: &LoroDoc, key: &WindowKey) {
    let Some(key) = normalize_window_key(key.as_str()) else {
        return;
    };

    let meta = doc.get_map("meta");
    let (windows, migrated) = ensure_window_map(&meta);
    let inserted = insert_window_presence(&windows, key);

    if migrated || inserted {
        doc.commit();
    }
}

/// Initializes `meta.windows` as a Loro-native map keyed by window key.
pub fn init_window_list(doc: &LoroDoc, windows: &[WindowKey]) {
    let meta = doc.get_map("meta");
    let windows_map = meta
        .insert_container(ROOT_WINDOWS_KEY, LoroMap::new())
        .unwrap();

    for window in windows {
        if let Some(key) = normalize_window_key(window.as_str()) {
            insert_window_presence(&windows_map, key);
        }
    }
}

fn ensure_window_map(meta: &LoroMap) -> (LoroMap, bool) {
    if let Some(windows) = window_list_map(meta) {
        return (windows, false);
    }

    let existing = read_legacy_window_bytes(meta);
    let windows = meta
        .insert_container(ROOT_WINDOWS_KEY, LoroMap::new())
        .unwrap();
    for key in existing {
        insert_window_presence(&windows, key.as_str());
    }
    (windows, true)
}

fn window_list_map(meta: &LoroMap) -> Option<LoroMap> {
    match meta.get(ROOT_WINDOWS_KEY)? {
        ValueOrContainer::Container(Container::Map(windows)) => Some(windows),
        _ => None,
    }
}

fn insert_window_presence(windows: &LoroMap, key: &str) -> bool {
    if windows.get(key).is_some() {
        return false;
    }
    windows.insert(key, WINDOW_PRESENT_MARKER).unwrap();
    true
}

fn read_window_map(windows: &LoroMap) -> Vec<WindowKey> {
    let mut keys = BTreeSet::new();
    windows.for_each(|raw_key, _| {
        if let Some(key) = normalize_window_key(raw_key) {
            keys.insert(key.to_string());
        }
    });
    keys.into_iter().map(WindowKey::new).collect()
}

fn read_legacy_window_bytes(meta: &LoroMap) -> Vec<WindowKey> {
    let mut keys = BTreeSet::new();
    if let Some(raw) = map_get_bytes(meta, ROOT_WINDOWS_KEY) {
        let encoded = String::from_utf8_lossy(&raw);
        for raw_key in encoded.split(',') {
            if let Some(key) = normalize_window_key(raw_key) {
                keys.insert(key.to_string());
            }
        }
    }
    keys.into_iter().map(WindowKey::new).collect()
}

fn normalize_window_key(raw_key: &str) -> Option<&str> {
    let key = raw_key.trim();
    if parse_window_key_str(key).is_some() {
        Some(key)
    } else {
        if !key.is_empty() {
            tracing::warn!(
                window_key = %key,
                "sync schema: ignoring invalid root window key"
            );
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use loro::{ExportMode, LoroValue};

    use super::super::loro_support::map_for_each_bytes;
    use super::*;

    #[test]
    fn root_doc_schema() {
        // Single root doc creation must populate every meta field:
        //   - vault_id (raw bytes)
        //   - schema_version (i64 LE = 1)
        // Verified together to keep this as one creation-time invariant.
        let doc = create_root_doc("user1", "vault-abc", &[]);
        let meta = doc.get_map("meta");

        let vid = map_get_bytes(&meta, "vault_id").unwrap();
        assert_eq!(vid, b"vault-abc", "vault_id mismatch");

        let sv = map_get_bytes(&meta, "schema_version").unwrap();
        assert_eq!(sv, schema_version_bytes(), "schema_version mismatch");
    }

    #[test]
    fn window_doc_has_three_maps() {
        let key = WindowKey::new("2026-02");
        let doc = create_window_doc("user1", &key);

        let entities = doc.get_map("entities");
        let edges = doc.get_map("edges");
        let tombstones = doc.get_map("tombstones");

        // All maps should be empty
        let mut count = 0;
        map_for_each_bytes(&entities, |_, _| count += 1);
        assert_eq!(count, 0);

        count = 0;
        map_for_each_bytes(&edges, |_, _| count += 1);
        assert_eq!(count, 0);

        count = 0;
        map_for_each_bytes(&tombstones, |_, _| count += 1);
        assert_eq!(count, 0);
    }

    #[test]
    fn read_and_add_windows() {
        let doc = create_root_doc(
            "user1",
            "vault-abc",
            &[WindowKey::new("2026-01"), WindowKey::new("2026-02")],
        );

        let windows = read_window_list(&doc);
        assert_eq!(
            windows,
            vec![WindowKey::new("2026-01"), WindowKey::new("2026-02")]
        );

        add_window_to_root(&doc, &WindowKey::new("2026-03"));
        let windows = read_window_list(&doc);
        assert_eq!(
            windows,
            vec![
                WindowKey::new("2026-01"),
                WindowKey::new("2026-02"),
                WindowKey::new("2026-03")
            ]
        );

        add_window_to_root(&doc, &WindowKey::new("2026-02"));
        assert_eq!(
            read_window_list(&doc),
            vec![
                WindowKey::new("2026-01"),
                WindowKey::new("2026-02"),
                WindowKey::new("2026-03")
            ]
        );
    }

    #[test]
    fn read_window_list_skips_blank_and_invalid_tokens() {
        let doc = create_root_doc("user1", "vault-abc", &[]);
        let meta = doc.get_map("meta");
        let windows = window_list_map(&meta).unwrap();
        windows.insert("2026-01", WINDOW_PRESENT_MARKER).unwrap();
        windows.insert("", WINDOW_PRESENT_MARKER).unwrap();
        windows.insert("2026-13", WINDOW_PRESENT_MARKER).unwrap();
        windows.insert("garbage", LoroValue::I64(1)).unwrap();
        windows.insert("2026-02", WINDOW_PRESENT_MARKER).unwrap();
        doc.commit();

        let windows = read_window_list(&doc);
        assert_eq!(
            windows,
            vec![WindowKey::new("2026-01"), WindowKey::new("2026-02")]
        );
    }

    #[test]
    fn add_window_to_root_is_idempotent() {
        // Idempotency holds at any insertion position — single-entry list
        // (only/first slot) and middle of a 3-entry list. Each case re-adds
        // an existing window and asserts the list stays unchanged.
        let cases: &[(&str, &[&str], &str, &[&str])] = &[
            // (case_name, initial_windows, reinsert_key, expected_windows)
            ("first_slot", &["2026-01"], "2026-01", &["2026-01"]),
            (
                "middle_slot",
                &["2026-01", "2026-02", "2026-03"],
                "2026-02",
                &["2026-01", "2026-02", "2026-03"],
            ),
        ];

        for (case_name, initial, reinsert, expected) in cases {
            let initial_keys: Vec<WindowKey> = initial.iter().map(|k| WindowKey::new(*k)).collect();
            let doc = create_root_doc("user1", "vault-abc", &initial_keys);

            add_window_to_root(&doc, &WindowKey::new(*reinsert));

            let windows = read_window_list(&doc);
            assert_eq!(
                windows.len(),
                expected.len(),
                "case {case_name}: list length changed"
            );
            for (i, expected_key) in expected.iter().enumerate() {
                assert_eq!(
                    windows[i].as_str(),
                    *expected_key,
                    "case {case_name}: index {i} mismatch"
                );
            }
        }
    }

    #[test]
    fn add_window_to_root_normalizes_incoming_key_before_insert() {
        let doc = create_root_doc("user1", "vault-abc", &[]);

        add_window_to_root(&doc, &WindowKey::new_unchecked_for_test(" 2026-01 "));

        let windows = read_window_list(&doc);
        assert_eq!(windows.len(), 1);
        assert_eq!(windows[0].as_str(), "2026-01");
    }

    #[test]
    fn add_window_to_root_rejects_invalid_key() {
        let doc = create_root_doc("user1", "vault-abc", &[WindowKey::new("2026-01")]);

        add_window_to_root(&doc, &WindowKey::new_unchecked_for_test("2026-02,evil"));

        let windows = read_window_list(&doc);
        assert_eq!(windows.len(), 1);
        assert_eq!(windows[0].as_str(), "2026-01");
    }

    #[test]
    fn root_window_list_round_trips_through_snapshot_and_updates() {
        let doc = create_root_doc(
            "user1",
            "vault-abc",
            &[WindowKey::new("2026-02"), WindowKey::new("2026-01")],
        );
        add_window_to_root(&doc, &WindowKey::new("2026-03"));

        let snapshot = doc.export(ExportMode::Snapshot).unwrap();
        let from_snapshot = LoroDoc::from_snapshot(&snapshot).unwrap();
        assert_eq!(
            read_window_list(&from_snapshot),
            vec![
                WindowKey::new("2026-01"),
                WindowKey::new("2026-02"),
                WindowKey::new("2026-03")
            ]
        );

        let updates = doc.export(ExportMode::all_updates()).unwrap();
        let from_updates = LoroDoc::new();
        from_updates.import(&updates).unwrap();
        assert_eq!(
            read_window_list(&from_updates),
            vec![
                WindowKey::new("2026-01"),
                WindowKey::new("2026-02"),
                WindowKey::new("2026-03")
            ]
        );
    }

    #[test]
    fn root_window_list_converges_concurrent_distinct_adds() {
        let base = create_root_doc("user1", "vault-abc", &[]);
        let snapshot = base.export(ExportMode::Snapshot).unwrap();
        let doc_a = LoroDoc::from_snapshot(&snapshot).unwrap();
        let doc_b = LoroDoc::from_snapshot(&snapshot).unwrap();
        doc_a.set_peer_id(1).unwrap();
        doc_b.set_peer_id(2).unwrap();

        add_window_to_root(&doc_a, &WindowKey::new("2026-01"));
        add_window_to_root(&doc_b, &WindowKey::new("2026-02"));

        let a_updates = doc_a.export(ExportMode::all_updates()).unwrap();
        let b_updates = doc_b.export(ExportMode::all_updates()).unwrap();
        doc_a.import(&b_updates).unwrap();
        doc_b.import(&a_updates).unwrap();

        let expected = vec![WindowKey::new("2026-01"), WindowKey::new("2026-02")];
        assert_eq!(read_window_list(&doc_a), expected);
        assert_eq!(read_window_list(&doc_b), expected);
    }
}
