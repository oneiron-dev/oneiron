//! CRDT Doc schema creation for the sync layer.
//!
//! Defines the root doc and window doc schemas per ARCH-023 Part 2.

use loro::LoroDoc;

use super::loro_support::{map_get_bytes, map_insert_bytes};
use super::types::{WindowKey, parse_window_key_str};

/// Creates a new root Doc with the standard schema.
///
/// The root doc holds a `meta` map with vault metadata and window list.
pub fn create_root_doc(_user_id: &str, vault_id: &str, windows: &[WindowKey]) -> LoroDoc {
    let doc = LoroDoc::new();
    let meta = doc.get_map("meta");

    map_insert_bytes(&meta, "vault_id", vault_id.as_bytes()).unwrap();
    map_insert_bytes(&meta, "schema_version", &1i64.to_le_bytes()).unwrap();

    let window_list: String = windows
        .iter()
        .map(|w| w.as_str())
        .collect::<Vec<_>>()
        .join(",");
    map_insert_bytes(&meta, "windows", window_list.as_bytes()).unwrap();

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
    match map_get_bytes(&meta, "windows") {
        Some(raw) => {
            let s = String::from_utf8_lossy(&raw);
            if s.is_empty() {
                Vec::new()
            } else {
                s.split(',')
                    .filter_map(|w| {
                        let key = w.trim();
                        if parse_window_key_str(key).is_some() {
                            Some(WindowKey::new(key))
                        } else {
                            if !key.is_empty() {
                                tracing::warn!(
                                    window_key = %key,
                                    "sync schema: ignoring invalid root window key"
                                );
                            }
                            None
                        }
                    })
                    .collect()
            }
        }
        None => Vec::new(),
    }
}

/// Adds a new window key to a root doc's `meta.windows` field.
pub fn add_window_to_root(doc: &LoroDoc, key: &WindowKey) {
    let key = key.as_str().trim();
    if parse_window_key_str(key).is_none() {
        if !key.is_empty() {
            tracing::warn!(
                window_key = %key,
                "sync schema: ignoring invalid root window key"
            );
        }
        return;
    }

    let meta = doc.get_map("meta");
    let current = map_get_bytes(&meta, "windows")
        .map(|raw| String::from_utf8_lossy(&raw).to_string())
        .unwrap_or_default();

    if !current.is_empty() && current.split(',').any(|window| window.trim() == key) {
        return;
    }

    let new_list = if current.is_empty() {
        key.to_string()
    } else {
        format!("{current},{key}")
    };
    map_insert_bytes(&meta, "windows", new_list.as_bytes()).unwrap();
    doc.commit();
}

#[cfg(test)]
mod tests {
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
        assert_eq!(sv, 1i64.to_le_bytes(), "schema_version mismatch");
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
        assert_eq!(windows.len(), 2);
        assert_eq!(windows[0].as_str(), "2026-01");
        assert_eq!(windows[1].as_str(), "2026-02");

        add_window_to_root(&doc, &WindowKey::new("2026-03"));
        let windows = read_window_list(&doc);
        assert_eq!(windows.len(), 3);
        assert_eq!(windows[2].as_str(), "2026-03");
    }

    #[test]
    fn read_window_list_skips_blank_and_invalid_tokens() {
        let doc = create_root_doc("user1", "vault-abc", &[]);
        let meta = doc.get_map("meta");
        let raw_windows = b"2026-01,,2026-13,garbage,2026-02";
        map_insert_bytes(&meta, "windows", raw_windows).unwrap();
        doc.commit();

        let windows = read_window_list(&doc);
        assert_eq!(
            windows,
            vec![WindowKey::new("2026-01"), WindowKey::new("2026-02")]
        );
        assert_eq!(
            map_get_bytes(&meta, "windows").unwrap().as_slice(),
            raw_windows
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

        let meta = doc.get_map("meta");
        assert_eq!(
            map_get_bytes(&meta, "windows").unwrap().as_slice(),
            b"2026-01"
        );
        let windows = read_window_list(&doc);
        assert_eq!(windows.len(), 1);
        assert_eq!(windows[0].as_str(), "2026-01");
    }

    #[test]
    fn add_window_to_root_rejects_invalid_key() {
        let doc = create_root_doc("user1", "vault-abc", &[WindowKey::new("2026-01")]);

        add_window_to_root(&doc, &WindowKey::new_unchecked_for_test("2026-02,evil"));

        let meta = doc.get_map("meta");
        assert_eq!(
            map_get_bytes(&meta, "windows").unwrap().as_slice(),
            b"2026-01"
        );
        let windows = read_window_list(&doc);
        assert_eq!(windows.len(), 1);
        assert_eq!(windows[0].as_str(), "2026-01");
    }
}
