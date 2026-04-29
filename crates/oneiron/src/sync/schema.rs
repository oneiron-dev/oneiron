//! CRDT Doc schema creation for the sync layer.
//!
//! Defines the root doc and window doc schemas per ARCH-023 Part 2.
//! Uses the engine-agnostic `CrdtDoc` trait, currently backed by Loro.

use super::engine::{CrdtDoc, CrdtMap};
use super::loro_engine::LoroDocument;
use super::types::{WindowKey, parse_window_key_str};

/// Creates a new root Doc with the standard schema.
///
/// The root doc holds a `meta` map with vault metadata and window list.
pub fn create_root_doc(_user_id: &str, vault_id: &str, windows: &[WindowKey]) -> LoroDocument {
    let doc = LoroDocument::new();
    let meta = doc.get_or_create_map("meta");

    meta.insert("vault_id", vault_id.as_bytes()).unwrap();
    meta.insert("schema_version", &1i64.to_le_bytes()).unwrap();

    let window_list: String = windows
        .iter()
        .map(|w| w.as_str())
        .collect::<Vec<_>>()
        .join(",");
    meta.insert("windows", window_list.as_bytes()).unwrap();

    doc.commit();
    doc
}

/// Creates a new window Doc with the standard 3-map schema.
///
/// Window docs contain `entities`, `edges`, and `tombstones` maps.
pub fn create_window_doc(_user_id: &str, _key: &WindowKey) -> LoroDocument {
    let doc = LoroDocument::new();

    // Ensure the three maps exist (get_or_create_map lazily creates them).
    let _entities = doc.get_or_create_map("entities");
    let _edges = doc.get_or_create_map("edges");
    let _tombstones = doc.get_or_create_map("tombstones");

    doc.commit();
    doc
}

/// Reads the window list from a root doc's `meta.windows` field.
pub fn read_window_list(doc: &LoroDocument) -> Vec<WindowKey> {
    let meta = doc.get_or_create_map("meta");
    match meta.get("windows") {
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
pub fn add_window_to_root(doc: &LoroDocument, key: &WindowKey) {
    let meta = doc.get_or_create_map("meta");
    let current = meta
        .get("windows")
        .map(|raw| String::from_utf8_lossy(&raw).to_string())
        .unwrap_or_default();

    let new_list = if current.is_empty() {
        key.as_str().to_string()
    } else {
        format!("{},{}", current, key.as_str())
    };
    meta.insert("windows", new_list.as_bytes()).unwrap();
    doc.commit();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_doc_has_meta_map() {
        let doc = create_root_doc("user1", "vault-abc", &[]);
        let meta = doc.get_or_create_map("meta");
        let vid = meta.get("vault_id").unwrap();
        assert_eq!(vid, b"vault-abc");
    }

    #[test]
    fn root_doc_schema_version() {
        let doc = create_root_doc("user1", "vault-abc", &[]);
        let meta = doc.get_or_create_map("meta");
        let sv = meta.get("schema_version").unwrap();
        assert_eq!(sv, 1i64.to_le_bytes());
    }

    #[test]
    fn window_doc_has_three_maps() {
        let key = WindowKey::new("2026-02");
        let doc = create_window_doc("user1", &key);

        let entities = doc.get_or_create_map("entities");
        let edges = doc.get_or_create_map("edges");
        let tombstones = doc.get_or_create_map("tombstones");

        // All maps should be empty
        let mut count = 0;
        entities.for_each(&mut |_, _| count += 1);
        assert_eq!(count, 0);

        count = 0;
        edges.for_each(&mut |_, _| count += 1);
        assert_eq!(count, 0);

        count = 0;
        tombstones.for_each(&mut |_, _| count += 1);
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
        let meta = doc.get_or_create_map("meta");
        let raw_windows = b"2026-01,,2026-13,garbage,2026-02";
        meta.insert("windows", raw_windows).unwrap();
        doc.commit();

        let windows = read_window_list(&doc);
        assert_eq!(
            windows,
            vec![WindowKey::new("2026-01"), WindowKey::new("2026-02")]
        );
        assert_eq!(meta.get("windows").unwrap().as_slice(), raw_windows);
    }
}
