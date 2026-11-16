//! A parted window row bound to its key (UC-10 PR 1; Engine RULING
//! UC10-PR1-PREMISE = A, 15 Nov 17:45). Four window maps carry a row past
//! its bound in parts: a manifest under the row's key and each part under
//! its digest (repo heads, document pins, room turns, room side rows). A
//! manifest names no id of the row: a room manifest is parts alone, a
//! parted pin its parts and actor, a repo head its CODE entity and parts.
//! So each family places a manifest, and the parts it lists, under the
//! holder its key names; only the joined row shows whose row it is.
//!
//! One group of captured values is judged at once: every version a window
//! capture or a discard projection met. Each manifest whose parts the group
//! all holds is joined and read as its map reads a joined row. A joined
//! row that is not the row its key names is a proven mismatch: the
//! checkpoint keeps the window whole with no owner hint, and the discard
//! projection defers the window. A manifest whose parts are not all held,
//! or join to bytes that read as no row of its map, proves nothing and
//! keeps its placement.

use std::collections::BTreeMap;

use loro::LoroValue;
use loro::checkpoint::{Classify, Field, OwnerId};

use super::SyncUnclassified;
use crate::store::checkpoint_payload::rows::OwnerRef;
use crate::sync::carrier_parts::{is_part_key, part_key};
use crate::sync::document_pins::DOCUMENT_PINS_MAP;
use crate::sync::repo_manifests::REPO_MANIFESTS_MAP;
use crate::sync::room_facts::ROOM_FACTS_MAP;
use crate::sync::room_turns::ROOM_TURNS_MAP;

/// The window maps that carry a row in parts.
const PARTED_MAPS: [&str; 4] = [
    REPO_MANIFESTS_MAP,
    DOCUMENT_PINS_MAP,
    ROOM_TURNS_MAP,
    ROOM_FACTS_MAP,
];

/// One parted map's values in a group: each value under a row key, and
/// each part filed under its own digest.
struct MapValues<B> {
    rows: Vec<(String, B)>,
    parts: BTreeMap<String, B>,
}

impl<B> Default for MapValues<B> {
    fn default() -> Self {
        Self {
            rows: Vec::new(),
            parts: BTreeMap::new(),
        }
    }
}

/// The parted maps' values of one group, in every version it met.
pub(in crate::sync) struct PartedRows<B> {
    maps: BTreeMap<&'static str, MapValues<B>>,
}

impl<B> Default for PartedRows<B> {
    fn default() -> Self {
        Self {
            maps: BTreeMap::new(),
        }
    }
}

impl<B: AsRef<[u8]>> PartedRows<B> {
    /// Notes the value `value` gives under `key` of the root map `root`:
    /// called, and its bytes taken, only for a parted map. A part enters
    /// only under its own digest, so a malformed old value under a part key
    /// cannot hide the right one.
    pub(in crate::sync) fn note(&mut self, root: &str, key: &str, value: impl FnOnce() -> B) {
        let Some(root) = PARTED_MAPS.into_iter().find(|map| *map == root) else {
            return;
        };
        let values = self.maps.entry(root).or_default();
        if is_part_key(key) {
            if values.parts.contains_key(key) {
                return;
            }
            let value = value();
            if part_key(blake3::hash(value.as_ref()).as_bytes()) == key {
                values.parts.insert(key.to_owned(), value);
            }
        } else {
            values.rows.push((key.to_owned(), value()));
        }
    }

    /// The first manifest the group proves is not the row its key names:
    /// its map and key. A map with no part held proves none: a manifest
    /// lists at least one part.
    pub(in crate::sync) fn mismatch(&self) -> Option<(&'static str, &str)> {
        self.maps
            .iter()
            .filter(|(_, values)| !values.parts.is_empty())
            .find_map(|(root, values)| {
                values
                    .rows
                    .iter()
                    .find(|(key, value)| bound(root, key, value.as_ref(), values) == Some(false))
                    .map(|(key, _)| (*root, key.as_str()))
            })
    }

    /// Why a checkpoint capture keeps the group's window whole on its
    /// parted rows: a proven mismatch names no owner; a repo head whose
    /// parts do not join to a manifest, but one of which the group holds,
    /// names its CODE entity, as before (FIX 10278).
    pub(super) fn capture_refusal(&self) -> Option<(Option<OwnerRef>, SyncUnclassified)> {
        if self.mismatch().is_some() {
            return Some((None, SyncUnclassified::Undecodable));
        }
        let heads = self.maps.get(REPO_MANIFESTS_MAP)?;
        heads.rows.iter().find_map(|(key, value)| {
            crate::sync::repo_manifests::checkpoint::unjoined_holder(key, value.as_ref(), |part| {
                heads.parts.get(part).map(AsRef::<[u8]>::as_ref)
            })
            .map(|owner| (Some(owner), SyncUnclassified::Undecodable))
        })
    }
}

/// Whether the value `value` under `key` of the parted map `root` is the
/// row its key names, its parts joined from `values`: `None` for a value
/// that is no manifest, for one whose parts do not all join, and for
/// joined bytes that read as no row of the map.
fn bound<B: AsRef<[u8]>>(
    root: &str,
    key: &str,
    value: &[u8],
    values: &MapValues<B>,
) -> Option<bool> {
    let part = |digest: &str| values.parts.get(digest).map(AsRef::<[u8]>::as_ref);
    match root {
        REPO_MANIFESTS_MAP => crate::sync::repo_manifests::checkpoint::bound(key, value, part),
        DOCUMENT_PINS_MAP => crate::sync::document_pins::checkpoint::bound(key, value, part),
        ROOM_TURNS_MAP => crate::sync::room_turns::checkpoint::bound(key, value, part),
        ROOM_FACTS_MAP => crate::sync::room_facts::checkpoint::bound(key, value, part),
        _ => None,
    }
}

/// A capture pass that places nothing and notes every parted map value
/// the window's history holds, for a capture whose own pass stopped at a
/// parted row's refusal.
#[derive(Default)]
pub(super) struct PartedCollector {
    pub(super) rows: PartedRows<Vec<u8>>,
}

impl Classify for PartedCollector {
    fn plain_key(&mut self, _: &str, _: &str) -> bool {
        true
    }

    fn holders(&mut self, field: Field<'_>) -> Option<Vec<OwnerId>> {
        if let Field::Value {
            root,
            key,
            value: LoroValue::Binary(bytes),
            ..
        } = field
        {
            self.rows.note(root, key, || bytes.to_vec());
        }
        Some(vec![0])
    }
}
