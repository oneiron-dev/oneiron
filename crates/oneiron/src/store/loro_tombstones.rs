//! The tombstones-map reads a delete-wins gate makes: presence and values of
//! every key that names an entity, under the tombstone value rule, and the
//! per-pass index over them. `sync::loro_support` re-exports each item.

use std::collections::HashMap;

use loro::{LoroMap, LoroValue, ValueOrContainer};

use crate::entity_id::EntityId;

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
    map.get(key).map(tombstone_value_bytes)
}

fn tombstone_value_bytes(value: ValueOrContainer) -> Vec<u8> {
    match value {
        ValueOrContainer::Value(LoroValue::Binary(bytes)) => bytes.to_vec(),
        _ => Vec::new(),
    }
}

/// The tombstones map read once for one sync pass (H15). The map is peer-sized: a pass that
/// rescanned it for every entity and edge it checks does O(carriers × tombstones) work, so the
/// index parses each key once when it is built.
///
/// Canonical lowercase keys are read live, so a tombstone this pass writes is seen at once. The
/// case-shifted aliases are a snapshot: only an import writes or removes them (local doors write
/// `to_hex` keys and never delete a tombstone), so build the index after the import a pass reads
/// and never hold it across one. An import into a shared live document from another thread can
/// still land mid-pass, as it could between any carrier's check and its write before: the
/// replay of the tombstone it brings purges a carrier the pass admitted. Presence and values
/// follow [`tombstone_map_contains_id`] and [`tombstone_values_for_id`] exactly.
pub(crate) struct TombstoneIndex {
    map: LoroMap,
    /// The value of every non-canonical key that parses to an id, keyed by that id, in map
    /// order and under the tombstone value rule.
    aliases: HashMap<EntityId, Vec<Vec<u8>>>,
}

impl TombstoneIndex {
    pub(crate) fn build(map: &LoroMap) -> Self {
        let mut aliases = HashMap::<EntityId, Vec<Vec<u8>>>::new();
        map.for_each(|key, value| {
            // A key that parses is 32 hex digits: it is the canonical `to_hex` spelling unless a
            // digit is uppercase.
            if let Some(id) = parse_tombstone_key(key)
                && key.bytes().any(|byte| byte.is_ascii_uppercase())
            {
                aliases
                    .entry(id)
                    .or_default()
                    .push(tombstone_value_bytes(value));
            }
        });
        Self {
            map: map.clone(),
            aliases,
        }
    }

    /// The map this index reads.
    pub(crate) fn map(&self) -> &LoroMap {
        &self.map
    }

    /// Whether any key names `id`, under ANY value (fail closed).
    pub(crate) fn contains(&self, id: &EntityId) -> bool {
        map_contains_key(&self.map, &id.to_hex()) || self.aliases.contains_key(id)
    }

    /// Whether a non-canonical key names `id`.
    pub(crate) fn has_alias(&self, id: &EntityId) -> bool {
        self.aliases.contains_key(id)
    }

    /// The values of EVERY key naming `id`: the canonical key's first, then each alias's.
    pub(crate) fn values_for(&self, id: &EntityId) -> Vec<Vec<u8>> {
        let mut values = Vec::new();
        if let Some(value) = map_get_tombstone_value(&self.map, &id.to_hex()) {
            values.push(value);
        }
        if let Some(aliased) = self.aliases.get(id) {
            values.extend(aliased.iter().cloned());
        }
        values
    }
}

/// Entity-canonical presence check for tombstone maps. Map keys are raw
/// remote strings and `EntityId::from_hex` accepts BOTH hex casings while
/// `to_hex` emits lowercase — so an exact lowercase get is blind to a
/// crafted UPPERCASE-hex tombstone key and a delete-wins gate would fail
/// OPEN. Fast path: the canonical lowercase key. On miss: scan the map and
/// treat ANY key that parses to the same `EntityId` as present (fail
/// closed). This scans the map on a miss: a pass that checks many ids
/// shares one [`TombstoneIndex`] instead. Entities/edges maps must keep
/// using the Binary-only helpers.
pub(crate) fn tombstone_map_contains_id(map: &LoroMap, id: &EntityId) -> bool {
    if map_contains_key(map, &id.to_hex()) {
        return true;
    }
    let mut present = false;
    map.for_each(|key, _| {
        if !present && parse_tombstone_key(key).is_some_and(|parsed| parsed == *id) {
            present = true;
        }
    });
    present
}

/// Collects the tombstones-map values of EVERY key aliasing `id` — the
/// canonical lowercase key plus any case-shifted hex alias — each read
/// under the tombstone value rule (Binary passes its bytes; a PRESENT
/// non-Binary value yields the EMPTY vec, which decodes HARD downstream).
/// A single-shot read: a pass that checks many ids shares one [`TombstoneIndex`].
pub(crate) fn tombstone_values_for_id(map: &LoroMap, id: &EntityId) -> Vec<Vec<u8>> {
    let canonical = id.to_hex();
    let mut values = Vec::new();
    if let Some(value) = map_get_tombstone_value(map, &canonical) {
        values.push(value);
    }
    map.for_each(|key, value| {
        if key != canonical && parse_tombstone_key(key).is_some_and(|parsed| parsed == *id) {
            values.push(tombstone_value_bytes(value));
        }
    });
    values
}

fn parse_tombstone_key(key: &str) -> Option<EntityId> {
    #[cfg(test)]
    TOMBSTONE_KEY_PARSES.with(|parses| parses.set(parses.get() + 1));
    EntityId::from_hex(key).ok()
}

#[cfg(test)]
thread_local! {
    /// Tombstone keys this thread parsed as entity ids: the H15 work pin.
    pub(crate) static TOMBSTONE_KEY_PARSES: std::cell::Cell<u64> =
        const { std::cell::Cell::new(0) };
}
