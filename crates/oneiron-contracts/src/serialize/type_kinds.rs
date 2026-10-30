//! The wire spelling of a scope's entity types (FIX 10762): each type byte
//! as its registry kind, and a byte the static registry does not name (a
//! pack's own type) as its decimal number, so no receipt fails to spell.
//! Read back the same way.
//!
//! `#[serde(with = ...)]` target. Public so the read filter inputs in
//! `oneiron` spell their types the way the receipt does (FIX 11745).

use std::collections::BTreeSet;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::registry::{ENTITY_TYPE_REGISTRY, entity_type_registry_entry};

pub fn kind(entity_type: u8) -> String {
    entity_type_registry_entry(entity_type)
        .map_or_else(|| entity_type.to_string(), |entry| entry.kind.to_owned())
}

fn type_byte(kind: &str) -> Option<u8> {
    ENTITY_TYPE_REGISTRY
        .iter()
        .find(|entry| entry.kind == kind)
        .map(|entry| entry.type_byte)
        .or_else(|| kind.parse().ok())
}

pub fn serialize<S: Serializer>(
    types: &Option<BTreeSet<u8>>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    types
        .as_ref()
        .map(|types| types.iter().copied().map(kind).collect::<Vec<_>>())
        .serialize(serializer)
}

pub fn deserialize<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<BTreeSet<u8>>, D::Error> {
    Option::<Vec<String>>::deserialize(deserializer)?
        .map(|kinds| {
            kinds
                .iter()
                .map(|kind| {
                    type_byte(kind).ok_or_else(|| {
                        <D::Error as serde::de::Error>::custom(format!(
                            "unknown entity kind {kind}"
                        ))
                    })
                })
                .collect()
        })
        .transpose()
}
