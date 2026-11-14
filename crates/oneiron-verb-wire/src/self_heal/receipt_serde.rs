//! Moved from `crates/oneiron/src/self_heal/receipt_serde.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use serde::Serializer;
use serde::de::Error;

pub mod id {
    use super::*;
    pub fn serialize<S: Serializer>(id: &EntityId, s: S) -> Result<S::Ok, S::Error> {
        id.to_hex().serialize(s)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<EntityId, D::Error> {
        EntityId::from_hex(&String::deserialize(d)?).map_err(D::Error::custom)
    }
}
