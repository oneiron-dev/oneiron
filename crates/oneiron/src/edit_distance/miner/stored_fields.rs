//! Explicit bounded field codecs for the miner's private JSON ledger.

use crate::entity_id::EntityId;
use rmpv::Value;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub(super) fn serialize_entity<S: Serializer>(id: &EntityId, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&id.to_hex())
}
pub(super) fn deserialize_entity<'de, D: Deserializer<'de>>(deserializer: D) -> Result<EntityId, D::Error> {
    EntityId::from_hex(&String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
}
pub(super) fn serialize_opt_entity<S: Serializer>(id: &Option<EntityId>, serializer: S) -> Result<S::Ok, S::Error> {
    id.as_ref().map(EntityId::to_hex).serialize(serializer)
}
pub(super) fn deserialize_opt_entity<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<EntityId>, D::Error> {
    Option::<String>::deserialize(deserializer)?.map(|id| EntityId::from_hex(&id).map_err(serde::de::Error::custom)).transpose()
}
pub(super) fn serialize_opt_value<S: Serializer>(value: &Option<Value>, serializer: S) -> Result<S::Ok, S::Error> {
    let bytes = value.as_ref().map(|value| {
        let mut bytes = Vec::new();
        rmpv::encode::write_value(&mut bytes, value).map_err(serde::ser::Error::custom)?;
        if bytes.len() > crate::memory::caps::MAX_ENTITY_PAYLOAD_BYTES {
            return Err(serde::ser::Error::custom("preference value exceeds entity limit"));
        }
        Ok::<_, S::Error>(bytes)
    }).transpose()?;
    bytes.serialize(serializer)
}
pub(super) fn deserialize_opt_value<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<Value>, D::Error> {
    Option::<Vec<u8>>::deserialize(deserializer)?.map(|bytes| {
        if bytes.len() > crate::memory::caps::MAX_ENTITY_PAYLOAD_BYTES {
            return Err(serde::de::Error::custom("preference value exceeds entity limit"));
        }
        let mut input = bytes.as_slice();
        let value = rmpv::decode::read_value(&mut input).map_err(serde::de::Error::custom)?;
        if !input.is_empty() { return Err(serde::de::Error::custom("trailing preference value")); }
        Ok(value)
    }).transpose()
}
