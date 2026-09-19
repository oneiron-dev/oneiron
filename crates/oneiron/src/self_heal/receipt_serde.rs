//! Strict serde adapters for ids and provenance in local healer receipts.
use crate::{EntityId, claim::ClaimSource};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error};
pub(super) mod id {
    use super::*;
    pub(in crate::self_heal) fn serialize<S: Serializer>(
        id: &EntityId,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        id.to_hex().serialize(s)
    }
    pub(in crate::self_heal) fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<EntityId, D::Error> {
        EntityId::from_hex(&String::deserialize(d)?).map_err(D::Error::custom)
    }
}
pub(super) mod ids {
    use super::*;
    pub(in crate::self_heal) fn serialize<S: Serializer>(
        ids: &[EntityId],
        s: S,
    ) -> Result<S::Ok, S::Error> {
        ids.iter()
            .map(EntityId::to_hex)
            .collect::<Vec<_>>()
            .serialize(s)
    }
    pub(in crate::self_heal) fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<Vec<EntityId>, D::Error> {
        Vec::<String>::deserialize(d)?
            .iter()
            .map(|v| EntityId::from_hex(v).map_err(D::Error::custom))
            .collect()
    }
}
pub(super) mod source {
    use super::*;
    pub(in crate::self_heal) fn serialize<S: Serializer>(
        source: &ClaimSource,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        source.as_str().serialize(s)
    }
    pub(in crate::self_heal) fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<ClaimSource, D::Error> {
        ClaimSource::parse(&String::deserialize(d)?)
            .ok_or_else(|| D::Error::custom("invalid claim source"))
    }
}

pub(super) mod value {
    use super::*;
    pub(in crate::self_heal) fn serialize<S: Serializer>(
        value: &rmpv::Value,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        let mut bytes = Vec::new();
        rmpv::encode::write_value(&mut bytes, value).map_err(serde::ser::Error::custom)?;
        bytes.serialize(s)
    }
    pub(in crate::self_heal) fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<rmpv::Value, D::Error> {
        let bytes = Vec::<u8>::deserialize(d)?;
        let mut cursor = std::io::Cursor::new(bytes.as_slice());
        let value = rmpv::decode::read_value(&mut cursor).map_err(D::Error::custom)?;
        if cursor.position() != bytes.len() as u64 {
            return Err(D::Error::custom("trailing value bytes"));
        }
        Ok(value)
    }
}
