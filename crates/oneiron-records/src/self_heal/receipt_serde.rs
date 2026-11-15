//! Moved from `crates/oneiron/src/self_heal/receipt_serde.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::claim::ClaimSource;
use oneiron_contracts::entity_id::EntityId;
pub(super) use oneiron_verb_wire::self_heal::receipt_serde::id;
use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use serde::Serializer;
use serde::de::Error;

pub mod ids {
    use super::*;
    pub fn serialize<S: Serializer>(ids: &[EntityId], s: S) -> Result<S::Ok, S::Error> {
        ids.iter()
            .map(EntityId::to_hex)
            .collect::<Vec<_>>()
            .serialize(s)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<EntityId>, D::Error> {
        Vec::<String>::deserialize(d)?
            .iter()
            .map(|v| EntityId::from_hex(v).map_err(D::Error::custom))
            .collect()
    }
}

pub mod source {
    use super::*;
    pub fn serialize<S: Serializer>(source: &ClaimSource, s: S) -> Result<S::Ok, S::Error> {
        source.as_str().serialize(s)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<ClaimSource, D::Error> {
        ClaimSource::parse(&String::deserialize(d)?)
            .ok_or_else(|| D::Error::custom("invalid claim source"))
    }
}

pub mod value {
    use super::*;
    pub fn serialize<S: Serializer>(value: &rmpv::Value, s: S) -> Result<S::Ok, S::Error> {
        let mut bytes = Vec::new();
        rmpv::encode::write_value(&mut bytes, value).map_err(serde::ser::Error::custom)?;
        bytes.serialize(s)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<rmpv::Value, D::Error> {
        let bytes = Vec::<u8>::deserialize(d)?;
        let mut cursor = std::io::Cursor::new(bytes.as_slice());
        let value = rmpv::decode::read_value(&mut cursor).map_err(D::Error::custom)?;
        if cursor.position() != bytes.len() as u64 {
            return Err(D::Error::custom("trailing value bytes"));
        }
        Ok(value)
    }
}
