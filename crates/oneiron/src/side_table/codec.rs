//! Core half of `side_table::codec`: its store-layer items live in `oneiron_store::side_table::codec` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::side_table::codec::*;

use super::CodecName;
use crate::entity_id::EntityId;
use crate::error::{Error, SideTableRowProblem};
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::io::Cursor;

/// How one table's values become bytes and back. A decode reads the whole row: trailing bytes,
/// a wrong version byte or a malformed body is a typed refusal, never a default.
pub(crate) trait SideCodec<V> {
    const NAME: CodecName;
    fn encode(value: &V) -> CodecResult<Vec<u8>>;
    fn decode(bytes: &[u8]) -> CodecResult<V>;
}

/// `rmp_serde::to_vec_named` on write, a strict whole-row decode on read (ARCH-0037:42).
pub(crate) enum Named {}

impl<V: Serialize + DeserializeOwned> SideCodec<V> for Named {
    const NAME: CodecName = CodecName::Named;

    fn encode(value: &V) -> CodecResult<Vec<u8>> {
        rmp_serde::to_vec_named(value)
            .map_err(|_| CodecError::Row(SideTableRowProblem::Unencodable))
    }

    fn decode(bytes: &[u8]) -> CodecResult<V> {
        strict_msgpack(bytes)
    }
}

/// One leading version byte, then [`Named`]. A row carrying any other version byte is refused.
pub(crate) enum VersionedNamed<const VERSION: u8> {}

impl<V: Serialize + DeserializeOwned, const VERSION: u8> SideCodec<V> for VersionedNamed<VERSION> {
    const NAME: CodecName = CodecName::VersionedNamed;

    fn encode(value: &V) -> CodecResult<Vec<u8>> {
        let mut out = vec![VERSION];
        rmp_serde::encode::write_named(&mut out, value)
            .map_err(|_| CodecError::Row(SideTableRowProblem::Unencodable))?;
        Ok(out)
    }

    fn decode(bytes: &[u8]) -> CodecResult<V> {
        match bytes.split_first() {
            Some((&found, body)) if found == VERSION => strict_msgpack(body),
            Some((&found, _)) => Err(SideTableRowProblem::UnknownVersion {
                found,
                expected: VERSION,
            }
            .into()),
            None => Err(SideTableRowProblem::Undecodable.into()),
        }
    }
}

/// Legacy: `serde_json`, kept for tables whose rows were JSON before the typed keyspace.
pub(crate) enum LegacyJson {}

impl<V: Serialize + DeserializeOwned> SideCodec<V> for LegacyJson {
    const NAME: CodecName = CodecName::LegacyJson;

    fn encode(value: &V) -> CodecResult<Vec<u8>> {
        serde_json::to_vec(value).map_err(|_| CodecError::Row(SideTableRowProblem::Unencodable))
    }

    fn decode(bytes: &[u8]) -> CodecResult<V> {
        serde_json::from_slice(bytes).map_err(|_| CodecError::Row(SideTableRowProblem::Undecodable))
    }
}

/// Legacy: positional `rmp_serde::to_vec`, kept for tables whose rows were compact MessagePack.
pub(crate) enum LegacyCompact {}

impl<V: Serialize + DeserializeOwned> SideCodec<V> for LegacyCompact {
    const NAME: CodecName = CodecName::LegacyCompact;

    fn encode(value: &V) -> CodecResult<Vec<u8>> {
        rmp_serde::to_vec(value).map_err(|_| CodecError::Row(SideTableRowProblem::Unencodable))
    }

    fn decode(bytes: &[u8]) -> CodecResult<V> {
        strict_msgpack(bytes)
    }
}

/// A byte layout the value type spells itself.
pub(crate) enum Raw {}

impl<V: RawValue> SideCodec<V> for Raw {
    const NAME: CodecName = CodecName::Raw;

    fn encode(value: &V) -> CodecResult<Vec<u8>> {
        value.to_raw()
    }

    fn decode(bytes: &[u8]) -> CodecResult<V> {
        V::from_raw(bytes)
    }
}
