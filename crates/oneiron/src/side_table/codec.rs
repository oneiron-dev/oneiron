//! The value codecs a side table may declare. `Named` is the one codec; the legacy entries keep
//! the bytes rows written before the typed keyspace already carry.

use std::io::Cursor;

use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::entity_id::EntityId;
use crate::error::{Error, SideTableRowProblem};

use super::CodecName;

/// Why a codec refused a row: a shape problem the table names, or a value type's own error.
#[derive(Debug)]
pub(crate) enum CodecError {
    Row(SideTableRowProblem),
    Value(Error),
}

impl From<SideTableRowProblem> for CodecError {
    fn from(problem: SideTableRowProblem) -> Self {
        Self::Row(problem)
    }
}

impl From<Error> for CodecError {
    fn from(error: Error) -> Self {
        Self::Value(error)
    }
}

type CodecResult<T> = std::result::Result<T, CodecError>;

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

fn strict_msgpack<V: DeserializeOwned>(bytes: &[u8]) -> CodecResult<V> {
    let mut cursor = Cursor::new(bytes);
    let value = rmp_serde::decode::from_read(&mut cursor)
        .map_err(|_| CodecError::Row(SideTableRowProblem::Undecodable))?;
    if cursor.position() != bytes.len() as u64 {
        return Err(SideTableRowProblem::TrailingBytes.into());
    }
    Ok(value)
}

/// A value that spells its own byte layout. A layout with its own validation returns its own
/// error; a plain layout refuses with [`SideTableRowProblem::Undecodable`].
pub(crate) trait RawValue: Sized {
    fn to_raw(&self) -> CodecResult<Vec<u8>>;
    fn from_raw(bytes: &[u8]) -> CodecResult<Self>;
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

fn plain<T>(value: Option<T>) -> CodecResult<T> {
    value.ok_or(CodecError::Row(SideTableRowProblem::Undecodable))
}

impl RawValue for Vec<u8> {
    fn to_raw(&self) -> CodecResult<Vec<u8>> {
        Ok(self.clone())
    }

    fn from_raw(bytes: &[u8]) -> CodecResult<Self> {
        Ok(bytes.to_vec())
    }
}

/// A presence marker: the row's value is empty.
impl RawValue for () {
    fn to_raw(&self) -> CodecResult<Vec<u8>> {
        Ok(Vec::new())
    }

    fn from_raw(bytes: &[u8]) -> CodecResult<Self> {
        plain(bytes.is_empty().then_some(()))
    }
}

impl RawValue for EntityId {
    fn to_raw(&self) -> CodecResult<Vec<u8>> {
        Ok(self.as_bytes().to_vec())
    }

    fn from_raw(bytes: &[u8]) -> CodecResult<Self> {
        plain(
            bytes
                .try_into()
                .ok()
                .and_then(|raw| EntityId::from_bytes(raw).ok()),
        )
    }
}

impl<const N: usize> RawValue for [u8; N] {
    fn to_raw(&self) -> CodecResult<Vec<u8>> {
        Ok(self.to_vec())
    }

    fn from_raw(bytes: &[u8]) -> CodecResult<Self> {
        plain(bytes.try_into().ok())
    }
}

/// Big-endian eight bytes.
impl RawValue for u64 {
    fn to_raw(&self) -> CodecResult<Vec<u8>> {
        Ok(self.to_be_bytes().to_vec())
    }

    fn from_raw(bytes: &[u8]) -> CodecResult<Self> {
        plain(bytes.try_into().ok().map(u64::from_be_bytes))
    }
}

impl RawValue for String {
    fn to_raw(&self) -> CodecResult<Vec<u8>> {
        Ok(self.as_bytes().to_vec())
    }

    fn from_raw(bytes: &[u8]) -> CodecResult<Self> {
        plain(String::from_utf8(bytes.to_vec()).ok())
    }
}
