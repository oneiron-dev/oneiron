//! The value codecs a side table may declare. `Named` is the one codec; the legacy entries keep
//! the bytes rows written before the typed keyspace already carry.

use std::io::Cursor;

use serde::Serialize;
use serde::de::DeserializeOwned;

use oneiron_base::error::Error;
use oneiron_base::error::SideTableRowProblem;
use oneiron_contracts::entity_id::EntityId;

/// Why a codec refused a row: a shape problem the table names, or a value type's own error.
#[derive(Debug)]
pub enum CodecError {
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

pub type CodecResult<T> = std::result::Result<T, CodecError>;

pub fn strict_msgpack<V: DeserializeOwned>(bytes: &[u8]) -> CodecResult<V> {
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
pub trait RawValue: Sized {
    fn to_raw(&self) -> CodecResult<Vec<u8>>;
    fn from_raw(bytes: &[u8]) -> CodecResult<Self>;
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
