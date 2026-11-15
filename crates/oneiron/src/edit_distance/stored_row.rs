//! The MessagePack codec of the edit-distance stored rows (PLAN-UC-08 PR 1): one typed-row encoder and
//! decoder over [`oneiron_contracts::msgpack`], and the one `RawValue` impl of a row gated on its schema
//! version field `v`. A row with bytes after it does not decode.

use oneiron_contracts::msgpack;
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::error::{Error, Result};

/// `row` as MessagePack, fields keyed by name; a row that does not serialize is
/// [`Error::InvariantViolation`] with `label`.
pub(super) fn encode_row<T: Serialize>(row: &T, label: &'static str) -> Result<Vec<u8>> {
    msgpack::encode_row(row).map_err(|_| Error::InvariantViolation(label))
}

/// The one typed row in `raw`; bytes that are not exactly one row (a trailer included) are
/// [`Error::CorruptedIndex`] with `label`.
pub(super) fn decode_row<T: DeserializeOwned>(raw: &[u8], label: &'static str) -> Result<T> {
    msgpack::decode_row(raw).map_err(|_| Error::CorruptedIndex(label))
}

/// `impl RawValue for $ty`: the row through [`encode_row`] and [`decode_row`] under `$label`, and a
/// decoded row whose `v` is not `$version` refused as [`Error::CorruptedIndex`] with `$label`.
macro_rules! versioned_row_codec {
    ($ty:ty, $label:expr, $version:expr) => {
        impl $crate::side_table::RawValue for $ty {
            fn to_raw(&self) -> ::std::result::Result<Vec<u8>, $crate::side_table::CodecError> {
                Ok($crate::edit_distance::stored_row::encode_row(self, $label)?)
            }

            fn from_raw(
                bytes: &[u8],
            ) -> ::std::result::Result<Self, $crate::side_table::CodecError> {
                let row: $ty = $crate::edit_distance::stored_row::decode_row(bytes, $label)?;
                if row.v != $version {
                    return Err($crate::side_table::CodecError::Value(
                        $crate::error::Error::CorruptedIndex($label),
                    ));
                }
                Ok(row)
            }
        }
    };
}

pub(super) use versioned_row_codec;
