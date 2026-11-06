//! Value-preserving encoding for policy manifest rewrites. The stock rmpv
//! encoder writes invalid-UTF8 strings as binary; manifests must retain their kind.
use rmpv::Value;

use crate::{Error, Result};

pub(super) fn write_value(output: &mut Vec<u8>, value: &Value) -> Result<()> {
    let length = |size: usize| {
        u32::try_from(size).map_err(|_| {
            Error::InvalidConfig("value exceeds MessagePack's length range".to_owned())
        })
    };
    let header_error = |_| Error::InvalidConfig("policy manifest value header encoding".to_owned());
    match value {
        Value::String(value) if value.is_err() => {
            rmp::encode::write_str_len(output, length(value.as_bytes().len())?)
                .map_err(header_error)?;
            output.extend_from_slice(value.as_bytes());
        }
        Value::Array(values) => {
            rmp::encode::write_array_len(output, length(values.len())?).map_err(header_error)?;
            for value in values {
                write_value(output, value)?;
            }
        }
        Value::Map(entries) => {
            rmp::encode::write_map_len(output, length(entries.len())?).map_err(header_error)?;
            for (key, value) in entries {
                write_value(output, key)?;
                write_value(output, value)?;
            }
        }
        _ => rmpv::encode::write_value(output, value)
            .map_err(|_| Error::InvalidConfig("policy manifest value encoding".to_owned()))?,
    }
    Ok(())
}
