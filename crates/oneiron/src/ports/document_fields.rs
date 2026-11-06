//! Core half of `ports::document_fields`: its store-layer items live in `oneiron_store::ports::document_fields` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::ports::document_fields::*;

use crate::{Error, Result};
use rmpv::Value;

pub(crate) fn validate_metadata(field: &str, value: &Value) -> Result<()> {
    validate_metadata_shape(field, value)?;
    scan_value(value)
}

pub(crate) fn validate_metadata_shape(field: &str, value: &Value) -> Result<()> {
    let mut tag_next = 0;
    while !advance_metadata_shape(field, value, &mut tag_next)? {}
    Ok(())
}

pub(crate) fn advance_metadata_shape(
    field: &str,
    value: &Value,
    tag_next: &mut usize,
) -> Result<bool> {
    let invalid_value = || invalid("invalid editable metadata field or value");
    let valid = match field {
        "tags" => {
            let tags = value.as_array().ok_or_else(invalid_value)?;
            if let Some(tag) = tags.get(*tag_next) {
                if tag.as_str().is_none() {
                    return Err(invalid_value());
                }
                *tag_next += 1;
                return Ok(false);
            }
            true
        }
        "pins" => value.as_array().is_some(),
        _ => is_metadata_field(field) && (value.is_nil() || value.as_str().is_some()),
    };
    if !valid {
        return Err(invalid_value());
    }
    Ok(true)
}

pub(crate) fn scan_metadata_string(text: &rmpv::Utf8String) -> Result<()> {
    crate::batch::secret_scan::scan_metadata_field(
        text.as_str().ok_or(invalid("metadata is not UTF-8"))?,
    )
}

fn scan_value(value: &Value) -> Result<()> {
    match value {
        Value::String(text) => scan_metadata_string(text)?,
        Value::Array(values) => {
            for value in values {
                scan_value(value)?;
            }
        }
        Value::Map(fields) => {
            for (key, value) in fields {
                scan_value(key)?;
                scan_value(value)?;
            }
        }
        _ => {}
    }
    Ok(())
}
