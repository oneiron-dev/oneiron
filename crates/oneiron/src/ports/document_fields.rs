//! Core half of `ports::document_fields`: its store-layer items live in `oneiron_store::ports::document_fields` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::ports::document_fields::*;

use crate::{Error, Result};
use rmpv::Value;

pub(crate) fn validate_metadata(field: &str, value: &Value) -> Result<()> {
    let valid = match field {
        "tags" => value
            .as_array()
            .is_some_and(|tags| tags.iter().all(|tag| tag.as_str().is_some())),
        "pins" => value.as_array().is_some(),
        _ => is_metadata_field(field) && (value.is_nil() || value.as_str().is_some()),
    };
    if !valid {
        return Err(invalid("invalid editable metadata field or value"));
    }
    scan_value(value)
}

fn scan_value(value: &Value) -> Result<()> {
    match value {
        Value::String(text) => {
            crate::batch::secret_scan::scan_metadata_field(
                text.as_str().ok_or(invalid("metadata is not UTF-8"))?,
            )?;
        }
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
