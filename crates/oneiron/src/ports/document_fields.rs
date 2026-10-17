//! Field vocabulary shared by document writes and value-based recovery.

use crate::{Error, Result};
use rmpv::Value;

fn invalid(reason: &'static str) -> Error {
    crate::error::ArtifactError::InvalidEditManifest(reason).into()
}

/// Editable labels and prose, never identity, scope, authority or claim values.
pub(crate) fn is_metadata_field(field: &str) -> bool {
    matches!(
        field,
        "title"
            | "tags"
            | "kind_label"
            | "pins"
            | "keep"
            | "name"
            | "label"
            | "description"
            | "desc"
            | "summary"
            | "instructions"
            | "why"
    )
}

pub(crate) fn is_text_field(field: &str) -> bool {
    matches!(field, "body" | "text" | "txt" | "content" | "markdown")
        || (is_metadata_field(field) && !matches!(field, "tags" | "pins"))
}

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
