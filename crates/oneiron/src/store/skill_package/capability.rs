//! Stored capability surface encoding.

use super::SkillCapabilitySurface;
use super::package::MAX_CAPABILITY_TEXT_BYTES;
use crate::error::{ArtifactError, Error, Result};
use crate::side_table::{CodecError, RawValue};
use crate::write_envelope::skill_source::support::{
    decode_value, encode_value, exact_map, required_value, validate_text,
};
use rmpv::Value;
use std::collections::BTreeSet;

impl RawValue for SkillCapabilitySurface {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok(encode_value(
            &encode_capability_surface_value(self),
            "capability surface MessagePack encode failed",
        )?)
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        Ok(decode_capability_surface(bytes)?)
    }
}

pub(crate) fn encode_capability_surface_value(surface: &SkillCapabilitySurface) -> Value {
    Value::Map(vec![
        (Value::from("bins"), string_set_value(&surface.bins)),
        (Value::from("env"), string_set_value(&surface.env)),
        (Value::from("mcp"), string_set_value(&surface.mcp)),
        (
            Value::from("allowedTools"),
            string_set_value(&surface.allowed_tools),
        ),
    ])
}

fn decode_capability_surface(bytes: &[u8]) -> Result<SkillCapabilitySurface> {
    const KEYS: [&str; 4] = ["bins", "env", "mcp", "allowedTools"];
    let value = decode_value(bytes, "invalid admitted capability surface")?;
    let entries = exact_map(&value, &KEYS, "invalid admitted capability surface")?;
    let surface = SkillCapabilitySurface {
        bins: decode_string_set(required_value(
            entries,
            KEYS[0],
            "invalid admitted capability surface",
        )?)?,
        env: decode_string_set(required_value(
            entries,
            KEYS[1],
            "invalid admitted capability surface",
        )?)?,
        mcp: decode_string_set(required_value(
            entries,
            KEYS[2],
            "invalid admitted capability surface",
        )?)?,
        allowed_tools: decode_string_set(required_value(
            entries,
            KEYS[3],
            "invalid admitted capability surface",
        )?)?,
    };
    surface.validate()?;
    Ok(surface)
}

fn string_set_value(values: &BTreeSet<String>) -> Value {
    Value::Array(
        values
            .iter()
            .map(|value| Value::from(value.as_str()))
            .collect(),
    )
}

fn decode_string_set(value: &Value) -> Result<BTreeSet<String>> {
    let Value::Array(values) = value else {
        return Err(Error::Artifact(ArtifactError::InvalidSkillBody(
            "capability entries must be an array",
        )));
    };
    let mut decoded = BTreeSet::new();
    for value in values {
        let text = value
            .as_str()
            .ok_or(Error::Artifact(ArtifactError::InvalidSkillBody(
                "capability entry must be text",
            )))?;
        validate_text(
            text,
            MAX_CAPABILITY_TEXT_BYTES,
            "capability entries must be non-empty",
        )?;
        if !decoded.insert(text.to_owned()) {
            return Err(Error::Artifact(ArtifactError::InvalidSkillBody(
                "duplicate capability entry",
            )));
        }
    }
    Ok(decoded)
}
