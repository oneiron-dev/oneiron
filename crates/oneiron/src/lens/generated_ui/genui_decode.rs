//! The staged version boundary every generated-UI envelope crosses first
//! (FIX 7967; CALLS "FIX 7967 7970 fallback outcome"): the protocol version
//! and the whole-card fallback are read before any typed tree or catalog
//! decoding. A version this build does not know yields its fallback text
//! alone, its body never read; a supported one decodes and validates whole,
//! with its structural errors as before.

use serde::de::DeserializeOwned;
use serde_json::Value;

use super::{GENERATED_UI_WIRE_VERSION, GeneratedUiCard, GeneratedUiRender};
use crate::lens::atom::LensText;
use crate::lens::validate::validate_required_lens_text;
use crate::{Error, Result};

/// The whole card as text, from an envelope whose `protocolVersion` this
/// build does not know. It is not a card: it carries no tree, action or
/// backing ref, and nothing on it can be acted on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedUiFallback {
    pub protocol_version: u64,
    pub fallback_text: LensText,
}

/// What an envelope decodes to: the typed value of a supported protocol
/// version, or only the fallback text of an unsupported one.
#[derive(Debug, Clone, PartialEq)]
pub enum GeneratedUiDecoded<T> {
    Supported(T),
    Fallback(GeneratedUiFallback),
}

impl GeneratedUiCard {
    /// One card envelope from JSON text, version first.
    pub fn decode_json(text: &str) -> Result<GeneratedUiDecoded<Self>> {
        decode_staged(parse(text)?, "card")
    }
}

impl GeneratedUiRender {
    /// One flat render envelope from JSON text, version first.
    pub fn decode_json(text: &str) -> Result<GeneratedUiDecoded<Self>> {
        decode_staged(parse(text)?, "render")
    }
}

fn parse(text: &str) -> Result<Value> {
    serde_json::from_str(text)
        .map_err(|error| Error::InvalidConfig(format!("generated-ui envelope is not JSON: {error}")))
}

/// Decode `value` as `T` when its `protocolVersion` is this build's, else
/// return its whole-card fallback.
pub(super) fn decode_staged<T: DeserializeOwned>(
    value: Value,
    kind: &str,
) -> Result<GeneratedUiDecoded<T>> {
    if let Some(fallback) = unsupported_fallback(&value, kind)? {
        return Ok(GeneratedUiDecoded::Fallback(fallback));
    }
    serde_json::from_value(value)
        .map(GeneratedUiDecoded::Supported)
        .map_err(|error| Error::InvalidConfig(format!("generated-ui {kind}: {error}")))
}

/// The fallback of an envelope that names a protocol version other than
/// this build's; `None` when it names this build's, or none, which the
/// typed decode then judges.
pub(super) fn unsupported_fallback(value: &Value, kind: &str) -> Result<Option<GeneratedUiFallback>> {
    let Some(protocol_version) = value.get("protocolVersion").and_then(Value::as_u64) else {
        return Ok(None);
    };
    if protocol_version == u64::from(GENERATED_UI_WIRE_VERSION) {
        return Ok(None);
    }
    let fallback_text = value
        .get("fallbackText")
        .and_then(Value::as_str)
        .map(LensText::new)
        .transpose()?
        .ok_or_else(|| {
            Error::InvalidConfig(format!(
                "generated-ui {kind} of unsupported wire version {protocol_version} must carry its whole-card fallbackText"
            ))
        })?;
    validate_required_lens_text("generated-ui unsupported-version fallbackText", &fallback_text)?;
    Ok(Some(GeneratedUiFallback {
        protocol_version,
        fallback_text,
    }))
}
