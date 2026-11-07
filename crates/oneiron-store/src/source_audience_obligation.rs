//! The source-audience obligation (fix list row 16256): one engine-owned key
//! in a bound row's own MessagePack body, saying the row reads only under the
//! source audience its binding names. The engine's source landing stamps it
//! on every CONVERSATION, TURN and MESSAGE it binds; the source-audience
//! judge reads it from the row's own bytes, whatever the row's kind and
//! whether or not its TURN or `PartOf` edge has arrived.
//!
//! This module is the vocabulary and the strict codec only. It grants no
//! authority: who may stamp a row is the engine's source landing alone.

use oneiron_base::error::{Error, Result};
use rmpv::ValueRef;

/// The top-level body key. Its one valid value is MessagePack Boolean
/// `true`; it always comes last in an engine-stamped body.
pub const SOURCE_AUDIENCE_REQUIRED_KEY: &str = "source_audience_required";

/// What one body says about the obligation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceAudienceObligation {
    /// The body is no MessagePack map, or its map does not name the key.
    Absent,
    /// The map names the key exactly once, as a string, with Boolean `true`,
    /// and holds no trailing bytes.
    Required,
    /// The key is present in any other shape: another value, a second copy,
    /// a non-string key spelling it, or a map followed by trailing bytes.
    /// A reader treats this as a row a source landed.
    Malformed,
}

impl SourceAudienceObligation {
    /// Whether the body names the obligation in any shape.
    #[must_use]
    pub const fn is_present(self) -> bool {
        !matches!(self, Self::Absent)
    }
}

/// The obligation one MessagePack body states, decoded strictly.
#[must_use]
pub fn decode_source_audience_obligation(body: &[u8]) -> SourceAudienceObligation {
    let mut cursor = body;
    let Ok(ValueRef::Map(entries)) = rmpv::decode::read_value_ref(&mut cursor) else {
        return SourceAudienceObligation::Absent;
    };
    let mut found = SourceAudienceObligation::Absent;
    for (key, value) in &entries {
        let (spelled, string_key) = match key {
            ValueRef::String(name) => (name.as_bytes(), true),
            ValueRef::Binary(bytes) | ValueRef::Ext(_, bytes) => (*bytes, false),
            _ => continue,
        };
        if spelled != SOURCE_AUDIENCE_REQUIRED_KEY.as_bytes() {
            continue;
        }
        found = match (found, string_key, value) {
            (SourceAudienceObligation::Absent, true, ValueRef::Boolean(true)) => {
                SourceAudienceObligation::Required
            }
            _ => SourceAudienceObligation::Malformed,
        };
    }
    if found == SourceAudienceObligation::Required && !cursor.is_empty() {
        return SourceAudienceObligation::Malformed;
    }
    found
}

/// `body`, a MessagePack map that does not name the obligation, with the
/// key appended last as `true`. The map's own entries keep their exact
/// bytes; only its length header is rewritten.
///
/// # Errors
///
/// [`Error::InvariantViolation`] when `body` is not exactly one MessagePack
/// map, or already names the key in any shape.
pub fn encode_source_audience_required(body: &[u8]) -> Result<Vec<u8>> {
    let refused = || Error::InvariantViolation("a source-audience stamp goes on one unstamped map");
    let mut cursor = body;
    let Ok(ValueRef::Map(entries)) = rmpv::decode::read_value_ref(&mut cursor) else {
        return Err(refused());
    };
    if !cursor.is_empty() || decode_source_audience_obligation(body).is_present() {
        return Err(refused());
    }
    let header = match body.first() {
        Some(0x80..=0x8f) => 1,
        Some(0xde) => 3,
        Some(0xdf) => 5,
        _ => return Err(refused()),
    };
    let len = u32::try_from(entries.len())
        .ok()
        .and_then(|len| len.checked_add(1))
        .ok_or_else(refused)?;
    let mut out = Vec::with_capacity(body.len() + SOURCE_AUDIENCE_REQUIRED_KEY.len() + 8);
    match len {
        0..=15 => out.push(0x80 | u8::try_from(len).map_err(|_| refused())?),
        16..=0xffff => {
            out.push(0xde);
            out.extend_from_slice(&u16::try_from(len).map_err(|_| refused())?.to_be_bytes());
        }
        _ => {
            out.push(0xdf);
            out.extend_from_slice(&len.to_be_bytes());
        }
    }
    out.extend_from_slice(body.get(header..).ok_or_else(refused)?);
    rmpv::encode::write_value_ref(
        &mut out,
        &ValueRef::String(SOURCE_AUDIENCE_REQUIRED_KEY.into()),
    )
    .map_err(|_| refused())?;
    rmpv::encode::write_value_ref(&mut out, &ValueRef::Boolean(true)).map_err(|_| refused())?;
    Ok(out)
}
