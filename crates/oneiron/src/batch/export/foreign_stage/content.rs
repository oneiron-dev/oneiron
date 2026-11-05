//! Admitted window bytes and their born-with text, retained together while
//! a foreign import is Pending. The receipt binds the whole carrier.

use crate::error::{Error, Result};
use crate::sync::selector::CarriedText;
use crate::window_key::WindowKey;

const CONTENT_ERR: &str = "staged import content";

pub(crate) struct StagedWindowPart {
    pub(crate) key: WindowKey,
    pub(crate) update: Vec<u8>,
    pub(crate) born_with: Vec<CarriedText>,
}

/// Each ordered part keeps its exact update and the text admission allowed
/// beside its rows. Neither the text nor this carrier is a pact credential.
pub(crate) fn encode_staged_import_parts(parts: &[StagedWindowPart]) -> Result<Vec<u8>> {
    let mut items = Vec::with_capacity(parts.len());
    for part in parts {
        let text = rmp_serde::to_vec_named(&part.born_with)
            .map_err(|_| Error::CorruptedIndex(CONTENT_ERR))?;
        items.push(rmpv::Value::Array(vec![
            rmpv::Value::from(part.key.as_str()),
            rmpv::Value::Binary(part.update.clone()),
            rmpv::Value::Binary(text),
        ]));
    }
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &rmpv::Value::Array(items))
        .map_err(|_| Error::CorruptedIndex(CONTENT_ERR))?;
    Ok(out)
}

/// Reads the closed CONTENT carrier. STAMPS keeps its separate two-field
/// window-record codec; no old CONTENT form is accepted here.
pub(crate) fn decode_staged_import_parts(raw: &[u8]) -> Result<Vec<StagedWindowPart>> {
    let err = || Error::CorruptedIndex(CONTENT_ERR);
    let mut cursor = std::io::Cursor::new(raw);
    let value = rmpv::decode::read_value(&mut cursor).map_err(|_| err())?;
    if cursor.position() != raw.len() as u64 {
        return Err(err());
    }
    let rmpv::Value::Array(items) = value else {
        return Err(err());
    };
    if items.is_empty() {
        return Err(err());
    }
    let mut seen = std::collections::HashSet::new();
    let mut parts = Vec::with_capacity(items.len());
    for item in items {
        let rmpv::Value::Array(fields) = item else {
            return Err(err());
        };
        let [key, update, text] = fields.as_slice() else {
            return Err(err());
        };
        let Some(key) = key.as_str().and_then(WindowKey::try_new) else {
            return Err(err());
        };
        let (rmpv::Value::Binary(update), rmpv::Value::Binary(text)) = (update, text) else {
            return Err(err());
        };
        if !seen.insert(key.as_str().to_owned()) {
            return Err(err());
        }
        let born_with: Vec<CarriedText> = rmp_serde::from_slice(text).map_err(|_| err())?;
        if rmp_serde::to_vec_named(&born_with).map_err(|_| err())? != *text {
            return Err(err());
        }
        parts.push(StagedWindowPart {
            key,
            update: update.clone(),
            born_with,
        });
    }
    Ok(parts)
}
