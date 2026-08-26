use std::io::Cursor;

use rmpv::Value;

use crate::error::{Error, Result};

pub(super) const MAX_HUB_TEXT_BYTES: usize = 4096;

pub(super) fn exact_map<'a>(
    value: &'a Value,
    keys: &[&str],
    context: &'static str,
) -> Result<&'a [(Value, Value)]> {
    let Value::Map(entries) = value else {
        return Err(Error::InvalidSkillBody(context));
    };
    let mut seen = vec![false; keys.len()];
    for (key, _) in entries {
        let key = key.as_str().ok_or(Error::InvalidSkillBody(context))?;
        let Some(index) = keys.iter().position(|known| *known == key) else {
            return Err(Error::InvalidSkillBody(context));
        };
        if seen[index] {
            return Err(Error::InvalidSkillBody(context));
        }
        seen[index] = true;
    }
    if seen.into_iter().all(|present| present) {
        Ok(entries)
    } else {
        Err(Error::InvalidSkillBody(context))
    }
}

pub(super) fn required_value<'a>(
    entries: &'a [(Value, Value)],
    key: &str,
    context: &'static str,
) -> Result<&'a Value> {
    entries
        .iter()
        .find_map(|(candidate, value)| (candidate.as_str() == Some(key)).then_some(value))
        .ok_or(Error::InvalidSkillBody(context))
}

pub(super) fn required_text(
    entries: &[(Value, Value)],
    key: &str,
    max_bytes: usize,
    context: &'static str,
) -> Result<String> {
    let text = required_value(entries, key, context)?
        .as_str()
        .ok_or(Error::InvalidSkillBody(context))?;
    validate_text(text, max_bytes, context)?;
    Ok(text.to_owned())
}

pub(super) fn validate_text(text: &str, max_bytes: usize, context: &'static str) -> Result<()> {
    if text.trim().is_empty() || text.len() > max_bytes {
        return Err(Error::InvalidSkillBody(context));
    }
    Ok(())
}

pub(super) fn encode_value(value: &Value, context: &'static str) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, value).map_err(|_| Error::InvariantViolation(context))?;
    Ok(bytes)
}

pub(super) fn decode_value(bytes: &[u8], context: &'static str) -> Result<Value> {
    let mut cursor = Cursor::new(bytes);
    let value =
        rmpv::decode::read_value(&mut cursor).map_err(|_| Error::InvalidSkillBody(context))?;
    if cursor.position() != bytes.len() as u64 {
        return Err(Error::InvalidSkillBody(context));
    }
    Ok(value)
}

pub(super) fn map_value<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    value
        .as_map()?
        .iter()
        .find_map(|(candidate, value)| (candidate.as_str() == Some(key)).then_some(value))
}

pub(super) fn map_text<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    map_value(value, key)?.as_str()
}
