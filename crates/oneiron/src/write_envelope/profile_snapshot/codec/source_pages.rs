//! The paged source frames of a PSYCH_PROFILE body (FIX 10054, Rule 5): a
//! size bound is a codec frame, never a cap on how many sources a snapshot
//! cites. Every page but the last holds a full frame, so one list encodes
//! one way; the page count has no bound.

use rmpv::Value;

use super::super::record::PsychProfileSource;
use super::{decode_entity_ref, invalid_profile, required_value, validate_keys};
use crate::error::Result;

/// Entries one codec page holds (CALLS "OF-10054 codec page", open): a frame
/// size, not a limit on a snapshot's sources.
pub const PSYCH_PROFILE_SOURCE_IDS_PER_CODEC_PAGE: usize = 4096;

const SOURCE_KEYS: [&str; 3] = ["revisionRef", "documentRef", "worldRef"];

/// `items` as full pages of `PSYCH_PROFILE_SOURCE_IDS_PER_CODEC_PAGE`, the
/// last holding the rest.
pub(super) fn encode_pages<T>(items: &[T], encode: impl Fn(&T) -> Value) -> Value {
    Value::Array(
        items
            .chunks(PSYCH_PROFILE_SOURCE_IDS_PER_CODEC_PAGE)
            .map(|page| Value::Array(page.iter().map(&encode).collect()))
            .collect(),
    )
}

/// Every entry of every page, in order. An empty page, an oversized one,
/// or a short page before the last is not the canonical framing.
pub(super) fn decode_pages<T>(
    value: &Value,
    malformed: &'static str,
    decode: impl Fn(&Value) -> Result<T>,
) -> Result<Vec<T>> {
    let Value::Array(pages) = value else {
        return Err(invalid_profile(malformed));
    };
    let mut items = Vec::new();
    for (at, page) in pages.iter().enumerate() {
        let Value::Array(page) = page else {
            return Err(invalid_profile(malformed));
        };
        let last = at + 1 == pages.len();
        if page.is_empty()
            || page.len() > PSYCH_PROFILE_SOURCE_IDS_PER_CODEC_PAGE
            || (!last && page.len() != PSYCH_PROFILE_SOURCE_IDS_PER_CODEC_PAGE)
        {
            return Err(invalid_profile(malformed));
        }
        for entry in page {
            items.push(decode(entry)?);
        }
    }
    Ok(items)
}

pub(super) fn encode_source(source: &PsychProfileSource) -> Value {
    Value::Map(vec![
        (
            Value::from(SOURCE_KEYS[0]),
            Value::from(source.revision_ref.to_hex()),
        ),
        (
            Value::from(SOURCE_KEYS[1]),
            Value::from(source.document_ref.to_hex()),
        ),
        (
            Value::from(SOURCE_KEYS[2]),
            source
                .world_ref
                .map_or(Value::Nil, |world| Value::from(world.to_hex())),
        ),
    ])
}

pub(super) fn decode_source(value: &Value) -> Result<PsychProfileSource> {
    let Value::Map(entries) = value else {
        return Err(invalid_profile("a source placement must be a map"));
    };
    validate_keys(entries, &SOURCE_KEYS)?;
    Ok(PsychProfileSource {
        revision_ref: decode_entity_ref(required_value(entries, SOURCE_KEYS[0])?)?,
        document_ref: decode_entity_ref(required_value(entries, SOURCE_KEYS[1])?)?,
        world_ref: match required_value(entries, SOURCE_KEYS[2])? {
            Value::Nil => None,
            world => Some(decode_entity_ref(world)?),
        },
    })
}
