//! The paged source frames of a PSYCH_PROFILE body (FIX 10054, Rule 5): a
//! size bound is a codec frame, never a cap on how many sources a snapshot
//! cites. Every page but the last holds a full frame, so one list encodes
//! one way; the page count has no bound. Each source carries the exact
//! version and words it was read from (FIX 11766).

use rmpv::Value;

use super::super::record::{
    PsychProfileByteRange, PsychProfileSource, PsychProfileSourceWords, PsychProfileSpanText,
    PsychProfileWordsPin,
};
use super::{decode_entity_ref, invalid_profile, required_value, validate_keys};
use crate::revision_ref::RevisionRef;
use oneiron_contracts::error::Result;

/// Entries one codec page holds (CALLS "OF-10054 codec page", open): a frame
/// size, not a limit on a snapshot's sources.
pub const PSYCH_PROFILE_SOURCE_IDS_PER_CODEC_PAGE: usize = 4096;

const SOURCE_KEYS: [&str; 5] = [
    "revisionRef",
    "documentRef",
    "worldRef",
    "documentRevision",
    "words",
];

/// The key naming which kind of words a source carries.
const WORDS_KIND_KEY: &str = "kind";

const RECORD_WORDS_KEYS: [&str; 2] = [WORDS_KIND_KEY, "content"];

const SPAN_WORDS_KEYS: [&str; 4] = [WORDS_KIND_KEY, "text", "ranges", "pin"];

const WORDS_KIND_RECORD: &str = "record";

const WORDS_KIND_SPANS: &str = "spans";

const SPAN_TEXT_DOCUMENT_KEY: &str = "documentFrontier";

const SPAN_TEXT_FIELD_KEY: &str = "field";

const PIN_CONTENT_KEY: &str = "content";

const PIN_PROJECTION_KEY: &str = "projection";

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
        (
            Value::from(SOURCE_KEYS[3]),
            Value::from(source.document_revision.to_hex()),
        ),
        (Value::from(SOURCE_KEYS[4]), encode_words(&source.words)),
    ])
}

pub(super) fn decode_source(value: &Value) -> Result<PsychProfileSource> {
    let Value::Map(entries) = value else {
        return Err(invalid_profile("a source must be a map"));
    };
    validate_keys(entries, &SOURCE_KEYS)?;
    Ok(PsychProfileSource {
        revision_ref: decode_entity_ref(required_value(entries, SOURCE_KEYS[0])?)?,
        document_ref: decode_entity_ref(required_value(entries, SOURCE_KEYS[1])?)?,
        world_ref: match required_value(entries, SOURCE_KEYS[2])? {
            Value::Nil => None,
            world => Some(decode_entity_ref(world)?),
        },
        document_revision: required_value(entries, SOURCE_KEYS[3])?
            .as_str()
            .and_then(|hex| RevisionRef::from_hex(hex).ok())
            .ok_or_else(|| invalid_profile("documentRevision must be a revision reference"))?,
        words: decode_words(required_value(entries, SOURCE_KEYS[4])?)?,
    })
}

fn encode_words(words: &PsychProfileSourceWords) -> Value {
    match words {
        PsychProfileSourceWords::Record { content } => Value::Map(vec![
            (
                Value::from(RECORD_WORDS_KEYS[0]),
                Value::from(WORDS_KIND_RECORD),
            ),
            (
                Value::from(RECORD_WORDS_KEYS[1]),
                Value::Binary(content.to_vec()),
            ),
        ]),
        PsychProfileSourceWords::Spans { text, ranges, pin } => Value::Map(vec![
            (
                Value::from(SPAN_WORDS_KEYS[0]),
                Value::from(WORDS_KIND_SPANS),
            ),
            (Value::from(SPAN_WORDS_KEYS[1]), encode_span_text(text)),
            (
                Value::from(SPAN_WORDS_KEYS[2]),
                Value::Array(
                    ranges
                        .iter()
                        .map(|range| {
                            Value::Array(vec![Value::from(range.start), Value::from(range.end)])
                        })
                        .collect(),
                ),
            ),
            (Value::from(SPAN_WORDS_KEYS[3]), encode_pin(*pin)),
        ]),
    }
}

fn decode_words(value: &Value) -> Result<PsychProfileSourceWords> {
    let Value::Map(entries) = value else {
        return Err(invalid_profile("source words must be a map"));
    };
    match required_value(entries, WORDS_KIND_KEY)?.as_str() {
        Some(WORDS_KIND_RECORD) => {
            validate_keys(entries, &RECORD_WORDS_KEYS)?;
            Ok(PsychProfileSourceWords::Record {
                content: decode_hash(required_value(entries, RECORD_WORDS_KEYS[1])?)?,
            })
        }
        Some(WORDS_KIND_SPANS) => {
            validate_keys(entries, &SPAN_WORDS_KEYS)?;
            Ok(PsychProfileSourceWords::Spans {
                text: decode_span_text(required_value(entries, SPAN_WORDS_KEYS[1])?)?,
                ranges: decode_ranges(required_value(entries, SPAN_WORDS_KEYS[2])?)?,
                pin: decode_pin(required_value(entries, SPAN_WORDS_KEYS[3])?)?,
            })
        }
        _ => Err(invalid_profile("source words kind must be record or spans")),
    }
}

fn encode_span_text(text: &PsychProfileSpanText) -> Value {
    Value::Map(vec![match text {
        PsychProfileSpanText::Document { frontier } => (
            Value::from(SPAN_TEXT_DOCUMENT_KEY),
            Value::Binary(frontier.clone()),
        ),
        PsychProfileSpanText::Field { field } => (
            Value::from(SPAN_TEXT_FIELD_KEY),
            Value::from(field.as_str()),
        ),
    }])
}

fn decode_span_text(value: &Value) -> Result<PsychProfileSpanText> {
    let malformed = "a span's text must name one document frontier or one body field";
    match single_entry(value, malformed)? {
        (SPAN_TEXT_DOCUMENT_KEY, Value::Binary(frontier)) => Ok(PsychProfileSpanText::Document {
            frontier: frontier.clone(),
        }),
        (SPAN_TEXT_FIELD_KEY, Value::String(field)) => field
            .as_str()
            .map(|field| PsychProfileSpanText::Field {
                field: field.to_owned(),
            })
            .ok_or_else(|| invalid_profile(malformed)),
        _ => Err(invalid_profile(malformed)),
    }
}

fn decode_ranges(value: &Value) -> Result<Vec<PsychProfileByteRange>> {
    let malformed = "a span's ranges must be [start, end] byte offset pairs";
    let Value::Array(ranges) = value else {
        return Err(invalid_profile(malformed));
    };
    ranges
        .iter()
        .map(|range| match range {
            Value::Array(pair) => match pair.as_slice() {
                [start, end] => Ok(PsychProfileByteRange {
                    start: start.as_u64().ok_or_else(|| invalid_profile(malformed))?,
                    end: end.as_u64().ok_or_else(|| invalid_profile(malformed))?,
                }),
                _ => Err(invalid_profile(malformed)),
            },
            _ => Err(invalid_profile(malformed)),
        })
        .collect()
}

fn encode_pin(pin: PsychProfileWordsPin) -> Value {
    let (key, hash) = match pin {
        PsychProfileWordsPin::Content(hash) => (PIN_CONTENT_KEY, hash),
        PsychProfileWordsPin::Projection(hash) => (PIN_PROJECTION_KEY, hash),
    };
    Value::Map(vec![(Value::from(key), Value::Binary(hash.to_vec()))])
}

fn decode_pin(value: &Value) -> Result<PsychProfileWordsPin> {
    let malformed = "a span's pin must name one content or projection hash";
    match single_entry(value, malformed)? {
        (PIN_CONTENT_KEY, hash) => Ok(PsychProfileWordsPin::Content(decode_hash(hash)?)),
        (PIN_PROJECTION_KEY, hash) => Ok(PsychProfileWordsPin::Projection(decode_hash(hash)?)),
        _ => Err(invalid_profile(malformed)),
    }
}

/// The one string key and its value of a single-entry map.
fn single_entry<'a>(value: &'a Value, malformed: &'static str) -> Result<(&'a str, &'a Value)> {
    let Value::Map(entries) = value else {
        return Err(invalid_profile(malformed));
    };
    let [(key, value)] = entries.as_slice() else {
        return Err(invalid_profile(malformed));
    };
    Ok((
        key.as_str().ok_or_else(|| invalid_profile(malformed))?,
        value,
    ))
}

fn decode_hash(value: &Value) -> Result<[u8; 32]> {
    match value {
        Value::Binary(bytes) => <[u8; 32]>::try_from(bytes.as_slice())
            .map_err(|_| invalid_profile("a source hash must be 32 bytes")),
        _ => Err(invalid_profile("a source hash must be 32 bytes")),
    }
}
