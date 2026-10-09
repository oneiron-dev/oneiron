//! Field readers the history decoders share: records, times and text.

use std::borrow::Cow;
use std::fmt;

use serde::de::{
    self, DeserializeSeed, Deserializer as _, IgnoredAny, MapAccess, SeqAccess, Visitor,
};
use serde_json::Value;
use serde_json::value::RawValue;

use crate::ingest::{IngestError, IngestResult};

/// The largest record a reader parses: one conversation of an export, one
/// line of a session log. A parsed record takes several times its bytes, so
/// one record is the most a reader holds as a tree at a time.
pub(super) const MAX_RECORD_BYTES: usize = 128 << 20;

/// One line of a session log as a JSON object, or `None` when it is not one.
/// A line longer than [`MAX_RECORD_BYTES`] is not parsed.
pub(super) fn json_record(line: &str) -> Option<Value> {
    if line.len() > MAX_RECORD_BYTES {
        return None;
    }
    serde_json::from_str::<Value>(line)
        .ok()
        .filter(Value::is_object)
}

/// Hands each conversation of an export to `each`, parsed alone: the items
/// of the document's top-level list, or of its `conversations` list. The rest
/// of the document is skipped unbuilt, so what an export holds besides its
/// conversations costs no memory, and a conversation larger than
/// [`MAX_RECORD_BYTES`] is refused before it is parsed.
pub(super) fn export_conversations(
    source_id: &'static str,
    text: &str,
    each: &mut dyn FnMut(Value) -> IngestResult<()>,
) -> IngestResult<()> {
    let mut export = Export {
        source_id,
        each,
        position: 0,
        failed: None,
    };
    let mut deserializer = serde_json::Deserializer::from_str(text);
    let read = deserializer
        .deserialize_any(Root {
            export: &mut export,
        })
        .and_then(|found| deserializer.end().map(|()| found));
    match (export.failed, read) {
        (Some(error), _) => Err(error),
        (None, Ok(true)) => Ok(()),
        (None, Ok(false)) => Err(IngestError::InvalidDocumentField {
            source_id,
            path: "conversations".to_owned(),
        }),
        (None, Err(error)) => Err(IngestError::InvalidDocument {
            source_id,
            message: error.to_string(),
        }),
    }
}

struct Export<'f> {
    source_id: &'static str,
    each: &'f mut dyn FnMut(Value) -> IngestResult<()>,
    position: usize,
    /// Why the read stopped, when a conversation did not decode.
    failed: Option<IngestError>,
}

impl Export<'_> {
    fn conversation(&mut self, raw: &RawValue) -> Result<(), ()> {
        let position = self.position;
        self.position += 1;
        let bytes = raw.get().len();
        let decoded = if bytes > MAX_RECORD_BYTES {
            Err(IngestError::InvalidDocument {
                source_id: self.source_id,
                message: format!(
                    "conversation {position} is {bytes} bytes; one conversation is read up to {MAX_RECORD_BYTES}"
                ),
            })
        } else {
            serde_json::from_str::<Value>(raw.get())
                .map_err(|error| IngestError::InvalidDocument {
                    source_id: self.source_id,
                    message: error.to_string(),
                })
                .and_then(|conversation| (self.each)(conversation))
        };
        decoded.map_err(|error| self.failed = Some(error))
    }
}

/// The document: a list of conversations, or an object holding one.
struct Root<'s, 'f> {
    export: &'s mut Export<'f>,
}

impl<'de> Visitor<'de> for Root<'_, '_> {
    /// Whether the document held a list of conversations.
    type Value = bool;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a list of conversations, or an object holding one")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, seq: A) -> Result<bool, A::Error> {
        List {
            export: self.export,
        }
        .visit_seq(seq)
        .map(|()| true)
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<bool, A::Error> {
        let mut found = false;
        while let Some(key) = map.next_key::<Cow<'de, str>>()? {
            if key == "conversations" && !found {
                map.next_value_seed(List {
                    export: &mut *self.export,
                })?;
                found = true;
            } else {
                map.next_value::<IgnoredAny>()?;
            }
        }
        Ok(found)
    }
}

/// A list of conversations, each handed on as it is read.
struct List<'s, 'f> {
    export: &'s mut Export<'f>,
}

impl<'de> DeserializeSeed<'de> for List<'_, '_> {
    type Value = ();

    fn deserialize<D: de::Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_seq(self)
    }
}

impl<'de> Visitor<'de> for List<'_, '_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a list of conversations")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        while let Some(raw) = seq.next_element::<&'de RawValue>()? {
            self.export
                .conversation(raw)
                .map_err(|()| de::Error::custom("a conversation did not decode"))?;
        }
        Ok(())
    }
}

/// A JSON string field, when present and non-empty.
pub(super) fn str_field<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
}

/// RFC 3339 text, or Unix seconds as a number (ChatGPT writes float seconds),
/// as Unix milliseconds.
pub(super) fn time_ms(value: &Value) -> Option<u64> {
    if let Some(text) = value.as_str() {
        let time = chrono::DateTime::parse_from_rfc3339(text).ok()?;
        return u64::try_from(time.timestamp_millis()).ok();
    }
    let seconds = value.as_f64().filter(|seconds| seconds.is_finite())?;
    let millis = (seconds * 1000.0).round();
    (millis >= 0.0 && millis < u64::MAX as f64).then_some(millis as u64)
}

/// [`time_ms`] of a field.
pub(super) fn time_field(value: &Value, key: &str) -> Option<u64> {
    value.get(key).and_then(time_ms)
}

/// The text blocks of a content array joined by blank lines, the way a chat
/// shows consecutive text parts.
pub(super) fn join_texts(parts: &[&str]) -> String {
    let mut out = String::new();
    for part in parts {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if !out.is_empty() {
            out.push_str("\n\n");
        }
        out.push_str(part);
    }
    out
}
