//! ARCH-0032 NOTE primitive, cut to the single kind this ticket lands:
//! `opinion/take` (registry record OF-330).
//!
//! A take is an actor's *opinion about* something, written BESIDE the thing
//! rather than into it. That placement is the point: ARCH-0003 CLAIMs are
//! neutral subject·predicate·value records, so an actor who disagrees with a
//! claim must not edit it — [`crate::facade::MemoryFacade::author_take`]
//! appends a NOTE and links it with `ClaimOf`, leaving the target byte-for-byte
//! untouched. Two actors over one claim therefore produce two NOTE entities,
//! never an upsert keyed by `(actor, target)`.
//!
//! [`NoteKind`] is deliberately CLOSED at one variant. The other six ARCH-0032
//! kinds (Scratchpad, Observation, Handoff, Research, Reflection, Diary) and
//! pack-defined `Plugin` kinds are not designed for the live engine yet;
//! placeholder variants would publish a wire surface nothing can honour.
//!
//! Byte law: the engine registers NOTE at [`crate::registry::ENTITY_TYPE_NOTE`]
//! (86, productivity band). Canon assigns 106 under BYTE-SPACE REDESIGN v3 and
//! ONE-1754 executes the persisted re-key as one atomic v3 map; this module
//! never writes a migration and never names 106.

use rmpv::Value;

use crate::entity_id::EntityId;
use crate::error::{Error, Result};

/// The pinned NOTE body ABI. A NOTE body is exactly one MessagePack map over
/// these three string keys — no more, no fewer, no repeats.
pub const NOTE_BODY_KEYS: [&str; 3] = ["kind", "author_ref", "markdown"];

const KEY_KIND: &str = NOTE_BODY_KEYS[0];
const KEY_AUTHOR_REF: &str = NOTE_BODY_KEYS[1];
const KEY_MARKDOWN: &str = NOTE_BODY_KEYS[2];

/// The kind discriminator of a NOTE body.
///
/// Closed at one variant on purpose — see the module doc. `parse` fails closed
/// so an unknown wire string can never widen the enum by accident.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoteKind {
    /// An actor's attributed opinion about a subject or a claim.
    OpinionTake,
}

impl NoteKind {
    /// The pinned wire literal. This string IS the storage ABI.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        "opinion/take"
    }

    /// Parses the wire literal; `None` for anything else.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        (raw == Self::OpinionTake.as_str()).then_some(Self::OpinionTake)
    }
}

/// A decoded NOTE body.
///
/// `author_ref` is engine-stamped from the bound facade actor, never caller
/// data, and always equals the target of the NOTE's mandatory `AuthoredBy`
/// edge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoteBody {
    pub kind: NoteKind,
    pub author_ref: EntityId,
    pub markdown: String,
}

/// What a take is about.
///
/// The two arms are not interchangeable: `Subject` links with `About` to any
/// entity, `Claim` links with `ClaimOf` and is proven to be a type-0 CLAIM
/// first, so a `ClaimOf` edge can never point at a non-claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TakeTarget {
    Subject(EntityId),
    Claim(EntityId),
}

/// Encodes a NOTE body to the pinned three-key MessagePack map.
pub fn encode_note_body(body: &NoteBody) -> Result<Vec<u8>> {
    validate_markdown(&body.markdown)?;
    let value = Value::Map(vec![
        (Value::from(KEY_KIND), Value::from(body.kind.as_str())),
        (
            Value::from(KEY_AUTHOR_REF),
            Value::from(body.author_ref.to_hex()),
        ),
        (Value::from(KEY_MARKDOWN), Value::from(body.markdown.as_str())),
    ]);
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &value)
        .map_err(|_| Error::InvariantViolation("NOTE body MessagePack encode failed"))?;
    Ok(out)
}

/// Decodes a NOTE body, fail-closed on every deviation from the ABI: bad
/// MessagePack, trailing bytes, non-string or unknown or duplicate keys, an
/// unknown kind, an unparseable actor ref, and blank markdown.
pub fn decode_note_body(bytes: &[u8]) -> Result<NoteBody> {
    let mut cursor = bytes;
    let value = rmpv::decode::read_value(&mut cursor)
        .map_err(|_| Error::InvalidNoteBody("body is not valid MessagePack"))?;
    if !cursor.is_empty() {
        return Err(Error::InvalidNoteBody("trailing bytes after body map"));
    }
    let Value::Map(entries) = value else {
        return Err(Error::InvalidNoteBody("body must be a MessagePack map"));
    };

    let mut kind: Option<NoteKind> = None;
    let mut author_ref: Option<EntityId> = None;
    let mut markdown: Option<String> = None;
    let mut seen = [false; NOTE_BODY_KEYS.len()];

    for (key, value) in &entries {
        let Some(key) = key.as_str() else {
            return Err(Error::InvalidNoteBody("body keys must be strings"));
        };
        let Some(index) = NOTE_BODY_KEYS.iter().position(|known| *known == key) else {
            return Err(Error::InvalidNoteBody(
                "body key is not in the pinned NOTE_BODY_KEYS set",
            ));
        };
        if seen[index] {
            return Err(Error::InvalidNoteBody("duplicate body key"));
        }
        seen[index] = true;

        match NOTE_BODY_KEYS[index] {
            KEY_KIND => {
                let raw = value
                    .as_str()
                    .ok_or(Error::InvalidNoteBody("kind must be a UTF-8 string"))?;
                kind = Some(
                    NoteKind::parse(raw).ok_or(Error::InvalidNoteBody("unknown NOTE kind"))?,
                );
            }
            KEY_AUTHOR_REF => {
                let raw = value
                    .as_str()
                    .ok_or(Error::InvalidNoteBody("author_ref must be a UTF-8 string"))?;
                author_ref = Some(
                    EntityId::from_hex(raw)
                        .map_err(|_| Error::InvalidNoteBody("author_ref is not a 32-hex id"))?,
                );
            }
            KEY_MARKDOWN => {
                let raw = value
                    .as_str()
                    .ok_or(Error::InvalidNoteBody("markdown must be a UTF-8 string"))?;
                validate_markdown(raw)?;
                markdown = Some(raw.to_owned());
            }
            _ => unreachable!("index resolved from NOTE_BODY_KEYS"),
        }
    }

    Ok(NoteBody {
        kind: kind.ok_or(Error::InvalidNoteBody("missing required body key kind"))?,
        author_ref: author_ref.ok_or(Error::InvalidNoteBody(
            "missing required body key author_ref",
        ))?,
        markdown: markdown.ok_or(Error::InvalidNoteBody(
            "missing required body key markdown",
        ))?,
    })
}

fn validate_markdown(markdown: &str) -> Result<()> {
    if markdown.trim().is_empty() {
        return Err(Error::InvalidNoteBody("markdown must not be blank"));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
