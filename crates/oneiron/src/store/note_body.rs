//! Core half of `store::note_body`: its store-layer items live in `oneiron_store::note_body` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::note_body::*;

use crate::entity_id::EntityId;
use crate::error::{Error, RecordError, Result};
use crate::store::note_kind as kinds;
use crate::store::receipt_identity::ERASED_CALL_IDENTITY;
use rmpv::Value;
use serde::{Deserialize, Serialize};

/// Whose act a NOTE row records: an actor, or no one once that actor was
/// erased (FIX 3520). It reads and writes as the actor's hex id, or as
/// [`ERASED_CALL_IDENTITY`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoteActor {
    Actor(EntityId),
    Erased,
}

impl NoteActor {
    /// Whether this is `actor`. No one is never an actor.
    #[must_use]
    pub fn is(self, actor: EntityId) -> bool {
        self == Self::Actor(actor)
    }

    /// The actor, while it is not erased. No one has no id, so it never
    /// stands for a live writer (FIX 6072, Engine R2).
    #[must_use]
    pub const fn id(self) -> Option<EntityId> {
        match self {
            Self::Actor(id) => Some(id),
            Self::Erased => None,
        }
    }

    /// Its stored spelling: the actor's hex id, or [`ERASED_CALL_IDENTITY`].
    #[must_use]
    pub fn to_wire(self) -> String {
        match self {
            Self::Actor(id) => id.to_hex(),
            Self::Erased => ERASED_CALL_IDENTITY.to_owned(),
        }
    }

    /// A stored spelling read back: [`ERASED_CALL_IDENTITY`], or a hex id.
    pub(crate) fn from_wire(value: &str) -> Option<Self> {
        if value == ERASED_CALL_IDENTITY {
            return Some(Self::Erased);
        }
        EntityId::from_hex(value).ok().map(Self::Actor)
    }
}

impl Serialize for NoteActor {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_wire())
    }
}

impl<'de> Deserialize<'de> for NoteActor {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::from_wire(&value)
            .ok_or_else(|| serde::de::Error::custom("not an actor id or the erased marker"))
    }
}

/// A decoded NOTE body.
///
/// `author_ref` is engine-stamped from the bound facade actor, never caller
/// data. A live author always equals the target of the NOTE's mandatory
/// `AuthoredBy` edge. An erased one ([`NoteActor::Erased`], stored as
/// `"erased"`) names no one and no edge: it reads as an unknown author, never
/// matches a live writer and opens no author-only read (FIX 6072, Engine R2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoteBody {
    pub kind: NoteKind,
    pub author_ref: NoteActor,
    pub markdown: String,
    /// Opaque source revision identity, stored as exactly 16 binary bytes.
    pub source_revision_ref: [u8; 16],
}

/// Encodes a NOTE body to the pinned four-key MessagePack map.
pub fn encode_note_body(body: &NoteBody) -> Result<Vec<u8>> {
    validate_markdown(&body.markdown)?;
    if NoteKind::wire(&body.kind.as_str()).as_ref() != Some(&body.kind) {
        return Err(Error::Record(RecordError::InvalidNoteBody(
            "invalid NOTE kind",
        )));
    }
    let value = Value::Map(vec![
        (
            Value::from(KEY_KIND),
            Value::from(body.kind.as_str().as_ref()),
        ),
        (
            Value::from(KEY_AUTHOR_REF),
            Value::from(body.author_ref.to_wire()),
        ),
        (
            Value::from(KEY_MARKDOWN),
            Value::from(body.markdown.as_str()),
        ),
        (
            Value::from(KEY_SOURCE_REVISION),
            Value::Binary(body.source_revision_ref.to_vec()),
        ),
    ]);
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &value)
        .map_err(|_| Error::InvariantViolation("NOTE body MessagePack encode failed"))?;
    Ok(out)
}

/// Decodes a NOTE body, fail-closed on every deviation from the ABI: bad
/// MessagePack, trailing bytes, non-string or unknown or duplicate keys, an
/// unknown kind, an actor ref that is neither an id nor the erased marker,
/// and blank markdown.
pub fn decode_note_body(bytes: &[u8]) -> Result<NoteBody> {
    decode_note_body_using(bytes, NoteKind::parse)
}

pub(crate) fn decode_note_body_using(
    bytes: &[u8],
    resolve: impl Fn(&str) -> Option<NoteKind>,
) -> Result<NoteBody> {
    let mut cursor = bytes;
    let value = rmpv::decode::read_value(&mut cursor).map_err(|_| {
        Error::Record(RecordError::InvalidNoteBody(
            "body is not valid MessagePack",
        ))
    })?;
    if !cursor.is_empty() {
        return Err(Error::Record(RecordError::InvalidNoteBody(
            "trailing bytes after body map",
        )));
    }
    let Value::Map(entries) = value else {
        return Err(Error::Record(RecordError::InvalidNoteBody(
            "body must be a MessagePack map",
        )));
    };

    let mut kind: Option<NoteKind> = None;
    let mut author_ref: Option<NoteActor> = None;
    let mut markdown: Option<String> = None;
    let mut source_revision_ref = None;
    let mut seen = [false; NOTE_BODY_KEYS.len()];

    for (key, value) in &entries {
        let Some(key) = key.as_str() else {
            return Err(Error::Record(RecordError::InvalidNoteBody(
                "body keys must be strings",
            )));
        };
        let Some(index) = NOTE_BODY_KEYS.iter().position(|known| *known == key) else {
            return Err(Error::Record(RecordError::InvalidNoteBody(
                "body key is not in the pinned NOTE_BODY_KEYS set",
            )));
        };
        if seen[index] {
            return Err(Error::Record(RecordError::InvalidNoteBody(
                "duplicate body key",
            )));
        }
        seen[index] = true;

        match NOTE_BODY_KEYS[index] {
            KEY_KIND => {
                let raw = value
                    .as_str()
                    .ok_or(Error::Record(RecordError::InvalidNoteBody(
                        "kind must be a UTF-8 string",
                    )))?;
                kind = Some(
                    resolve(raw).ok_or(Error::Record(RecordError::InvalidNoteBody(
                        "unknown NOTE kind",
                    )))?,
                );
            }
            KEY_AUTHOR_REF => {
                let raw = value
                    .as_str()
                    .ok_or(Error::Record(RecordError::InvalidNoteBody(
                        "author_ref must be a UTF-8 string",
                    )))?;
                author_ref = Some(NoteActor::from_wire(raw).ok_or(Error::Record(
                    RecordError::InvalidNoteBody("author_ref is not a 32-hex id or erased"),
                ))?);
            }
            KEY_MARKDOWN => {
                let raw = value
                    .as_str()
                    .ok_or(Error::Record(RecordError::InvalidNoteBody(
                        "markdown must be a UTF-8 string",
                    )))?;
                validate_markdown(raw)?;
                markdown = Some(raw.to_owned());
            }
            KEY_SOURCE_REVISION => {
                let Value::Binary(bytes) = value else {
                    return Err(Error::Record(RecordError::InvalidNoteBody(
                        "source_revision_ref must be 16 binary bytes",
                    )));
                };
                source_revision_ref = Some(bytes.as_slice().try_into().map_err(|_| {
                    Error::Record(RecordError::InvalidNoteBody(
                        "source_revision_ref must be 16 binary bytes",
                    ))
                })?);
            }
            _ => unreachable!("index resolved from NOTE_BODY_KEYS"),
        }
    }

    Ok(NoteBody {
        source_revision_ref: source_revision_ref.ok_or(Error::Record(
            RecordError::InvalidNoteBody("missing required body key source_revision_ref"),
        ))?,
        kind: kind.ok_or(Error::Record(RecordError::InvalidNoteBody(
            "missing required body key kind",
        )))?,
        author_ref: author_ref.ok_or(Error::Record(RecordError::InvalidNoteBody(
            "missing required body key author_ref",
        )))?,
        markdown: markdown.ok_or(Error::Record(RecordError::InvalidNoteBody(
            "missing required body key markdown",
        )))?,
    })
}
