//! Governed NOTE cores, PACK kind descriptors, and per-note editable documents.

use rmpv::Value;

use crate::entity_id::EntityId;
use crate::error::{Error, RecordError, Result};

/// The pinned NOTE body ABI. A NOTE body is exactly one MessagePack map over
/// kind and author_ref plus either birth markdown or document_head.
pub const NOTE_BODY_KEYS: [&str; 4] = ["kind", "author_ref", "markdown", "document_head"];

const KEY_KIND: &str = NOTE_BODY_KEYS[0];
const KEY_AUTHOR_REF: &str = NOTE_BODY_KEYS[1];
const KEY_MARKDOWN: &str = NOTE_BODY_KEYS[2];
const KEY_DOCUMENT_HEAD: &str = NOTE_BODY_KEYS[3];

pub(crate) mod documents;
mod id_wire;
mod kinds;
mod proposals;
mod verbs;
pub use proposals::{NoteFork, NoteLandingReceipt, NoteReviewBundle, NoteVerdict};

pub use documents::{NoteAnchor, NoteDocument, NoteEdit, NoteEditOutcome, NoteVersion};
pub use kinds::{
    ContextDefault, ExtractionDefault, NoteKind, NoteKindDescriptor, RetentionDefault,
};

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
    pub document_head: Option<EntityId>,
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
    if body.document_head.is_none() {
        validate_markdown(&body.markdown)?;
    } else if !body.markdown.is_empty() {
        return Err(
            RecordError::InvalidNoteBody("document-backed core cannot retain markdown").into(),
        );
    }
    let value = Value::Map(vec![
        (Value::from(KEY_KIND), Value::from(body.kind.as_str())),
        (
            Value::from(KEY_AUTHOR_REF),
            Value::from(body.author_ref.to_hex()),
        ),
        match body.document_head {
            Some(head) => (Value::from(KEY_DOCUMENT_HEAD), Value::from(head.to_hex())),
            None => (
                Value::from(KEY_MARKDOWN),
                Value::from(body.markdown.as_str()),
            ),
        },
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
    let mut author_ref: Option<EntityId> = None;
    let mut markdown: Option<String> = None;
    let mut document_head = None;
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
                author_ref = Some(EntityId::from_hex(raw).map_err(|_| {
                    Error::Record(RecordError::InvalidNoteBody(
                        "author_ref is not a 32-hex id",
                    ))
                })?);
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
            KEY_DOCUMENT_HEAD => {
                document_head =
                    Some(EntityId::from_hex(value.as_str().ok_or(
                        RecordError::InvalidNoteBody("head must be an id"),
                    )?)?);
            }
            _ => unreachable!("index resolved from NOTE_BODY_KEYS"),
        }
    }

    if markdown.is_some() == document_head.is_some() {
        return Err(RecordError::InvalidNoteBody(
            "exactly one of markdown and document_head is required",
        )
        .into());
    }
    Ok(NoteBody {
        kind: kind.ok_or(Error::Record(RecordError::InvalidNoteBody(
            "missing required body key kind",
        )))?,
        author_ref: author_ref.ok_or(Error::Record(RecordError::InvalidNoteBody(
            "missing required body key author_ref",
        )))?,
        markdown: markdown.unwrap_or_default(),
        document_head,
    })
}

fn validate_markdown(markdown: &str) -> Result<()> {
    if markdown.trim().is_empty() {
        return Err(Error::Record(RecordError::InvalidNoteBody(
            "markdown must not be blank",
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod document_tests;
