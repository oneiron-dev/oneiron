//! Attributed NOTE records with built-in, plugin and registered PACK kinds.
//! Editable text and citation authority use the canonical entity-document path.

use rmpv::Value;

use crate::entity_id::EntityId;
use crate::error::{Error, RecordError, Result};

/// The pinned NOTE body ABI. A NOTE body is exactly one MessagePack map over
/// these four string keys — no more, no fewer, no repeats.
pub const NOTE_BODY_KEYS: [&str; 4] = ["kind", "author_ref", "markdown", "source_revision_ref"];

const KEY_KIND: &str = NOTE_BODY_KEYS[0];
const KEY_AUTHOR_REF: &str = NOTE_BODY_KEYS[1];
const KEY_MARKDOWN: &str = NOTE_BODY_KEYS[2];

/// The kind discriminator of a NOTE body.
///
/// Built-in and plugin identities retain their typed variants. PACK names are
/// data; every write and store-aware read still checks their installed descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NoteKind {
    /// An actor's attributed opinion about a subject or a claim.
    OpinionTake,
    /// A pack namespace tag; only `brief` carries a blessed contract.
    Plugin(String),
    /// Private to the author. Ordinary retrieval never includes this kind.
    Diary,
    /// A shipped or vault-registered PACK discriminator; admission checks the registry.
    Registered(String),
}

impl NoteKind {
    /// The pinned wire literal. This string IS the storage ABI.
    #[must_use]
    pub fn as_str(&self) -> std::borrow::Cow<'_, str> {
        match self {
            Self::OpinionTake => std::borrow::Cow::Borrowed("opinion/take"),
            Self::Diary => std::borrow::Cow::Borrowed("diary"),
            Self::Plugin(tag) => std::borrow::Cow::Owned(format!("plugin/{tag}")),
            Self::Registered(kind) => std::borrow::Cow::Borrowed(kind),
        }
    }

    /// Parses a shipped kind or a syntactically valid plugin namespace.
    /// Vault-registered non-plugin kinds require the store-aware resolver.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "opinion/take" => return Some(Self::OpinionTake),
            "diary" => return Some(Self::Diary),
            _ => {}
        }
        if kinds::is_shipped_kind(raw) {
            return Some(Self::Registered(raw.to_owned()));
        }
        let tag = raw.strip_prefix("plugin/")?;
        (!tag.is_empty()
            && tag.len() <= 128
            && tag
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c)))
        .then(|| Self::Plugin(tag.to_owned()))
    }
    /// Syntax-only decode for registry-aware callers. This never grants admission.
    pub(crate) fn wire(raw: &str) -> Option<Self> {
        Self::parse(raw).or_else(|| {
            (!raw.starts_with("plugin/") && kinds::valid_name(raw))
                .then(|| Self::Registered(raw.to_owned()))
        })
    }
}

pub(crate) mod documents;
pub(crate) mod erase;
mod kinds;
pub(crate) mod recovery;
pub(crate) mod storage;
pub(crate) use kinds::validate_registered_kind;
mod proposals;
mod verbs;
pub use documents::{
    NoteAnchor, NoteDocument as NoteProgramDocument, NoteEdit as NoteProgramEdit,
    NoteEditOutcome as NoteProgramEditOutcome, NoteVersion,
};
pub use kinds::{ContextDefault, ExtractionDefault, NoteKindDescriptor, RetentionDefault};
pub use proposals::{NoteFork, NoteLandingReceipt, NoteReviewBundle, NoteVerdict};
const KEY_SOURCE_REVISION: &str = NOTE_BODY_KEYS[3];

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
    /// Opaque source revision identity, stored as exactly 16 binary bytes.
    pub source_revision_ref: [u8; 16],
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

/// The scope a NOTE writer binds to the facade's verified actor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoteScope {
    /// An opinion beside a subject or claim.
    About(TakeTarget),
    /// A diary belonging to exactly this actor, never a vault-wide audience.
    ActorPrivate { owner_ref: EntityId },
}

/// A typed write request. The facade supplies author identity; callers cannot
/// supply an independent stored author or widen a diary's scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoteWriteEnvelope {
    pub kind: NoteKind,
    pub scope: NoteScope,
    pub markdown: String,
    pub source_revision_ref: [u8; 16],
    /// The active mask the NOTE is born under; `None` stamps the vault
    /// default. It must be a stored FACET row.
    pub mask: Option<EntityId>,
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
            Value::from(body.author_ref.to_hex()),
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

pub(crate) fn validate_markdown(markdown: &str) -> Result<()> {
    if markdown.trim().is_empty() {
        return Err(Error::Record(RecordError::InvalidNoteBody(
            "markdown must not be blank",
        )));
    }
    Ok(())
}

/// Registry-aware decoding for stored NOTE cores, including PACK-defined kinds.
pub(crate) fn decode_note_body_in_txn(
    store: &impl crate::store::ManifestDbs,
    txn: &heed::RoTxn<'_>,
    bytes: &[u8],
) -> Result<NoteBody> {
    let body = decode_note_body_using(bytes, NoteKind::wire)?;
    kinds::context_in_txn(store, txn, body.kind.as_str().as_ref())?;
    Ok(body)
}

/// Shared NOTE admission. Ordinary retrieval excludes every owner-only kind.
pub(crate) fn note_body_readable(
    store: &impl crate::store::ManifestDbs,
    txn: &heed::RoTxn<'_>,
    bytes: &[u8],
    actor: Option<&EntityId>,
) -> Result<bool> {
    let Ok(body) = decode_note_body_using(bytes, NoteKind::wire) else {
        return Ok(false);
    };
    let context = kinds::context_in_txn(store, txn, body.kind.as_str().as_ref())?;
    Ok(context != ContextDefault::OwnerOnly || actor == Some(&body.author_ref))
}

/// Ordinary retrieval's NOTE privacy floor. Unrelated entity kinds and missing
/// graph endpoints retain their existing admission semantics.
pub(crate) fn ordinary_entity_visible(
    store: &impl crate::store::ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    let Some(raw) = store.entities().get(txn, id.as_bytes())? else {
        return Ok(true);
    };
    let Some(header) = crate::batch::EntityMetadataHeader::parse(&raw) else {
        return Ok(false);
    };
    Ok(header.entity_type != crate::registry::ENTITY_TYPE_NOTE
        || note_body_readable(
            store,
            txn,
            &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
            None,
        )?)
}

#[cfg(test)]
mod tests;

mod citation_erase;
mod delete;
mod pin_index;
pub(crate) use citation_erase::{
    PENDING_CITATION_ERASE, ensure_citations_ready, erase_citations_in_txn,
};
pub(crate) use pin_index::citation_delete_scope_exists;
#[cfg(feature = "sync")]
pub(crate) use pin_index::{remove_citation_request, track_citation_request};
#[cfg(feature = "sync")]
mod citation_scrub;
#[cfg(feature = "sync")]
pub(crate) use citation_erase::validate_pins as validate_citation_dependencies;
#[cfg(feature = "sync")]
pub(crate) use citation_scrub::scrub_pending_citations;
#[cfg(test)]
mod erasure_tests;
mod live_body;
pub(crate) use live_body::live_body_in_txn;
mod kind_contract;
#[cfg(all(test, feature = "sync"))]
mod live_body_tests;
pub(crate) use delete::delete_document_in_txn;
mod id_codec;
pub use kind_contract::{
    BriefKindContract, NoteContextDefault, NoteExtractionDefault, NoteRetentionDefault,
};
mod birth;
#[cfg(feature = "sync")]
mod brief_view;
mod document;
mod document_store;
pub(crate) use birth::document_birth_in_txn;
mod operations;
pub use operations::{NoteAuthorship, NoteChange, NoteOperation, NoteOperationReceipt};
#[cfg(feature = "sync")]
mod replica;
#[cfg(feature = "sync")]
pub use brief_view::{BriefCitationView, BriefView};
#[cfg(feature = "sync")]
pub(crate) use replica::{import_note_from_authority, validate_note_export};
#[cfg(all(test, feature = "sync"))]
mod document_tests;
#[cfg(all(test, feature = "sync"))]
mod sync_tests;
pub use document::{NoteDocumentView, NoteEdit, NoteEditOutcome, NotePin, NoteSpanResolution};

#[cfg(test)]
mod program_tests;

#[cfg(test)]
mod adapter_tests;
