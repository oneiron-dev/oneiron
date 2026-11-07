//! NOTE body vocabulary and the pinned four-field MessagePack codec.

use rmpv::Value;
use serde::{Deserialize, Serialize};

use crate::entity_id::EntityId;
use crate::error::{Error, RecordError, Result};
use crate::store::note_kind as kinds;
use crate::store::receipt_identity::ERASED_CALL_IDENTITY;

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

/// The stored spelling's prefix for [`NoteActor::Imported`]: `imported:`
/// and the source id in hex.
const IMPORTED_ACTOR_PREFIX: &str = "imported:";

/// Whose act a NOTE row records: an actor, no one once that actor was
/// erased (FIX 3520), or the author a source vault recorded, which an
/// archive import keeps (FIX 7777). It reads and writes as the actor's hex
/// id, as [`ERASED_CALL_IDENTITY`], or as `imported:` and the source id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoteActor {
    Actor(EntityId),
    Erased,
    /// A source vault's author, kept by an archive import as provenance
    /// (FIX 7777). It is never a local actor: it matches no writer, opens
    /// no author-only read or edit, and resolves through no stamp token.
    Imported(EntityId),
}

impl NoteActor {
    /// Whether this is `actor`. No one is never an actor, and an imported
    /// author is never a local one.
    #[must_use]
    pub fn is(self, actor: EntityId) -> bool {
        self == Self::Actor(actor)
    }

    /// The actor, while it is a local one. No one has no id, so it never
    /// stands for a live writer (FIX 6072, Engine R2); nor does an imported
    /// author (FIX 7777).
    #[must_use]
    pub const fn id(self) -> Option<EntityId> {
        match self {
            Self::Actor(id) => Some(id),
            Self::Erased | Self::Imported(_) => None,
        }
    }

    /// The source vault's author an archive import kept, for display and
    /// provenance only (FIX 7777).
    #[must_use]
    pub const fn imported(self) -> Option<EntityId> {
        match self {
            Self::Imported(id) => Some(id),
            Self::Actor(_) | Self::Erased => None,
        }
    }

    /// Its stored spelling: the actor's hex id, [`ERASED_CALL_IDENTITY`],
    /// or `imported:` and the source id.
    #[must_use]
    pub fn to_wire(self) -> String {
        match self {
            Self::Actor(id) => id.to_hex(),
            Self::Erased => ERASED_CALL_IDENTITY.to_owned(),
            Self::Imported(id) => format!("{IMPORTED_ACTOR_PREFIX}{}", id.to_hex()),
        }
    }

    /// A stored spelling read back: [`ERASED_CALL_IDENTITY`], `imported:`
    /// and a hex id, or a hex id.
    pub(crate) fn from_wire(value: &str) -> Option<Self> {
        if value == ERASED_CALL_IDENTITY {
            return Some(Self::Erased);
        }
        if let Some(source) = value.strip_prefix(IMPORTED_ACTOR_PREFIX) {
            return EntityId::from_hex(source).ok().map(Self::Imported);
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

const KEY_SOURCE_REVISION: &str = NOTE_BODY_KEYS[3];

/// A decoded NOTE body.
///
/// `author_ref` is engine-stamped from the bound facade actor, never caller
/// data. A live author always equals the target of the NOTE's mandatory
/// `AuthoredBy` edge. An erased one ([`NoteActor::Erased`], stored as
/// `"erased"`) names no one and no edge: it reads as an unknown author, never
/// matches a live writer and opens no author-only read (FIX 6072, Engine R2).
/// An imported one ([`NoteActor::Imported`], stored as `imported:<hex>`)
/// names the author a source vault recorded and no edge; it is provenance,
/// and opens nothing either (FIX 7777).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoteBody {
    pub kind: NoteKind,
    pub author_ref: NoteActor,
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
                    RecordError::InvalidNoteBody(
                        "author_ref is not a 32-hex id, erased or imported",
                    ),
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

pub(crate) fn validate_markdown(markdown: &str) -> Result<()> {
    if markdown.trim().is_empty() {
        return Err(Error::Record(RecordError::InvalidNoteBody(
            "markdown must not be blank",
        )));
    }
    Ok(())
}
