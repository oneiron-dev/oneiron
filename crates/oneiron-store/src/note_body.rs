//! NOTE body vocabulary and the pinned four-field MessagePack codec.

use rmpv::Value;
use serde::{Deserialize, Serialize};

use crate::note_kind as kinds;
use crate::receipt_identity::ERASED_CALL_IDENTITY;
use oneiron_base::error::Error;
use oneiron_base::error::RecordError;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;

/// The pinned NOTE body ABI. A NOTE body is exactly one MessagePack map over
/// these four string keys — no more, no fewer, no repeats.
pub const NOTE_BODY_KEYS: [&str; 4] = ["kind", "author_ref", "markdown", "source_revision_ref"];

pub const KEY_KIND: &str = NOTE_BODY_KEYS[0];
pub const KEY_AUTHOR_REF: &str = NOTE_BODY_KEYS[1];
pub const KEY_MARKDOWN: &str = NOTE_BODY_KEYS[2];

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
    pub fn wire(raw: &str) -> Option<Self> {
        Self::parse(raw).or_else(|| {
            (!raw.starts_with("plugin/") && kinds::valid_name(raw))
                .then(|| Self::Registered(raw.to_owned()))
        })
    }
}

pub const KEY_SOURCE_REVISION: &str = NOTE_BODY_KEYS[3];

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

pub fn validate_markdown(markdown: &str) -> Result<()> {
    if markdown.trim().is_empty() {
        return Err(Error::Record(RecordError::InvalidNoteBody(
            "markdown must not be blank",
        )));
    }
    Ok(())
}
