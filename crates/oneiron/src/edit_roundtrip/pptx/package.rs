//! Public PowerPoint comment requests, inspection facts, and typed refusals.

use crate::entity_id::EntityId;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub(super) const P: &str = "http://schemas.openxmlformats.org/presentationml/2006/main";
pub(super) const A: &str = "http://schemas.openxmlformats.org/drawingml/2006/main";
pub(super) const R: &str = "http://schemas.openxmlformats.org/officeDocument/2006/relationships";
pub(super) const REL: &str = "http://schemas.openxmlformats.org/package/2006/relationships";
pub(super) const CT: &str = "http://schemas.openxmlformats.org/package/2006/content-types";
pub(super) const P188: &str = "http://schemas.microsoft.com/office/powerpoint/2018/8/main";
pub(super) const P14: &str = "http://schemas.microsoft.com/office/powerpoint/2010/main";
pub(super) const A16: &str = "http://schemas.microsoft.com/office/drawing/2014/main";
pub(super) const SLIDE_ID_EXT: &str = "{BB962C8B-B14F-4D97-AF65-F5344CB8AC3E}";
pub(super) const COMMENT_EXT: &str = "{6950BFC3-D8DA-4A85-94F7-54DA5524770B}";
pub(super) const COMMENT_REL: &str =
    "http://schemas.microsoft.com/office/2018/10/relationships/comments";
pub(super) const AUTHOR_REL: &str =
    "http://schemas.microsoft.com/office/2018/10/relationships/authors";
pub(super) const AUTHORS: &str = "ppt/authors.xml";
pub(super) const PRESENTATION_RELS: &str = "ppt/_rels/presentation.xml.rels";

/// Typed refusals from the narrow comment writer. No repair or guessing occurs.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PptxError {
    #[error("invalid or unsupported OPC package")]
    InvalidPackage,
    #[error("invalid or unsupported XML")]
    InvalidXml,
    #[error("invalid comment request")]
    InvalidPatch,
    #[error("signed packages cannot be edited")]
    SignedPackage,
    #[error("target slide does not resolve")]
    SlideNotFound,
    #[error("creation identity is ambiguous")]
    AmbiguousAnchor,
    #[error("shape position is not verified in slide coordinates")]
    UnverifiedGeometry,
    #[error("comment thread does not resolve")]
    ThreadNotFound,
    #[error("comment identity already exists")]
    DuplicateComment,
    #[error("only the original author may resolve the comment")]
    NotAuthor,
    #[error("author identity conflicts with the imported author")]
    AuthorConflict,
    #[error("a relationship or content-type reference is invalid")]
    InvalidReference,
    #[error("an undeclared package part changed")]
    PartDiffOutsideTransaction,
}

pub(super) type PatchResult<T> = std::result::Result<T, PptxError>;

/// Export identity selected by the caller, not inferred from file metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PptxAuthor {
    pub guid: String,
    pub name: String,
}

/// Stable imported identity plus the slide number observed at inspection.
/// A shape is addressed by its creation GUID, never its name or nearby geometry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PptxCommentTarget {
    pub slide: u64,
    pub slide_creation_id: Option<u32>,
    pub shape_creation_id: Option<String>,
    /// Optional inspection hash refuses a changed shape rather than guessing.
    pub shape_fingerprint: Option<[u8; 32]>,
}

/// A new thread, a reply, or an author-owned resolution toggle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PptxCommentAction {
    Add {
        target: PptxCommentTarget,
        text: String,
    },
    Reply {
        text: String,
    },
    Resolve {
        resolved: bool,
    },
}

/// One narrow operation. `thread_id` is also the exported root comment GUID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PptxCommentPatch {
    /// Engine identities retained independently of the displayed Office author.
    #[serde(with = "entity_ref")]
    pub asked_by: EntityId,
    #[serde(with = "entity_ref")]
    pub answered_by: EntityId,
    pub author: PptxAuthor,
    #[serde(with = "entity_ref")]
    pub thread_id: EntityId,
    /// Unique reply GUID; for Add this must equal `thread_id`.
    #[serde(with = "entity_ref")]
    pub comment_id: EntityId,
    /// UTC Unix milliseconds; serialized as an OOXML dateTime.
    pub at: u64,
    pub action: PptxCommentAction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PptxDriftReason {
    MissingShape,
    AmbiguousShape,
    MissingSlideIdentity,
    TargetChanged,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PptxAnchorOutcome {
    Slide {
        slide: u64,
        sld_id: u32,
        creation_id: u32,
    },
    Shape {
        slide: u64,
        sld_id: u32,
        creation_id: u32,
        shape_creation_id: String,
        x: i64,
        y: i64,
    },
    UnknownAnchor {
        reason: PptxDriftReason,
    },
}

/// Inspection never writes missing identities.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PptxShapeIdentity {
    pub shape_id: u32,
    pub creation_id: Option<String>,
    pub fingerprint: [u8; 32],
    /// None for inherited, grouped, rotated, or otherwise unresolved geometry.
    pub position: Option<(i64, i64)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PptxSlideIdentity {
    pub slide: u64,
    pub part: String,
    pub sld_id: u32,
    /// p14 creation IDs are unsigned 32-bit integers, not GUIDs.
    pub creation_id: Option<u32>,
    /// Normalized slide content; ignores only declared review metadata extensions.
    pub fingerprint: [u8; 32],
    pub shapes: Vec<PptxShapeIdentity>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PptxInspection {
    pub slides: Vec<PptxSlideIdentity>,
    pub signature_parts: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PptxCommentEffects {
    pub new_bytes: Vec<u8>,
    pub touched_parts: BTreeSet<String>,
    pub minted_slide_creation_ids: Vec<(u64, u32)>,
    pub anchors: Vec<(EntityId, PptxAnchorOutcome)>,
}

pub(super) fn guid(id: EntityId) -> String {
    let hex = id.to_hex();
    format!(
        "{{{}-{}-{}-{}-{}}}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    )
    .to_ascii_uppercase()
}

pub(super) fn canonical_guid(text: &str) -> PatchResult<String> {
    uuid::Uuid::parse_str(text)
        .map(|id| format!("{{{id}}}").to_ascii_uppercase())
        .map_err(|_| PptxError::InvalidPatch)
}

/// Keeps package refusals typed while retaining the existing vault error as a source.
#[derive(Debug, thiserror::Error)]
pub enum PptxProposalError {
    #[error(transparent)]
    Patch(#[from] PptxError),
    #[error(transparent)]
    Vault(#[from] crate::error::Error),
}

mod entity_ref {
    use crate::EntityId;
    use serde::{Deserialize, Deserializer, Serializer};
    pub(super) fn serialize<S: Serializer>(
        id: &EntityId,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&id.to_hex())
    }
    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<EntityId, D::Error> {
        let value = String::deserialize(deserializer)?;
        let id = EntityId::from_hex(&value).map_err(serde::de::Error::custom)?;
        if id.to_hex() != value {
            return Err(serde::de::Error::custom("noncanonical comment entity ref"));
        }
        Ok(id)
    }
}
