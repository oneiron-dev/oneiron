//! PowerPoint comment requests, inspection facts, codec limits and typed refusals.

use crate::retained_opc::{Limits, XmlLimits};
use schemars::JsonSchema;
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
    #[error("a written anchor does not read back as it was resolved")]
    AnchorReadBack,
}

pub(super) type PatchResult<T> = std::result::Result<T, PptxError>;

/// The caller's codec ceilings for one comment read or edit: the package's,
/// checked before decompression and again after it, then each XML part's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PptxCommentLimits {
    pub max_archive_bytes: usize,
    pub max_entries: usize,
    pub max_part_bytes: usize,
    pub max_expanded_bytes: usize,
    pub max_author_name_bytes: usize,
    pub max_xml_bytes: usize,
    pub max_xml_attributes: usize,
    pub max_xml_namespaces: usize,
    pub max_xml_depth: usize,
    pub max_xml_nodes: usize,
}

impl PptxCommentLimits {
    #[must_use]
    pub const fn valid(&self) -> bool {
        self.max_archive_bytes > 0
            && self.max_entries > 0
            && self.max_part_bytes > 0
            && self.max_expanded_bytes > 0
            && self.max_author_name_bytes > 0
            && self.max_xml_bytes > 0
            && self.max_xml_attributes > 0
            && self.max_xml_namespaces > 0
            && self.max_xml_depth > 0
            && self.max_xml_nodes > 0
    }

    /// The retained-OPC ceilings the package opens under.
    #[must_use]
    pub const fn package(&self) -> Limits {
        Limits {
            archive_bytes: self.max_archive_bytes,
            entries: self.max_entries,
            part_bytes: self.max_part_bytes,
            expanded_bytes: self.max_expanded_bytes,
            xml: XmlLimits {
                max_depth: self.max_xml_depth,
                max_nodes: self.max_xml_nodes,
            },
        }
    }
}

/// Export identity selected by the caller, not inferred from file metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PptxAuthor {
    pub guid: String,
    pub name: String,
}

/// Stable imported identity plus the slide number observed at inspection.
/// A shape is addressed by its creation GUID, never its name or nearby geometry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PptxCommentTarget {
    pub slide: u64,
    pub slide_creation_id: Option<u32>,
    pub shape_creation_id: Option<String>,
    /// Optional inspection hash refuses a changed shape rather than guessing.
    pub shape_fingerprint: Option<[u8; 32]>,
}

/// A new thread, a reply, or an author-owned resolution toggle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
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

/// One narrow comment operation in Office's own identities. `thread_id` is
/// the exported root comment GUID; any GUID spelling parses, and the writer
/// exports the braced upper-case form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PptxCommentEdit {
    pub author: PptxAuthor,
    pub thread_id: String,
    /// Unique reply GUID; for Add this must equal `thread_id`.
    pub comment_id: String,
    /// UTC Unix milliseconds; serialized as an OOXML dateTime.
    pub at: u64,
    pub action: PptxCommentAction,
}

/// Where a slide that lacks a p14 creation ID gets one.
#[derive(Debug, Clone, Copy)]
pub enum SlideMints<'a> {
    /// Fresh IDs drawn from the caller's entropy; never the largest surviving
    /// ID plus one.
    Draw(&'a [u8]),
    /// Exactly these `(slide, creation_id)` pairs, as an earlier edit
    /// recorded them; a mint the edit does not need, or one it needs and
    /// the list lacks, refuses.
    Replay(&'a [(u64, u32)]),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PptxDriftReason {
    MissingShape,
    AmbiguousShape,
    MissingSlideIdentity,
    TargetChanged,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PptxShapeIdentity {
    pub shape_id: u32,
    pub creation_id: Option<String>,
    pub fingerprint: [u8; 32],
    /// The verified slide-space top-left in EMU, through inherited placeholder
    /// geometry, enclosing groups, rotation and flips; None when unresolved.
    pub position: Option<(i64, i64)>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PptxInspection {
    pub slides: Vec<PptxSlideIdentity>,
    pub signature_parts: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PptxCommentEffects {
    pub new_bytes: Vec<u8>,
    pub touched_parts: BTreeSet<String>,
    pub minted_slide_creation_ids: Vec<(u64, u32)>,
    /// Each new thread's anchor, keyed by its canonical root comment GUID.
    pub anchors: Vec<(String, PptxAnchorOutcome)>,
}

/// The braced upper-case GUID Office writes for these sixteen bytes.
#[must_use]
pub fn guid(bytes: [u8; 16]) -> String {
    let hex: String = bytes.iter().map(|b| format!("{b:02X}")).collect();
    format!(
        "{{{}-{}-{}-{}-{}}}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    )
}

/// A GUID's sixteen bytes, from its simple, hyphenated, braced or URN
/// spelling; anything else is None.
#[must_use]
pub fn guid_bytes(text: &str) -> Option<[u8; 16]> {
    let inner = if let Some(rest) = text.strip_prefix("urn:uuid:") {
        rest
    } else if let Some(rest) = text.strip_prefix('{') {
        rest.strip_suffix('}')?
    } else {
        text
    };
    let hex: Vec<u8> = match inner.len() {
        32 => inner.bytes().collect(),
        36 => {
            let raw = inner.as_bytes();
            if [8, 13, 18, 23].iter().any(|&at| raw[at] != b'-') {
                return None;
            }
            raw.iter().copied().filter(|&b| b != b'-').collect()
        }
        _ => return None,
    };
    if hex.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (at, pair) in hex.chunks(2).enumerate() {
        let digit = |b: u8| char::from(b).to_digit(16);
        out[at] = u8::try_from(digit(pair[0])? * 16 + digit(pair[1])?).ok()?;
    }
    Some(out)
}

pub(super) fn canonical_guid(text: &str) -> PatchResult<String> {
    guid_bytes(text).map(guid).ok_or(PptxError::InvalidPatch)
}
