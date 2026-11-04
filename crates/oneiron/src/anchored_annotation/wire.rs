//! Typed wire shapes for artifact units and anchored comment threads.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{AnnotationComment, BodyAnchor, DriftMarker, Locator, ThreadState};
use crate::blob_artifact::ArtifactKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

/// A position in one office artifact version. Character offsets count Unicode
/// characters, not bytes; slides are 1-based and ranges use A1 notation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "format", rename_all = "snake_case", deny_unknown_fields)]
pub enum AnnotationLocator {
    Xlsx {
        sheet: String,
        range: String,
    },
    Docx {
        para_path: String,
        char_start: u64,
        char_end: u64,
    },
    Pptx {
        slide: u64,
        shape_id: String,
    },
}

impl TryFrom<&AnnotationLocator> for Locator {
    type Error = Error;

    fn try_from(locator: &AnnotationLocator) -> Result<Self> {
        match locator {
            AnnotationLocator::Xlsx { sheet, range } => Self::xlsx(sheet.clone(), range),
            AnnotationLocator::Docx {
                para_path,
                char_start,
                char_end,
            } => Self::docx(para_path.clone(), *char_start, *char_end),
            AnnotationLocator::Pptx { slide, shape_id } => Self::pptx(*slide, shape_id.clone()),
        }
    }
}

impl From<&Locator> for AnnotationLocator {
    fn from(locator: &Locator) -> Self {
        match locator {
            Locator::Xlsx { sheet, range } => Self::Xlsx {
                sheet: sheet.clone(),
                range: range.to_a1(),
            },
            Locator::Docx {
                para_path,
                char_start,
                char_end,
            } => Self::Docx {
                para_path: para_path.clone(),
                char_start: *char_start,
                char_end: *char_end,
            },
            Locator::Pptx { slide, shape_id } => Self::Pptx {
                slide: *slide,
                shape_id: shape_id.clone(),
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ArtifactUnitsRequest {
    pub artifact_ref: String,
    /// The head when absent. This reads version bytes, not a live body frontier.
    #[serde(default)]
    pub version: Option<u64>,
}

/// A unit's locator and the text it actually holds. A null quote means the
/// place has no readable text or its identity is ambiguous; it cannot be pinned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ArtifactUnitView {
    pub locator: AnnotationLocator,
    pub quote: Option<String>,
}

/// Support comes from a unit reader, never from artifact-kind enum membership.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ArtifactUnitsView {
    Supported {
        artifact_id: EntityId,
        version: u64,
        content_hash: String,
        kind: ArtifactKind,
        units: Vec<ArtifactUnitView>,
    },
    Unsupported {
        artifact_id: EntityId,
        kind: ArtifactKind,
        reason: String,
    },
}

/// Pins a readable quote at an exact locator; the head is chosen when no
/// version is supplied. Opening a thread makes this pin durable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AnnotationPinRequest {
    pub artifact_ref: String,
    #[serde(default)]
    pub version: Option<u64>,
    pub locator: AnnotationLocator,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AnnotationAnchorView {
    pub artifact_id: EntityId,
    pub version: u64,
    pub locator: AnnotationLocator,
    /// Read from the immutable version and stored locator, with the caller's
    /// file sight. Null is explicit unreadability, never a nearby text match.
    pub quote: Option<String>,
    /// Where the unit stands in the artifact's live body; null for an anchor
    /// that names its version only.
    pub body: Option<AnnotationBodyAnchorView>,
}

/// A body-frontier anchor: the live body's frontier and the unit's locator
/// in the body there. Live edits move it; an export lands it on a version.
/// A deck's locator holds the slide's position there and, as `shape_id`,
/// the node's id in the body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AnnotationBodyAnchorView {
    pub frontier: Vec<u8>,
    pub locator: AnnotationLocator,
}

impl From<&BodyAnchor> for AnnotationBodyAnchorView {
    fn from(body: &BodyAnchor) -> Self {
        Self {
            frontier: body.frontier.clone(),
            locator: (&body.locator).into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AnnotationThreadOpenRequest {
    pub artifact_ref: String,
    /// An explicit pin: callers use the version returned by units or anchors.pin.
    pub version: u64,
    pub locator: AnnotationLocator,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AnnotationThreadRequest {
    pub artifact_ref: String,
    /// A thread identity, not an entity ref or a body block id.
    pub thread_ref: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AnnotationCommentRequest {
    pub artifact_ref: String,
    pub thread_ref: String,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AnnotationAssignRequest {
    pub artifact_ref: String,
    pub thread_ref: String,
    #[serde(default)]
    pub assignee_ref: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AnnotationThreadState {
    Open,
    Resolved,
}

impl From<AnnotationThreadState> for ThreadState {
    fn from(state: AnnotationThreadState) -> Self {
        match state {
            AnnotationThreadState::Open => Self::Open,
            AnnotationThreadState::Resolved => Self::Resolved,
        }
    }
}

impl From<ThreadState> for AnnotationThreadState {
    fn from(state: ThreadState) -> Self {
        match state {
            ThreadState::Open => Self::Open,
            ThreadState::Resolved => Self::Resolved,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AnnotationStateRequest {
    pub artifact_ref: String,
    pub thread_ref: String,
    pub state: AnnotationThreadState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AnnotationResolution {
    /// Still at the opening version and locator.
    Pinned,
    /// The engine mapped the anchor across a version change.
    Mapped,
    /// The engine could not map it; the last readable pin stays in anchor.
    Drifted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AnnotationDriftView {
    pub drifted_at_version: u64,
    pub pinned_version: u64,
}

impl From<DriftMarker> for AnnotationDriftView {
    fn from(drift: DriftMarker) -> Self {
        Self {
            drifted_at_version: drift.drifted_at_version,
            pinned_version: drift.pinned_version,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AnnotationCommentView {
    pub thread_id: EntityId,
    pub author: EntityId,
    pub text: String,
    pub at: u64,
    pub claim_id: EntityId,
}

impl From<AnnotationComment> for AnnotationCommentView {
    fn from(comment: AnnotationComment) -> Self {
        Self {
            thread_id: comment.thread_id,
            author: comment.author,
            text: comment.text,
            at: comment.at,
            claim_id: comment.claim_id,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AnnotationBriefView {
    pub brief_ref: String,
    pub task_id: EntityId,
    pub thread_id: EntityId,
    pub anchor: AnnotationAnchorView,
    pub artifact_version: u64,
    pub thread_text: String,
    pub assignee: Option<EntityId>,
}

/// A live thread, its durable opening pin and current mapped or drifted
/// anchor, append-only comments and the latest assignment's stable transcript.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AnnotationThreadView {
    pub thread_id: EntityId,
    pub origin: AnnotationAnchorView,
    pub anchor: AnnotationAnchorView,
    pub resolution: AnnotationResolution,
    pub drift: Option<AnnotationDriftView>,
    pub state: AnnotationThreadState,
    pub head_claim_id: EntityId,
    pub comments: Vec<AnnotationCommentView>,
    pub brief: Option<AnnotationBriefView>,
}
