//! Moved from `crates/oneiron/src/anchored_annotation/wire.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::blob_artifact::family::ArtifactKind;
use oneiron_contracts::entity_id::EntityId;
use schemars::JsonSchema;
use serde::Deserialize;
use serde::Serialize;

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
    DocxStory {
        scope: oneiron_docedit::docx_body::DocxStoryScope,
        para_path: String,
        char_start: u64,
        char_end: u64,
    },
    Pptx {
        slide: u64,
        shape_id: String,
    },
    Html {
        part_id: String,
        char_start: u64,
        char_end: u64,
    },
    /// A span over a plain-text file's whole decoded text (FIX 7905).
    Text {
        char_start: u64,
        char_end: u64,
    },
    /// A span over one code file's whole decoded text (FIX 7905): `commit`
    /// is the code artifact's repo_ref commit (40 lowercase hex), `path`
    /// the file's path in that snapshot and `file_hash` its content hash
    /// (64 lowercase hex), so the words read from those exact bytes.
    Code {
        commit: String,
        path: String,
        file_hash: String,
        char_start: u64,
        char_end: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ArtifactUnitsRequest {
    pub artifact_ref: String,
    /// The head when absent. This reads version bytes, not a live body frontier.
    /// A code artifact's one anchor version is `CODE_ANCHOR_VERSION` (0).
    #[serde(default)]
    pub version: Option<u64>,
    /// Code artifacts only: the snapshot file whose lines to list, each with
    /// its words. Absent, a code artifact lists one whole-file unit per
    /// readable text file, with a null quote: a code file's words are read
    /// by pin or with `path`. Ignored for blob artifacts.
    #[serde(default)]
    pub path: Option<String>,
}

/// A unit's locator and the text it actually holds. A null quote means the
/// place has no readable text or its identity is ambiguous; it cannot be
/// pinned. A code artifact's whole-file unit is the exception: its quote is
/// null and a pin reads its words.
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AnnotationCommentView {
    pub thread_id: EntityId,
    pub author: EntityId,
    pub text: String,
    pub at: u64,
    pub claim_id: EntityId,
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
    /// The sub-session of the plan run this thread's approval started
    /// (agent-runtime-v1.md:342); `None` on every other thread.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub_session_id: Option<EntityId>,
}
