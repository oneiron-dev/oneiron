//! Engine-owned annotation claims, thread/comment/brief records and sweep results.

use crate::entity_id::EntityId;
pub use oneiron_docedit::anchored_annotation::{
    A1Range, ANNOTATION_LOCATOR_RANGE_MAX_BYTES, ANNOTATION_LOCATOR_TEXT_MAX_BYTES, Locator,
    ReanchorOp, ReanchorOutcome,
};
pub(super) use oneiron_docedit::anchored_annotation::{FORMAT_DOCX, FORMAT_PPTX, FORMAT_XLSX};

/// CLAIM predicate for a thread head (anchor + lifecycle state + drift).
pub const ANNOTATION_THREAD_PREDICATE: &str = "annotation.thread";

/// CLAIM predicate for one append-only comment in a thread.
pub const ANNOTATION_COMMENT_PREDICATE: &str = "annotation.comment";

/// CLAIM predicate recording that a thread was assigned into a task-brief.
pub const ANNOTATION_BRIEF_PREDICATE: &str = "annotation.brief";

/// Maximum byte length of a single comment body.
pub const ANNOTATION_COMMENT_TEXT_MAX_BYTES: usize = 16 * 1024;

pub(super) const STATE_OPEN: &str = "open";

pub(super) const STATE_RESOLVED: &str = "resolved";

/// An anchor: the artifact version a locator resolves against.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Anchor {
    /// The blob artifact this anchor lands on.
    pub artifact_id: EntityId,
    /// The artifact version the locator resolves against.
    pub version: u64,
    /// The format-typed position within that version.
    pub locator: Locator,
}

impl Anchor {
    /// Builds an anchor.
    #[must_use]
    pub fn new(artifact_id: EntityId, version: u64, locator: Locator) -> Self {
        Self {
            artifact_id,
            version,
            locator,
        }
    }
}

/// A thread's lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadState {
    /// Open / unresolved.
    Open,
    /// Resolved.
    Resolved,
}

impl ThreadState {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Open => STATE_OPEN,
            Self::Resolved => STATE_RESOLVED,
        }
    }

    pub(super) fn parse(text: &str) -> Option<Self> {
        match text {
            STATE_OPEN => Some(Self::Open),
            STATE_RESOLVED => Some(Self::Resolved),
            _ => None,
        }
    }
}

/// Records that a thread could not be re-anchored across a version bump and is
/// pinned to its original version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DriftMarker {
    /// The new artifact version at which re-anchoring failed.
    pub drifted_at_version: u64,
    /// The version the thread stays pinned to (its origin).
    pub pinned_version: u64,
}

/// A reconstructed thread head.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AnnotationThread {
    /// Stable thread identity.
    pub thread_id: EntityId,
    /// The current anchor. When drifted, `anchor.version` is the pinned origin.
    pub anchor: Anchor,
    /// The version the thread was first opened against.
    pub origin_version: u64,
    /// Lifecycle state.
    pub state: ThreadState,
    /// Drift status; `Some` means the anchor is pinned to its origin version.
    pub drift: Option<DriftMarker>,
    /// The `Active` head claim id (the supersession target for state changes).
    pub head_claim_id: EntityId,
}

impl AnnotationThread {
    /// Whether the thread's anchor has drifted off its original position.
    #[must_use]
    pub fn is_drifted(&self) -> bool {
        self.drift.is_some()
    }
}

/// One append-only comment.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AnnotationComment {
    /// The thread this comment belongs to.
    pub thread_id: EntityId,
    /// Author entity ref.
    pub author: EntityId,
    /// Comment body.
    pub text: String,
    /// Authored time (engine clock).
    pub at: u64,
    /// The comment's claim id.
    pub claim_id: EntityId,
}

/// The task-brief a thread assignment produces (OF-368 D4).
///
/// The brief is a productivity `TASK` entity plus a `brief:`-prefixed
/// correlation ref that downstream receipts/attempts project on (the B2 RS4
/// brief-rooted projection). It carries the anchor payload, the thread text,
/// and the `artifact@version` so the assigned agent has the full ask.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct TaskBrief {
    /// The `brief:<thread hex>` correlation ref.
    pub brief_ref: String,
    /// The productivity TASK entity id.
    pub task_id: EntityId,
    /// The source thread.
    pub thread_id: EntityId,
    /// The anchor payload (artifact + version + locator).
    pub anchor: Anchor,
    /// The artifact version the anchor resolves against.
    pub artifact_version: u64,
    /// The concatenated thread transcript.
    pub thread_text: String,
    /// The assignee/@mention target, if one was given.
    pub assignee: Option<EntityId>,
}

/// Summary of a re-anchor sweep across one version bump.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct ReanchorSummary {
    /// Threads whose anchors were re-mapped to the new version.
    pub remapped: Vec<AnnotationThread>,
    /// Threads whose anchors drifted and are now pinned to their origin.
    pub drifted: Vec<AnnotationThread>,
}
