//! Typed wire shapes for artifact units and anchored comment threads.

use super::{AnnotationComment, BodyAnchor, DriftMarker, Locator, ThreadState};
use crate::error::{Error, Result};

#[doc(hidden)]
pub use oneiron_verb_wire::anchored_annotation::wire::{
    AnnotationAnchorView, AnnotationAssignRequest, AnnotationBodyAnchorView, AnnotationBriefView,
    AnnotationCommentRequest, AnnotationCommentView, AnnotationDriftView, AnnotationLocator,
    AnnotationPinRequest, AnnotationResolution, AnnotationStateRequest,
    AnnotationThreadOpenRequest, AnnotationThreadRequest, AnnotationThreadState,
    AnnotationThreadView, ArtifactUnitView, ArtifactUnitsRequest, ArtifactUnitsView,
};

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
            AnnotationLocator::DocxStory {
                scope,
                para_path,
                char_start,
                char_end,
            } => Self::docx_story(scope.clone(), para_path.clone(), *char_start, *char_end),
            AnnotationLocator::Pptx { slide, shape_id } => Self::pptx(*slide, shape_id.clone()),
            AnnotationLocator::Html {
                part_id,
                char_start,
                char_end,
            } => Self::html(part_id.clone(), *char_start, *char_end),
            AnnotationLocator::Text {
                char_start,
                char_end,
            } => Self::text(*char_start, *char_end),
            AnnotationLocator::Code {
                commit,
                path,
                file_hash,
                char_start,
                char_end,
            } => Self::code(
                commit.clone(),
                path.clone(),
                file_hash.clone(),
                *char_start,
                *char_end,
            ),
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
            Locator::DocxStory {
                scope,
                para_path,
                char_start,
                char_end,
            } => Self::DocxStory {
                scope: scope.clone(),
                para_path: para_path.clone(),
                char_start: *char_start,
                char_end: *char_end,
            },
            Locator::Pptx { slide, shape_id } => Self::Pptx {
                slide: *slide,
                shape_id: shape_id.clone(),
            },
            Locator::Html {
                part_id,
                char_start,
                char_end,
            } => Self::Html {
                part_id: part_id.clone(),
                char_start: *char_start,
                char_end: *char_end,
            },
            Locator::Text {
                char_start,
                char_end,
            } => Self::Text {
                char_start: *char_start,
                char_end: *char_end,
            },
            Locator::Code {
                commit,
                path,
                file_hash,
                char_start,
                char_end,
            } => Self::Code {
                commit: commit.clone(),
                path: path.clone(),
                file_hash: file_hash.clone(),
                char_start: *char_start,
                char_end: *char_end,
            },
        }
    }
}

impl From<&BodyAnchor> for AnnotationBodyAnchorView {
    fn from(body: &BodyAnchor) -> Self {
        Self {
            frontier: body.frontier.clone(),
            locator: (&body.locator).into(),
        }
    }
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

impl From<DriftMarker> for AnnotationDriftView {
    fn from(drift: DriftMarker) -> Self {
        Self {
            drifted_at_version: drift.drifted_at_version,
            pinned_version: drift.pinned_version,
        }
    }
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
