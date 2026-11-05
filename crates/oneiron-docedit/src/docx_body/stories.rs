//! Native non-body stories, kept separate from the document body's id space.

use crate::{ArchiveLimits, DoceditError, Document, preflight_with_limits};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use stemma::domain::HeaderFooterKind;

use super::{DocxBlock, block};

/// A native story's identity. Block ids are local to this scope; a story's
/// `p_1` never addresses the document body's `p_1`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DocxStoryScope {
    Header {
        part_name: String,
        band: DocxHeaderFooterBand,
    },
    Footer {
        part_name: String,
        band: DocxHeaderFooterBand,
    },
    Footnote {
        id: String,
    },
    Endnote {
        id: String,
    },
    Comment {
        id: String,
    },
}

/// The header/footer band named by the source package.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DocxHeaderFooterBand {
    Default,
    First,
    Even,
}

impl From<&HeaderFooterKind> for DocxHeaderFooterBand {
    fn from(kind: &HeaderFooterKind) -> Self {
        match kind {
            HeaderFooterKind::Default => Self::Default,
            HeaderFooterKind::First => Self::First,
            HeaderFooterKind::Even => Self::Even,
        }
    }
}

/// One non-body story, with its own ordered, locally identified blocks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DocxStory {
    pub scope: DocxStoryScope,
    pub blocks: Vec<DocxBlock>,
}

/// The document body and its native non-body stories from one parse.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DocxRead {
    pub blocks: Vec<DocxBlock>,
    pub stories: Vec<DocxStory>,
}

/// Read the main body and every authored header/footer, footnote, endnote
/// and comment story under the caller's existing archive/resource limits.
/// The existing `read_docx_blocks` API remains body-only.
pub fn read_docx_body(bytes: &[u8], limits: ArchiveLimits) -> Result<DocxRead, DoceditError> {
    crate::within(limits, || {
        preflight_with_limits(bytes, limits)?;
        let document = Document::parse(bytes)?;
        let canonical = &document.snapshot().canonical;
        let mut stories = Vec::new();
        let mut push = |scope, blocks: &[stemma::domain::TrackedBlock]| {
            let view = stemma::view::build_story_blocks_view(blocks);
            stories.push(DocxStory {
                scope,
                blocks: view.blocks.iter().map(block).collect(),
            });
        };
        for story in &canonical.headers {
            if !story.synthesized {
                push(
                    DocxStoryScope::Header {
                        part_name: story.part_name.clone(),
                        band: (&story.kind).into(),
                    },
                    &story.blocks,
                );
            }
        }
        for story in &canonical.footers {
            if !story.synthesized {
                push(
                    DocxStoryScope::Footer {
                        part_name: story.part_name.clone(),
                        band: (&story.kind).into(),
                    },
                    &story.blocks,
                );
            }
        }
        for story in &canonical.footnotes {
            push(
                DocxStoryScope::Footnote {
                    id: story.id.clone(),
                },
                &story.blocks,
            );
        }
        for story in &canonical.endnotes {
            push(
                DocxStoryScope::Endnote {
                    id: story.id.clone(),
                },
                &story.blocks,
            );
        }
        for story in &canonical.comments {
            push(
                DocxStoryScope::Comment {
                    id: story.id.clone(),
                },
                &story.blocks,
            );
        }
        Ok(DocxRead {
            blocks: document.read().blocks.iter().map(block).collect(),
            stories,
        })
    })
}
