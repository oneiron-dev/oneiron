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
        let mut read = read_document(&document)?;
        for (story, (_, source)) in read.stories.iter_mut().zip(story_blocks(&document)) {
            story.blocks.extend(super::cells::descendant_table_blocks(
                source,
                matches!(&story.scope, DocxStoryScope::Comment { .. }),
            )?);
        }
        Ok(read)
    })
}

fn read_document(document: &Document) -> Result<DocxRead, DoceditError> {
    let canonical = &document.snapshot().canonical;
    let mut stories = Vec::new();
    let mut push = |scope: DocxStoryScope, blocks: &[stemma::domain::TrackedBlock]| {
        let view = stemma::view::build_story_blocks_view(blocks);
        let comment = matches!(&scope, DocxStoryScope::Comment { .. });
        stories.push(DocxStory {
            scope,
            blocks: view
                .blocks
                .iter()
                .map(|view| block(view, blocks, comment))
                .collect::<Result<_, _>>()?,
        });
        Ok::<_, DoceditError>(())
    };
    for (scope, blocks) in story_blocks(document) {
        push(scope, blocks)?;
    }
    Ok(DocxRead {
        blocks: document
            .read()
            .blocks
            .iter()
            .map(|view| block(view, &canonical.blocks, false))
            .collect::<Result<_, _>>()?,
        stories,
    })
}

/// Read the exact story's blocks and cell paragraphs. Existing top-level and
/// direct-cell results precede nested cell paragraphs. An omitted scope
/// is the existing body-only read; a missing story never falls back to the body.
pub fn read_docx_scoped_blocks(
    bytes: &[u8],
    limits: ArchiveLimits,
    scope: Option<&DocxStoryScope>,
) -> Result<Vec<DocxBlock>, DoceditError> {
    let Some(scope) = scope else {
        return super::read_docx_blocks(bytes, limits);
    };
    crate::within(limits, || {
        preflight_with_limits(bytes, limits)?;
        let document = Document::parse(bytes)?;
        let mut blocks = read_document(&document)?
            .stories
            .into_iter()
            .find(|story| &story.scope == scope)
            .map(|story| story.blocks)
            .unwrap_or_default();
        let paragraphs = blocks
            .iter()
            .flat_map(|block| {
                block.cells.iter().flat_map(move |cell| {
                    cell.paragraphs.iter().map(move |paragraph| DocxBlock {
                        id: paragraph.id.clone(),
                        kind: super::DocxBlockKind::Paragraph,
                        role: None,
                        text: paragraph.text.clone(),
                        runs: Vec::new(),
                        cells: Vec::new(),
                        locked: paragraph.locked.or(block.locked),
                    })
                })
            })
            .collect::<Vec<_>>();
        blocks.extend(paragraphs);
        if let Some((_, source)) = story_blocks(&document)
            .into_iter()
            .find(|(candidate, _)| candidate == scope)
        {
            blocks.extend(super::cells::descendant_paragraph_blocks(
                source,
                matches!(scope, DocxStoryScope::Comment { .. }),
            ));
        }
        Ok(blocks)
    })
}

/// The authored native stories, in the same order for reads and anchors.
fn story_blocks(document: &Document) -> Vec<(DocxStoryScope, &[stemma::domain::TrackedBlock])> {
    let canonical = &document.snapshot().canonical;
    let mut stories = Vec::new();
    for story in &canonical.headers {
        if !story.synthesized {
            stories.push((
                DocxStoryScope::Header {
                    part_name: story.part_name.clone(),
                    band: (&story.kind).into(),
                },
                story.blocks.as_slice(),
            ));
        }
    }
    for story in &canonical.footers {
        if !story.synthesized {
            stories.push((
                DocxStoryScope::Footer {
                    part_name: story.part_name.clone(),
                    band: (&story.kind).into(),
                },
                story.blocks.as_slice(),
            ));
        }
    }
    for story in &canonical.footnotes {
        stories.push((
            DocxStoryScope::Footnote {
                id: story.id.clone(),
            },
            story.blocks.as_slice(),
        ));
    }
    for story in &canonical.endnotes {
        stories.push((
            DocxStoryScope::Endnote {
                id: story.id.clone(),
            },
            story.blocks.as_slice(),
        ));
    }
    for story in &canonical.comments {
        stories.push((
            DocxStoryScope::Comment {
                id: story.id.clone(),
            },
            story.blocks.as_slice(),
        ));
    }
    stories
}

/// Native story paragraphs, including direct table-cell paragraphs, in their
/// current accepted-inline reading with actual `w14:paraId` identities.
/// Deleted blocks and inline tombstones are not current anchor text. The body
/// reader keeps its redline semantics.
#[must_use]
pub fn story_anchor_blocks(
    document: &Document,
) -> Vec<(DocxStoryScope, Vec<crate::DocxAnchorBlock>)> {
    use stemma::domain::{BlockNode, TrackingStatus};
    story_blocks(document)
        .into_iter()
        .map(|(scope, blocks)| {
            let mut current: Vec<_> = blocks
                .iter()
                .filter_map(|tracked| {
                    if !matches!(
                        tracked.status,
                        TrackingStatus::Normal | TrackingStatus::Inserted(_)
                    ) || !matches!(tracked.block, BlockNode::Paragraph(_))
                    {
                        return None;
                    }
                    Some(tracked.clone())
                })
                .collect();
            for tracked in &mut current {
                if let BlockNode::Paragraph(paragraph) = &mut tracked.block {
                    paragraph.segments.retain(|segment| {
                        matches!(
                            segment.status,
                            TrackingStatus::Normal | TrackingStatus::Inserted(_)
                        )
                    });
                }
            }
            let para_ids: std::collections::HashMap<String, Option<String>> = current
                .iter()
                .filter_map(|tracked| match &tracked.block {
                    BlockNode::Paragraph(paragraph) => {
                        Some((paragraph.id.to_string(), paragraph.para_id.clone()))
                    }
                    _ => None,
                })
                .collect();
            // Reuse the native label/text reader after filtering only the
            // local clone. Neither canonical content nor native ids move.
            let view = stemma::view::build_story_blocks_view(&current);
            let mut anchors: Vec<_> = view
                .blocks
                .into_iter()
                .filter_map(|block| {
                    let block_id = block.id.to_string();
                    Some(crate::DocxAnchorBlock {
                        para_id: para_ids.get(&block_id)?.clone(),
                        block_id,
                        text: block.text,
                    })
                })
                .collect();
            anchors.extend(super::cells::anchor_blocks(blocks));
            (scope, anchors)
        })
        .collect()
}
