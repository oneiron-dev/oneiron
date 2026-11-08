//! Exact native story paragraphs from the version bytes a locator names.

use super::TextLimits;
use crate::office_body::DocxStoryUnits;
use oneiron_docedit::DocxAnchorBlock;
use oneiron_docedit::docx_body::DocxStoryScope;

pub(crate) type StoryAnchors = Vec<(DocxStoryScope, Vec<DocxAnchorBlock>)>;

pub(in crate::anchored_annotation) fn read(
    bytes: &[u8],
    limits: &TextLimits,
) -> crate::Result<Option<StoryAnchors>> {
    let resources = crate::office_body::document_resources();
    let parsed = resources.docx(|| {
        oneiron_docedit::preflight_with_limits(bytes, limits.docx)?;
        oneiron_docedit::Document::parse(bytes)
            .map(|document| oneiron_docedit::docx_body::story_anchor_blocks(&document))
    });
    match parsed {
        Ok(stories) => Ok(Some(stories)),
        Err(error) => {
            if let Some(refusal) = oneiron_docedit::docx_resource(&error) {
                return Err(crate::office_body::document_refused(refusal));
            }
            Ok(None)
        }
    }
}

pub(in crate::anchored_annotation) fn units(
    bytes: &[u8],
    limits: &TextLimits,
) -> crate::Result<Option<Vec<DocxStoryUnits>>> {
    Ok(read(bytes, limits)?.map(|stories| {
        stories
            .into_iter()
            .map(|(scope, paragraphs)| DocxStoryUnits {
                scope,
                paragraphs: paragraphs
                    .into_iter()
                    .map(|p| (p.block_id, p.text))
                    .collect(),
            })
            .collect()
    }))
}
