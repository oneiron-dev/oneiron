//! Version re-anchoring inside the exact native story a locator names.

use super::{Paragraphs, pair_paragraph, remap_span};
use crate::anchored_annotation::anchor_text::stories;
use crate::anchored_annotation::{AnnotationThread, Locator, ReanchorOutcome};
use crate::{EntityId, Result, Vault};
use oneiron_docedit::docx_body::DocxStoryScope;

type StoryParagraphs = Vec<(DocxStoryScope, Paragraphs)>;

pub(super) struct StoryReanchor {
    before: Option<StoryParagraphs>,
    after: Option<StoryParagraphs>,
}

impl StoryReanchor {
    pub(super) fn load(
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        artifact: &EntityId,
        from: u64,
        to: u64,
        threads: &[AnnotationThread],
    ) -> Result<Option<Self>> {
        if !threads.iter().any(|thread| {
            thread.anchor.version == from
                && !thread.is_drifted()
                && matches!(thread.anchor.locator, Locator::DocxStory { .. })
        }) {
            return Ok(None);
        }
        let limits = vault.text_limits_in_txn(txn)?;
        let read = |version| -> Result<Option<StoryParagraphs>> {
            let Some(bytes) = vault.read_blob_artifact_version_in_txn(txn, artifact, version)?
            else {
                return Ok(None);
            };
            Ok(stories::read(&bytes, &limits)?.map(|rows| {
                rows.into_iter()
                    .map(|(scope, paragraphs)| (scope, Paragraphs::new(paragraphs)))
                    .collect()
            }))
        };
        Ok(Some(Self {
            before: read(from)?,
            after: read(to)?,
        }))
    }

    pub(super) fn rebind(&self, locator: &Locator) -> ReanchorOutcome {
        let Locator::DocxStory {
            scope,
            para_path,
            char_start,
            char_end,
        } = locator
        else {
            return ReanchorOutcome::Drifted;
        };
        let mapped = || {
            let before = only_story(self.before.as_ref()?, scope)?;
            let after = only_story(self.after.as_ref()?, scope)?;
            let index = before
                .blocks
                .iter()
                .position(|block| block.block_id == *para_path)?;
            let shares_ids = before.ids.keys().any(|id| after.ids.contains_key(id));
            let paired = pair_paragraph(before, after, index, shares_ids, false)?;
            let new = &after.blocks[paired];
            let (start, end) = remap_span(
                &before.blocks[index].text,
                &new.text,
                *char_start,
                *char_end,
            )?;
            Locator::docx_story(scope.clone(), new.block_id.clone(), start, end).ok()
        };
        mapped().map_or(ReanchorOutcome::Drifted, ReanchorOutcome::Mapped)
    }
}

fn only_story<'a>(stories: &'a StoryParagraphs, scope: &DocxStoryScope) -> Option<&'a Paragraphs> {
    let mut matches = stories.iter().filter(|(found, _)| found == scope);
    let (_, paragraphs) = matches.next()?;
    matches.next().is_none().then_some(paragraphs)
}
