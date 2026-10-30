//! The ask run a standing artifact question's selection builds.

use super::{Changed, Selection};
use crate::edit_roundtrip::{
    ArtifactAsk, ArtifactAskRun, FolderAsk, FolderItem, ParagraphAsk, SheetRowsAsk,
};
use crate::{EntityId, Result, Vault};

/// The builder `selection` names, over the readable `files` of a folder ask, asking
/// only the units in `only` when an arrival named them; a folder ask reads its files
/// under `sight`, the one its saved lane holds now.
pub(super) fn ask_selection(
    vault: &Vault,
    artifact: EntityId,
    selection: &Selection<'_>,
    files: &[EntityId],
    only: Option<&Changed>,
    ask: ArtifactAsk<'_>,
    sight: crate::secret_custody::SecretSight,
) -> Result<ArtifactAskRun> {
    match selection {
        Selection::SheetRows {
            sheet,
            rows,
            answer_col,
            header_row,
            max_count,
        } => vault.ask_blob_artifact_sheet_rows(
            &artifact,
            &SheetRowsAsk {
                ask,
                sheet,
                rows: *rows,
                answer_col: *answer_col,
                header_row: *header_row,
                max_count_override: *max_count,
                only_rows: match only {
                    Some(Changed::Rows(rows)) => Some(rows),
                    _ => None,
                },
            },
        ),
        Selection::Paragraphs {
            blocks,
            author,
            labels,
        } => vault.ask_blob_artifact_paragraphs(
            &artifact,
            &ParagraphAsk {
                ask,
                blocks: match only {
                    Some(Changed::Blocks(changed)) => changed.as_slice(),
                    _ => *blocks,
                },
                author,
                labels,
            },
        ),
        Selection::FolderItems {
            sheet,
            answer_col,
            items,
            max_count,
        } => {
            let items: Vec<FolderItem> = items
                .iter()
                .filter(|item| files.contains(&item.artifact))
                .filter(|item| match only {
                    Some(Changed::Items(changed)) => changed.contains(*item),
                    _ => true,
                })
                .copied()
                .collect();
            if items.is_empty() {
                return Ok(ArtifactAskRun {
                    proposal: None,
                    abstained: Vec::new(),
                    refused: Vec::new(),
                    read_rows: Vec::new(),
                });
            }
            vault.ask_folder_items_into_sheet(
                &artifact,
                &FolderAsk {
                    ask,
                    items: &items,
                    sheet,
                    answer_col: *answer_col,
                    max_count_override: *max_count,
                    sight,
                },
            )
        }
    }
}
