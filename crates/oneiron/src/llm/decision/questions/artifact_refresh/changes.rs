//! Sparse changed-unit reads for standing artifact questions.

use super::{Asking, Changed, Selection};
use crate::edit_roundtrip::judgment_cells::named_sheet_cells;
use crate::edit_roundtrip::{CellRef, CellValue, SheetRowSelection};
use crate::office_body::LivePin;
use crate::{EntityId, Result};

impl Asking<'_> {
    /// The units of `selection` whose reads moved between the `baseline` versions the
    /// question answered and the `observed` heads: a row whose read cells (or header)
    /// changed, its answer cell aside; a paragraph whose text changed; a folder item whose
    /// file has a newer head. `None` when a version no longer reads, so all are asked.
    /// An export of the live edit the last ask already read asks nothing again: reads
    /// compare past the newest export since the baseline, as a held answer's split does
    /// (FIX 12049).
    pub(super) fn changed_units(
        &self,
        artifact: EntityId,
        selection: &Selection<'_>,
        baseline: &[(EntityId, u64)],
        observed: &[(EntityId, u64)],
        pinned: &[(EntityId, LivePin)],
    ) -> Result<Option<Changed>> {
        let vault = self.vault;
        let version = |versions: &[(EntityId, u64)], id: EntityId| {
            versions
                .iter()
                .find(|(read, _)| *read == id)
                .map_or(0, |(_, version)| *version)
        };
        let pin = |id: EntityId| {
            pinned
                .iter()
                .find(|(read, _)| *read == id)
                .map(|(_, pin)| pin)
        };
        if let Selection::FolderItems { items, .. } = selection {
            let mut changed = Vec::new();
            for item in items {
                let (base, head) = (
                    version(baseline, item.artifact),
                    version(observed, item.artifact),
                );
                if base == head {
                    continue;
                }
                if let Some(pin) = pin(item.artifact)
                    && let Some(span) = vault.export_span(&item.artifact, Some(pin), base, head)?
                {
                    if vault.live_body_changed_until(
                        &item.artifact,
                        Some(pin),
                        Some(span.frontier.as_slice()),
                    )? {
                        changed.push(*item);
                        continue;
                    }
                    // The export holds what the last ask already read; versions after it
                    // still ask, as today.
                    if span.bytes.is_none() {
                        continue;
                    }
                }
                changed.push(*item);
            }
            return Ok(Some(Changed::Items(changed)));
        }
        let (then, now) = (version(baseline, artifact), version(observed, artifact));
        // The newest export since the baseline holds the body as it stood at its
        // frontier, compared with the pin the last ask read (FIX 12017).
        let artifact_pin = pin(artifact);
        let exported = vault.export_span(&artifact, artifact_pin, then, now)?;
        let (Some(then), Some(now)) = (
            vault.read_blob_artifact_version(&artifact, then)?,
            vault.read_blob_artifact_version(&artifact, now)?,
        ) else {
            return Ok(None);
        };
        Ok(match selection {
            Selection::SheetRows {
                sheet,
                rows,
                answer_col,
                header_row,
                ..
            } => {
                let wanted = |cell: &CellRef| {
                    cell.col != *answer_col
                        && (rows.start.col..=rows.end.col).contains(&cell.col)
                        && ((rows.start.row..=rows.end.row).contains(&cell.row)
                            || Some(cell.row) == *header_row)
                };
                let (Ok(then), Ok(now)) = (
                    named_sheet_cells(&then, sheet, &wanted),
                    named_sheet_cells(&now, sheet, &wanted),
                ) else {
                    return Ok(None);
                };
                let exported_sheet = match (&exported, artifact_pin) {
                    (Some(span), Some(pin)) => vault.live_sheet_until(
                        &artifact,
                        Some(pin),
                        sheet,
                        Some((span.frontier.as_slice(), span.version)),
                    )?,
                    _ => None,
                };
                let export_cells = match exported.as_ref().and_then(|span| span.bytes.as_ref()) {
                    Some(bytes) => match named_sheet_cells(bytes, sheet, &wanted) {
                        Ok(cells) => Some(cells),
                        Err(_) => return Ok(None),
                    },
                    None => None,
                };
                let read_from = match &exported {
                    Some(span) if span.bytes.is_none() => &now,
                    Some(_) => export_cells.as_ref().unwrap_or(&then),
                    None => &then,
                };
                let changed = |cell: &CellRef| {
                    read_from.get(cell).unwrap_or(&CellValue::Blank)
                        != now.get(cell).unwrap_or(&CellValue::Blank)
                };
                let source_header_moved = header_row.is_some_and(|row| {
                    read_from
                        .keys()
                        .chain(now.keys())
                        .any(|cell| cell.row == row && wanted(cell) && changed(cell))
                });
                let live_cells = || {
                    exported_sheet
                        .iter()
                        .flat_map(|sheet| sheet.changed_cells())
                };
                let live_header_moved = header_row.is_some_and(|header| {
                    live_cells().any(|(row, col)| row == header && wanted(&CellRef { col, row }))
                });
                let header_moved = source_header_moved
                    || live_header_moved
                    || exported_sheet
                        .as_ref()
                        .is_some_and(|sheet| sheet.whole().is_some());
                let selected = if header_moved {
                    SheetRowSelection::range(rows.start.row, rows.end.row)
                } else {
                    let mut selected = SheetRowSelection::default();
                    for cell in read_from.keys().chain(now.keys()) {
                        if wanted(cell)
                            && changed(cell)
                            && (rows.start.row..=rows.end.row).contains(&cell.row)
                        {
                            selected.insert(cell.row);
                        }
                    }
                    for (row, col) in live_cells() {
                        if wanted(&CellRef { col, row })
                            && (rows.start.row..=rows.end.row).contains(&row)
                        {
                            selected.insert(row);
                        }
                    }
                    selected
                };
                Some(Changed::Rows(selected))
            }
            Selection::Paragraphs { blocks, scope, .. } => {
                let limits = {
                    let txn = vault.store.env.read_txn()?;
                    vault.docx_archive_limits_in_txn(&txn, Some(self.record.principal))?
                };
                // The DOCX reads run in the host's memory (FIX 10651); a resource
                // refusal is the engine's error, never a quiet re-ask of all (FIX 10587).
                let resources = crate::office_body::document_resources();
                let texts = |bytes: &[u8]| {
                    let read = match resources.docx(|| {
                        oneiron_docedit::docx_body::read_docx_scoped_blocks(bytes, limits, *scope)
                    }) {
                        Ok(read) => read,
                        Err(error) => {
                            if let Some(refusal) = error.resource() {
                                return Err(crate::office_body::document_refused(refusal));
                            }
                            return Ok(None);
                        }
                    };
                    Ok(Some(
                        read.into_iter()
                            .map(|block| {
                                let text = *blake3::hash(block.text.as_bytes()).as_bytes();
                                (block.id, text)
                            })
                            .collect::<std::collections::BTreeMap<_, _>>(),
                    ))
                };
                let (Some(then), Some(now)) = (texts(&then)?, texts(&now)?) else {
                    return Ok(None);
                };
                let exported_units = match (&exported, artifact_pin) {
                    (Some(span), Some(pin)) => vault.live_scoped_paragraphs_until(
                        &artifact,
                        Some(pin),
                        *scope,
                        Some(span.frontier.as_slice()),
                    )?,
                    _ => None,
                };
                let export_texts = match exported.as_ref().and_then(|span| span.bytes.as_ref()) {
                    Some(bytes) => match texts(bytes)? {
                        Some(texts) => Some(texts),
                        None => return Ok(None),
                    },
                    None => None,
                };
                let read_from = match &exported {
                    Some(span) if span.bytes.is_none() => &now,
                    Some(_) => export_texts.as_ref().unwrap_or(&then),
                    None => &then,
                };
                Some(Changed::Blocks(
                    blocks
                        .iter()
                        .filter(|block| {
                            read_from.get(*block) != now.get(*block)
                                || exported_units
                                    .as_ref()
                                    .is_some_and(|units| units.change(*block).is_some())
                        })
                        .cloned()
                        .collect(),
                ))
            }
            Selection::FolderItems { .. } => None,
        })
    }
}
