//! What an anchored comment reads of a live DOCX or XLSX body (FIX 2460):
//! the frontier a version projects, and the anchorable units at a frontier.
//! Entry: `Vault::office_body_units_in_txn`.

use super::*;
use oneiron_docedit::xlsx_body::XlsxAxisEdit;

/// One live body's anchorable units at a frontier.
pub(crate) enum OfficeBodyUnits {
    /// The blocks in order: the body's block id and its text.
    Docx(Vec<(String, String)>),
    /// The worksheets in order, by key and name, and the row and column
    /// edits since import, in order, by sheet key.
    Xlsx {
        sheets: Vec<(String, String)>,
        axes: Vec<(String, XlsxAxisEdit)>,
    },
}

impl Vault {
    /// Every artifact with a live DOCX or XLSX body.
    pub(crate) fn office_text_bodies_in_txn(&self, txn: &RoTxn<'_>) -> Result<Vec<EntityId>> {
        Ok(SOURCES
            .scan(&self.store, txn)?
            .into_iter()
            .filter(|(_, source)| source.kind != OfficeBodyKind::Pptx)
            .map(|(artifact, _)| artifact)
            .collect())
    }

    /// The artifact's newest export: its version and the body frontier it
    /// projects.
    pub(crate) fn office_body_latest_export_in_txn(
        &self,
        txn: &RoTxn<'_>,
        artifact: &EntityId,
    ) -> Result<Option<(u64, Vec<u8>)>> {
        let mut exports = EXPORTS.iter_rev_from(&self.store, txn, artifact.as_bytes())?;
        Ok(exports
            .next()
            .transpose()?
            .map(|(_, record)| (record.version, record.frontier)))
    }

    /// The body frontier whose projection `version` holds: the import's for
    /// the imported version, an export's for the version it landed. `None`
    /// when the artifact has no DOCX or XLSX body or the body never held it.
    pub(crate) fn office_body_frontier_of_version_in_txn(
        &self,
        txn: &RoTxn<'_>,
        artifact: &EntityId,
        version: u64,
    ) -> Result<Option<Vec<u8>>> {
        let Some(source) = SOURCES.get(&self.store, txn, artifact)? else {
            return Ok(None);
        };
        if source.kind == OfficeBodyKind::Pptx {
            return Ok(None);
        }
        if version == source.source_version {
            return Ok(Some(self.head_in_txn(txn, artifact)?.import_frontier));
        }
        Ok(EXPORTS
            .get(&self.store, txn, &version_key(artifact, version))?
            .map(|record| record.frontier))
    }

    /// The head frontier of the artifact's DOCX or XLSX body; `None` for no
    /// body or a deck.
    pub(crate) fn office_body_frontier_in_txn(
        &self,
        txn: &RoTxn<'_>,
        artifact: &EntityId,
    ) -> Result<Option<Vec<u8>>> {
        match SOURCES.get(&self.store, txn, artifact)? {
            Some(source) if source.kind != OfficeBodyKind::Pptx => {
                Ok(Some(self.head_in_txn(txn, artifact)?.frontier))
            }
            _ => Ok(None),
        }
    }

    /// The units of the artifact's DOCX or XLSX body at frontier `at`; `None`
    /// for no body or a deck.
    pub(crate) fn office_body_units_in_txn(
        &self,
        txn: &RoTxn<'_>,
        artifact: &EntityId,
        at: &[u8],
    ) -> Result<Option<OfficeBodyUnits>> {
        let Some(source) = SOURCES.get(&self.store, txn, artifact)? else {
            return Ok(None);
        };
        Ok(match source.kind {
            OfficeBodyKind::Docx => {
                let (_, doc) = self.loro_body(txn, artifact, source.kind, Some(at))?;
                let blocks = docx::read(&doc)?.blocks;
                Some(OfficeBodyUnits::Docx(
                    blocks
                        .into_iter()
                        .map(|block| (block.id, block.text))
                        .collect(),
                ))
            }
            OfficeBodyKind::Xlsx => {
                let (_, doc) = self.loro_body(txn, artifact, source.kind, Some(at))?;
                let body = xlsx::read(&doc)?;
                Some(OfficeBodyUnits::Xlsx {
                    sheets: body
                        .sheets
                        .into_iter()
                        .map(|sheet| (sheet.key, sheet.name))
                        .collect(),
                    axes: body.axes,
                })
            }
            OfficeBodyKind::Pptx => None,
        })
    }
}
