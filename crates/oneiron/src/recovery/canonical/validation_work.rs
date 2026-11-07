//! Ordered canonical validation groups shared by synchronous and turn-based recovery.

use super::{
    CanonicalSnapshot, asset_body_refs, row_births, source_audiences, validation, withdrawn_cutoffs,
};
use crate::error::Result;

#[derive(Default)]
pub(crate) struct CanonicalValidation {
    stage: ValidationStage,
    manifest: validation::ManifestValidation,
    window_rows: validation::WindowRows,
    document_rows: validation::DocumentRows,
    entity_document_rows: validation::EntityDocumentRows,
    asset_body_refs: asset_body_refs::AssetBodyRefsValidation,
    row_births: row_births::RowBirthsValidation,
    withdrawn_cutoffs: withdrawn_cutoffs::WithdrawnCutoffsValidation,
}

#[derive(Default)]
enum ValidationStage {
    #[default]
    Manifest,
    WindowRows,
    AssetBodyRefs,
    Documents,
    EntityDocuments,
    RowBirths,
    SourceAudiences,
    WithdrawnCutoffs,
    Complete,
}

impl CanonicalValidation {
    /// Validate one group or one row page over the same immutable snapshot.
    pub(crate) fn advance(
        &mut self,
        snapshot: &CanonicalSnapshot,
        max_rows: usize,
    ) -> Result<bool> {
        self.stage = match self.stage {
            ValidationStage::Manifest => {
                if !self.manifest.advance(snapshot, max_rows)? {
                    return Ok(false);
                }
                self.manifest = validation::ManifestValidation::default();
                ValidationStage::WindowRows
            }
            ValidationStage::WindowRows => {
                if !self.window_rows.advance(snapshot, max_rows)? {
                    return Ok(false);
                }
                self.window_rows = validation::WindowRows::default();
                ValidationStage::AssetBodyRefs
            }
            ValidationStage::AssetBodyRefs => {
                if !self.asset_body_refs.advance(snapshot, max_rows)? {
                    return Ok(false);
                }
                self.asset_body_refs = asset_body_refs::AssetBodyRefsValidation::default();
                ValidationStage::Documents
            }
            ValidationStage::Documents => {
                if !self.document_rows.advance(snapshot, max_rows)? {
                    return Ok(false);
                }
                self.document_rows = validation::DocumentRows::default();
                ValidationStage::EntityDocuments
            }
            ValidationStage::EntityDocuments => {
                if !self.entity_document_rows.advance(snapshot, max_rows)? {
                    return Ok(false);
                }
                self.entity_document_rows = validation::EntityDocumentRows::default();
                ValidationStage::RowBirths
            }
            ValidationStage::RowBirths => {
                if !self.row_births.advance(snapshot, max_rows)? {
                    return Ok(false);
                }
                self.row_births = row_births::RowBirthsValidation::default();
                ValidationStage::SourceAudiences
            }
            ValidationStage::SourceAudiences => {
                source_audiences::validate(snapshot)?;
                ValidationStage::WithdrawnCutoffs
            }
            ValidationStage::WithdrawnCutoffs => {
                if !self.withdrawn_cutoffs.advance(snapshot, max_rows)? {
                    return Ok(false);
                }
                self.withdrawn_cutoffs = withdrawn_cutoffs::WithdrawnCutoffsValidation::default();
                ValidationStage::Complete
            }
            ValidationStage::Complete => return Ok(true),
        };
        Ok(matches!(self.stage, ValidationStage::Complete))
    }

    pub(crate) fn position(&self) -> String {
        if matches!(self.stage, ValidationStage::Manifest) {
            let (stage, next) = self.manifest.position();
            return format!("manifest {stage} {next}");
        }
        if matches!(self.stage, ValidationStage::WindowRows) {
            let (stage, next) = self.window_rows.position();
            return format!("window rows {stage} {next}");
        }
        if matches!(self.stage, ValidationStage::EntityDocuments) {
            let (stage, next) = self.entity_document_rows.position();
            return format!("entity documents {stage} {next}");
        }
        if matches!(self.stage, ValidationStage::Documents) {
            let (stage, next) = self.document_rows.position();
            return format!("NOTE documents {stage} {next}");
        }
        if matches!(self.stage, ValidationStage::AssetBodyRefs) {
            return format!("asset body references {}", self.asset_body_refs.position());
        }
        if matches!(self.stage, ValidationStage::RowBirths) {
            return format!("row births {}", self.row_births.position());
        }
        if matches!(self.stage, ValidationStage::WithdrawnCutoffs) {
            let (stage, next) = self.withdrawn_cutoffs.position();
            return format!("withdrawn cutoffs {stage} {next}");
        }
        match self.stage {
            ValidationStage::Manifest => "manifest",
            ValidationStage::WindowRows => "window rows",
            ValidationStage::AssetBodyRefs => "asset body references",
            ValidationStage::Documents => "NOTE documents",
            ValidationStage::EntityDocuments => "entity documents",
            ValidationStage::RowBirths => "row births",
            ValidationStage::SourceAudiences => "source audiences",
            ValidationStage::WithdrawnCutoffs => "withdrawn cutoffs",
            ValidationStage::Complete => "complete",
        }
        .to_owned()
    }
}
