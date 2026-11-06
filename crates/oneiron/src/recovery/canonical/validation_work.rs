//! Ordered canonical validation groups shared by synchronous and turn-based recovery.

use super::{CanonicalSnapshot, asset_body_refs, row_births, validation, withdrawn_cutoffs};
use crate::error::Result;

#[derive(Default)]
pub(crate) struct CanonicalValidation {
    stage: ValidationStage,
    window_rows: validation::WindowRows,
    document_rows: validation::DocumentRows,
    asset_body_refs: asset_body_refs::AssetBodyRefsValidation,
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
                validation::validate_manifest_and_order(snapshot)?;
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
                validation::validate_entity_documents(snapshot)?;
                ValidationStage::RowBirths
            }
            ValidationStage::RowBirths => {
                row_births::validate(snapshot)?;
                ValidationStage::WithdrawnCutoffs
            }
            ValidationStage::WithdrawnCutoffs => {
                withdrawn_cutoffs::validate(snapshot)?;
                ValidationStage::Complete
            }
            ValidationStage::Complete => return Ok(true),
        };
        Ok(matches!(self.stage, ValidationStage::Complete))
    }

    pub(crate) fn position(&self) -> String {
        if matches!(self.stage, ValidationStage::WindowRows) {
            let (stage, next) = self.window_rows.position();
            return format!("window rows {stage} {next}");
        }
        if matches!(self.stage, ValidationStage::Documents) {
            let (stage, next) = self.document_rows.position();
            return format!("NOTE documents {stage} {next}");
        }
        if matches!(self.stage, ValidationStage::AssetBodyRefs) {
            return format!("asset body references {}", self.asset_body_refs.position());
        }
        match self.stage {
            ValidationStage::Manifest => "manifest",
            ValidationStage::WindowRows => "window rows",
            ValidationStage::AssetBodyRefs => "asset body references",
            ValidationStage::Documents => "NOTE documents",
            ValidationStage::EntityDocuments => "entity documents",
            ValidationStage::RowBirths => "row births",
            ValidationStage::WithdrawnCutoffs => "withdrawn cutoffs",
            ValidationStage::Complete => "complete",
        }
        .to_owned()
    }
}
