//! Ordered canonical validation groups shared by synchronous and turn-based recovery.

use super::{CanonicalSnapshot, row_births, validation, withdrawn_cutoffs};
use crate::error::Result;

#[derive(Default)]
pub(crate) struct CanonicalValidation {
    stage: ValidationStage,
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
    /// Validate one whole group. The caller retains the same immutable snapshot
    /// until every group passes; nested row walks are not paged here.
    pub(crate) fn advance(&mut self, snapshot: &CanonicalSnapshot) -> Result<bool> {
        self.stage = match self.stage {
            ValidationStage::Manifest => {
                validation::validate_manifest_and_order(snapshot)?;
                ValidationStage::WindowRows
            }
            ValidationStage::WindowRows => {
                validation::validate_window_rows(snapshot)?;
                ValidationStage::AssetBodyRefs
            }
            ValidationStage::AssetBodyRefs => {
                snapshot.validate_asset_body_refs()?;
                ValidationStage::Documents
            }
            ValidationStage::Documents => {
                validation::validate_documents(snapshot)?;
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

    pub(crate) fn position(&self) -> &'static str {
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
    }
}
