//! Lower native Word edits into the shared checked document settlement input.
use super::{DocxOutcome, DocxProposal, DocxValidationReport};
use crate::roundtrip::{
    EditManifest, EditOp, EditOutcome, EditProposal, MutationMode, OfficeFormat, RecalcStatus,
    ValidationCheck, ValidationReport,
};
use crate::{PrepareInput, Result};

impl crate::PreparationReport for DocxValidationReport {
    fn passed(&self) -> bool {
        self.ok && !self.checks.is_empty() && self.checks.iter().all(|check| check.passed)
    }
}

impl From<DocxValidationReport> for ValidationReport {
    fn from(report: DocxValidationReport) -> Self {
        Self {
            ok: report.ok,
            checks: report
                .checks
                .into_iter()
                .map(|check| ValidationCheck {
                    name: check.name,
                    passed: check.passed,
                    detail: check.detail,
                })
                .collect(),
        }
    }
}

impl DocxProposal {
    /// Bind a native proposal to a storage version and the common op vocabulary.
    /// The original commitment is checked before any re-binding.
    pub fn into_edit_proposal(self, base_version: Option<u64>) -> Result<EditProposal> {
        let engine = self.manifest.engine.engine_id();
        self.prepared.verify(PrepareInput {
            base_content_hash: self.base_content_hash,
            base_version: None,
            run_ref: &self.run_ref,
            output: &self.new_bytes,
            writes: &self.manifest,
            report: &self.validation,
            engine: &engine,
        })?;
        let package = crate::opc::read(&self.new_bytes)?;
        let inspection = crate::roundtrip::inspect::inspect(&package, OfficeFormat::Docx);
        let manifest = EditManifest {
            schema_version: crate::roundtrip::EDIT_MANIFEST_SCHEMA_VERSION,
            format: OfficeFormat::Docx,
            ops: self.manifest.ops.into_iter().map(EditOp::Docx).collect(),
            touched_parts: self.manifest.touched_parts,
            mutation_mode: MutationMode::Minimal,
            warnings: Vec::new(),
        };
        let validation: ValidationReport = self.validation.into();
        let prepared = crate::prepare(PrepareInput {
            base_content_hash: self.base_content_hash,
            base_version,
            run_ref: &self.run_ref,
            output: &self.new_bytes,
            writes: &manifest,
            report: &validation,
            engine: &engine,
        })?;
        Ok(EditProposal {
            run_ref: self.run_ref,
            format: OfficeFormat::Docx,
            new_bytes: self.new_bytes,
            manifest,
            inspection,
            validation,
            recalc: RecalcStatus::NotNeeded,
            base_version,
            base_content_hash: self.base_content_hash,
            engine,
            prepared,
        })
    }
}

impl DocxOutcome {
    /// Convert to the same outcome accepted by the engine's single settlement door.
    pub fn into_edit_outcome(self, base_version: Option<u64>) -> Result<EditOutcome> {
        match self {
            Self::Proposed(proposal) => Ok(EditOutcome::Proposed(Box::new(
                proposal.into_edit_proposal(base_version)?,
            ))),
            Self::Rejected { report, .. } => Ok(EditOutcome::Rejected {
                inspection: crate::roundtrip::StructureSummary {
                    format: OfficeFormat::Docx,
                    sheets: Vec::new(),
                    defined_names: Vec::new(),
                    has_pivots: false,
                    has_charts: false,
                    has_macros: false,
                    cross_sheet_dependencies: Vec::new(),
                    unknown_parts: Vec::new(),
                },
                report: report.into(),
            }),
        }
    }
}
