//! Native DOCX edit entry. The document compiler owns Word revision XML;
//! the vault owns retained proposals, actual-package diffing, and settlement.

use super::inspect::inspect;
use super::opc;
use super::session_validate::{diff_parts, validate};
use super::{
    EDIT_MANIFEST_SCHEMA_VERSION, EditManifest, EditOp, EditOutcome, EditProposal, MutationMode,
    OfficeFormat, RecalcStatus,
};
use crate::entity_id::EntityId;
use crate::error::{ArtifactError, Error, Result};

/// Apply one native, guarded Word transaction and return an uncommitted proposal.
/// The transaction is schema-checked by the document compiler; an invalid
/// target, stale guard or broken package never yields settleable bytes.
/// Spreadsheet operations continue through [`super::run_edit_roundtrip`].
pub fn run_docx_revision(
    input_bytes: &[u8],
    transaction_json: &str,
    run_ref: &str,
) -> Result<EditOutcome> {
    if run_ref.trim().is_empty() {
        return Err(Error::Artifact(ArtifactError::EditRoundtripFailed(
            "run_ref must be non-empty",
        )));
    }
    let before = opc::read(input_bytes)?;
    let inspection = inspect(&before, OfficeFormat::Docx);
    let current = oneiron_docedit::revise(input_bytes, transaction_json).map_err(|_| {
        Error::Artifact(ArtifactError::EditRoundtripFailed(
            "native docx revision failed validation or could not be written",
        ))
    })?;
    let after = match opc::read(&current) {
        Ok(package) => package,
        Err(_) => {
            return Ok(EditOutcome::Rejected {
                inspection,
                report: super::ValidationReport::single_failure(
                    "well_formed_opc",
                    "native docx output is not a readable OPC package",
                ),
            });
        }
    };
    let report = validate(&before, &after, OfficeFormat::Docx);
    if !report.ok {
        return Ok(EditOutcome::Rejected { inspection, report });
    }
    Ok(EditOutcome::Proposed(EditProposal {
        run_ref: run_ref.to_owned(),
        format: OfficeFormat::Docx,
        new_bytes: current,
        manifest: EditManifest {
            schema_version: EDIT_MANIFEST_SCHEMA_VERSION,
            format: OfficeFormat::Docx,
            ops: vec![EditOp::DocxRevision {
                transaction: transaction_json.to_owned(),
            }],
            touched_parts: diff_parts(&before, &after),
            mutation_mode: MutationMode::Full,
            warnings: Vec::new(),
        },
        inspection,
        validation: report,
        recalc: RecalcStatus::NotNeeded,
        calc_engine: None,
        base_version: None,
        base_content_hash: *blake3::hash(input_bytes).as_bytes(),
    }))
}

impl crate::Vault {
    /// Propose a tracked Word revision against the exact current blob head.
    /// The result is uncommitted and can be selected or discarded through the
    /// ordinary consent-gated, consume-once settlement door.
    pub fn propose_blob_artifact_docx_revision(
        &self,
        artifact_id: &EntityId,
        transaction_json: &str,
        run_ref: &str,
    ) -> Result<EditOutcome> {
        let head = self
            .blob_artifact_head(artifact_id)?
            .ok_or(Error::EntityNotFound)?;
        let body = self
            .get_blob_artifact(artifact_id)?
            .ok_or(Error::EntityNotFound)?;
        if OfficeFormat::from_media_type(&body.media_type)? != OfficeFormat::Docx {
            return Err(Error::Artifact(ArtifactError::InvalidEditManifest(
                "native docx revision requires a docx blob artifact",
            )));
        }
        let bytes = self
            .read_blob_artifact_version(artifact_id, head.version)?
            .ok_or(Error::EntityNotFound)?;
        let mut outcome = run_docx_revision(&bytes, transaction_json, run_ref)?;
        if let EditOutcome::Proposed(proposal) = &mut outcome {
            proposal.base_version = Some(head.version);
            proposal.calc_engine = head.calc_engine.map(Box::new);
        }
        Ok(outcome)
    }
}
