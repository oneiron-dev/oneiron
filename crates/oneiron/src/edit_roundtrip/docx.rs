//! Native DOCX edit entry. The document compiler owns Word revision XML;
//! the vault owns retained proposals, actual-package diffing, and settlement.

use super::inspect::inspect;
use super::opc;
use super::session_validate::{diff_parts, validate};
use super::{
    EDIT_MANIFEST_SCHEMA_VERSION, EditManifest, EditOp, EditOutcome, EditProposal, MutationMode,
    OfficeFormat, RecalcStatus,
};
use crate::blob_artifact::read_blob_artifact_head_in_txn;
use crate::entity_id::EntityId;
use crate::error::{ArtifactError, Error, Result};
use oneiron_docedit::ArchiveLimits;

/// Apply one native, guarded Word transaction and return an uncommitted proposal.
/// The transaction is schema-checked by the document compiler; an invalid
/// target, stale guard or broken package never yields settleable bytes.
/// Spreadsheet operations continue through [`super::run_edit_roundtrip`].
pub fn run_docx_revision(
    input_bytes: &[u8],
    transaction_json: &str,
    run_ref: &str,
) -> Result<EditOutcome> {
    run_docx_revision_with_limits(
        input_bytes,
        transaction_json,
        run_ref,
        ArchiveLimits::DEFAULT,
    )
}

pub(super) fn run_docx_revision_with_limits(
    input_bytes: &[u8],
    transaction_json: &str,
    run_ref: &str,
    limits: ArchiveLimits,
) -> Result<EditOutcome> {
    if run_ref.trim().is_empty() {
        return Err(Error::Artifact(ArtifactError::EditRoundtripFailed(
            "run_ref must be non-empty",
        )));
    }
    oneiron_docedit::preflight_with_limits(input_bytes, limits).map_err(|_| {
        Error::Artifact(ArtifactError::EditRoundtripFailed(
            "docx input exceeds effective archive limits",
        ))
    })?;
    let before = opc::read_with_limits(input_bytes, limits)?;
    let inspection = inspect(&before, OfficeFormat::Docx);
    let transaction =
        oneiron_docedit::prepare_revision_transaction(transaction_json).map_err(|_| {
            Error::Artifact(ArtifactError::InvalidEditManifest(
                "native docx revision transaction is invalid",
            ))
        })?;
    let current =
        oneiron_docedit::revise_with_limits(input_bytes, &transaction, limits).map_err(|_| {
            Error::Artifact(ArtifactError::EditRoundtripFailed(
                "native docx revision failed validation or could not be written",
            ))
        })?;
    let after = match opc::read_with_limits(&current, limits) {
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
            ops: vec![EditOp::DocxRevision { transaction }],
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

/// Independently recheck the OPC linker/passthrough gate on the actual output
/// at settlement, not the caller's public `validation.ok` claim.
pub(crate) fn validate_docx_passthrough(
    base: &[u8],
    output: &[u8],
    limits: ArchiveLimits,
) -> Result<bool> {
    let before = opc::read_with_limits(base, limits)?;
    let after = opc::read_with_limits(output, limits)?;
    Ok(validate(&before, &after, OfficeFormat::Docx).ok)
}

/// Compare decompressed part content to a fresh engine replay. This is a
/// transaction-to-output binding, NOT a substitute for the separate fidelity
/// and Word-application checks; ZIP metadata and compression may differ.
pub(crate) fn docx_parts_match_replay(
    expected: &[u8],
    output: &[u8],
    limits: ArchiveLimits,
) -> Result<bool> {
    let expected = opc::read_with_limits(expected, limits)?;
    let actual = opc::read_with_limits(output, limits)?;
    Ok(expected.parts().len() == actual.parts().len()
        && expected
            .parts()
            .iter()
            .all(|part| actual.part(&part.name) == Some(part.data.as_slice())))
}

impl crate::Vault {
    /// Resolve trusted vault and exact-holder archive ceilings in the same
    /// LMDB snapshot as the document read; malformed policy refuses the edit.
    pub(crate) fn docx_archive_limits_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        holder: Option<EntityId>,
    ) -> Result<ArchiveLimits> {
        crate::gate::resolve_policy_manifest(&self.store, txn)?
            .docx_archive_limits(holder)
            .ok_or(Error::Artifact(ArtifactError::InvalidEditManifest(
                "docx archive policy is malformed",
            )))
    }

    /// Propose a tracked Word revision against the exact current blob head.
    /// The result is uncommitted and can be selected or discarded through the
    /// ordinary consent-gated, consume-once settlement door.
    pub fn propose_blob_artifact_docx_revision(
        &self,
        artifact_id: &EntityId,
        transaction_json: &str,
        run_ref: &str,
    ) -> Result<EditOutcome> {
        self.propose_blob_artifact_docx_revision_for_holder(
            artifact_id,
            transaction_json,
            run_ref,
            None,
        )
    }

    /// The caller's holder identity selects only restrictive policy rows.
    /// The settle actor is resolved again inside its write transaction, so a
    /// claimed holder can never widen the vault limit or bypass settlement.
    pub fn propose_blob_artifact_docx_revision_for_holder(
        &self,
        artifact_id: &EntityId,
        transaction_json: &str,
        run_ref: &str,
        holder: Option<EntityId>,
    ) -> Result<EditOutcome> {
        let rtxn = self.store.env.read_txn()?;
        let limits = self.docx_archive_limits_in_txn(&rtxn, holder)?;
        let head = read_blob_artifact_head_in_txn(&self.store, &rtxn, artifact_id)?
            .ok_or(Error::EntityNotFound)?;
        let body = self
            .get_blob_artifact_in_txn(&rtxn, artifact_id)?
            .ok_or(Error::EntityNotFound)?;
        if OfficeFormat::from_media_type(&body.media_type)? != OfficeFormat::Docx {
            return Err(Error::Artifact(ArtifactError::InvalidEditManifest(
                "native docx revision requires a docx blob artifact",
            )));
        }
        let bytes = self
            .read_blob_artifact_version_in_txn(&rtxn, artifact_id, head.version)?
            .ok_or(Error::EntityNotFound)?;
        let mut outcome = run_docx_revision_with_limits(&bytes, transaction_json, run_ref, limits)?;
        if let EditOutcome::Proposed(proposal) = &mut outcome {
            proposal.base_version = Some(head.version);
            proposal.calc_engine = head.calc_engine.map(Box::new);
        }
        Ok(outcome)
    }
}
