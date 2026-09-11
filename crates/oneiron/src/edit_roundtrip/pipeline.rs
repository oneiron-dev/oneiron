//! Round-trip pipeline entry.

use super::address::validate_ops;
use super::inspect::{inspect, mutation_mode_for};
use super::opc;
use super::session_validate::{diff_parts, validate};
use super::{
    EDIT_MANIFEST_SCHEMA_VERSION, EditManifest, EditOp, EditPlan, EditSession, MutationMode,
    OfficeDoc, OfficeFormat, StructureSummary, ValidationReport,
};
use crate::blob_artifact::BlobVersionProvenance;
use crate::entity_id::EntityId;
use crate::error::ArtifactError;
use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};

/// Whether a recalc stage ran, and why not when it did not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecalcStatus {
    NotNeeded,
    Performed,
    /// Edited bytes could not be reparsed before recalc; the gate will reject.
    Skipped,
}

/// The retained-output proposal: the new bytes plus everything a settlement
/// (ARTL-4) or viewer (ARTL-5) needs, committing nothing.
#[derive(Debug, Clone)]
pub struct EditProposal {
    pub run_ref: String,
    pub format: OfficeFormat,
    pub new_bytes: Vec<u8>,
    pub manifest: EditManifest,
    pub inspection: StructureSummary,
    pub validation: ValidationReport,
    pub recalc: RecalcStatus,
    /// The artifact version these bytes were produced FROM, when the proposal
    /// was run against a blob artifact ([`crate::Vault::propose_blob_artifact_edit`]).
    /// `None` for a raw [`run_edit_roundtrip`] with no artifact binding. ARTL-4
    /// settle records it as the receipt's before-version ref.
    pub base_version: Option<u64>,
    /// Content hash (blake3) of the base bytes the edit started from. ARTL-4
    /// settle refuses a stale proposal by requiring this to still equal the
    /// artifact head's content hash — an intervening edit changes the head hash,
    /// so committing these bytes would clobber it and replay a stale manifest.
    pub base_content_hash: [u8; 32],
}

impl EditProposal {
    /// The provenance ARTL-4 appends when it settles this proposal into a new
    /// blob version.
    #[must_use]
    pub fn agent_run_provenance(&self) -> BlobVersionProvenance {
        BlobVersionProvenance::AgentRun {
            run_ref: self.run_ref.clone(),
        }
    }
}

/// The pipeline result: a settle-ready proposal, or a rejection whose report
/// says which corruption check failed. A rejection never carries proposal
/// bytes forward.
#[derive(Debug, Clone)]
pub enum EditOutcome {
    Proposed(EditProposal),
    Rejected {
        inspection: StructureSummary,
        report: ValidationReport,
    },
}

/// Runs the full four-stage edit round-trip against a copy of `input_bytes`.
///
/// The input bytes are never mutated. On success the returned
/// [`EditProposal`] is a retained output — nothing is written to any store.
pub fn run_edit_roundtrip<S: EditSession>(
    session: &S,
    input_bytes: &[u8],
    format: OfficeFormat,
    plan: &EditPlan,
    run_ref: &str,
) -> Result<EditOutcome> {
    if run_ref.trim().is_empty() {
        return Err(Error::Artifact(ArtifactError::EditRoundtripFailed(
            "run_ref must be non-empty",
        )));
    }

    // The op vocabulary and inspection are spreadsheet-specific, and `classify`
    // marks `word/` and `ppt/` parts Supported — so the passthrough gate would
    // not protect a docx/pptx from a mangling session and the fidelity law
    // would be vacuous. Until format-appropriate pipelines exist, accept only
    // xlsx/xlsm; a docx/pptx artifact is an unsupported-media-type refusal.
    if !matches!(format, OfficeFormat::Xlsx) {
        return Err(Error::Artifact(ArtifactError::InvalidEditManifest(
            "edit round-trip supports only xlsx/xlsm; docx and pptx are not yet supported",
        )));
    }

    // Reject a malformed plan before it can reach a session: cells, ranges, and
    // axis positions are 1-based, but the unchecked constructors let 0 through.
    validate_ops(&plan.ops)?;

    // Stage 0: decompose the input. A bad input is a hard error (the caller
    // handed us a broken blob), distinct from a session producing bad output.
    let before = opc::read(input_bytes)?;
    let doc_before = OfficeDoc::new(format, input_bytes.to_vec(), before.clone());

    // Stage 1: inspect-first.
    let inspection = inspect(&before, format);
    let (mutation_mode, mut warnings) = mutation_mode_for(&inspection);

    // Minimal-mutation mode preserves pivot/chart/macro parts byte-for-byte,
    // and those parts index into the grid by absolute address. A structural op
    // would shift that grid and leave the preserved parts stale, so refuse it
    // here rather than emit a silently-wrong file; cell-level ops stay allowed.
    if mutation_mode == MutationMode::Minimal && plan.ops.iter().any(EditOp::is_structural) {
        return Err(Error::Artifact(ArtifactError::InvalidEditManifest(
            "minimal-mutation mode refuses structural ops: preserved pivot/chart/macro parts would go stale against the shifted grid",
        )));
    }

    // Stage 2: targeted edit through the seam.
    let applied = session.apply_edits(&doc_before, plan)?;
    let mut current = applied.bytes;
    warnings.extend(applied.warnings);

    // Stage 3: recalc when inputs changed. Fail closed if the edit may change
    // formula values but this session image cannot recalc: retaining stale
    // cached formula values in the output is silent data corruption, so refuse
    // and let the caller route to a recalc-capable session rather than propose.
    let recalc = if plan.needs_recalc(&applied.applied_ops) {
        if !session.supports_recalc() {
            return Err(Error::Artifact(ArtifactError::EditRoundtripFailed(
                "edit may change formula values but the session cannot recalc; route to a recalc-capable session",
            )));
        }
        match opc::read(&current) {
            Ok(package) => {
                let edited = OfficeDoc::new(format, current.clone(), package);
                current = session.recalc(&edited)?;
                RecalcStatus::Performed
            }
            Err(_) => RecalcStatus::Skipped,
        }
    } else {
        RecalcStatus::NotNeeded
    };

    // Stage 4: corruption + passthrough gate over the actual output bytes.
    let after = match opc::read(&current) {
        Ok(package) => package,
        Err(_) => {
            let report = ValidationReport::single_failure(
                "well_formed_opc",
                "edit output is not a readable OPC package",
            );
            return Ok(EditOutcome::Rejected { inspection, report });
        }
    };

    let manifest = EditManifest {
        schema_version: EDIT_MANIFEST_SCHEMA_VERSION,
        format,
        ops: applied.applied_ops,
        touched_parts: diff_parts(&before, &after),
        mutation_mode,
        warnings,
    };

    let report = validate(&before, &after, format);
    if !report.ok {
        return Ok(EditOutcome::Rejected { inspection, report });
    }

    Ok(EditOutcome::Proposed(EditProposal {
        run_ref: run_ref.to_owned(),
        format,
        new_bytes: current,
        manifest,
        inspection,
        validation: report,
        recalc,
        // The raw round-trip has no artifact/version context; the base is the
        // input bytes it edited. `propose_blob_artifact_edit` fills base_version.
        base_version: None,
        base_content_hash: *blake3::hash(input_bytes).as_bytes(),
    }))
}

impl crate::Vault {
    /// Runs the ARTL-3 edit round-trip against the current head bytes of a
    /// blob artifact, returning a retained-output proposal.
    ///
    /// This commits nothing: the version append (with
    /// [`BlobVersionProvenance::AgentRun`]) and the receipt are ARTL-4's
    /// settlement, driven from the returned [`EditProposal`].
    pub fn propose_blob_artifact_edit<S: EditSession>(
        &self,
        artifact_id: &EntityId,
        session: &S,
        plan: &EditPlan,
        run_ref: &str,
    ) -> Result<EditOutcome> {
        let head = self
            .blob_artifact_head(artifact_id)?
            .ok_or(Error::EntityNotFound)?;
        let bytes = self
            .read_blob_artifact_version(artifact_id, head.version)?
            .ok_or(Error::EntityNotFound)?;
        let body = self
            .get_blob_artifact(artifact_id)?
            .ok_or(Error::EntityNotFound)?;
        let format = OfficeFormat::from_media_type(&body.media_type)?;
        let mut outcome = run_edit_roundtrip(session, &bytes, format, plan, run_ref)?;
        // Bind the proposal to the head it was produced from, so ARTL-4 settle
        // can refuse it if an intervening edit has moved the head since.
        if let EditOutcome::Proposed(proposal) = &mut outcome {
            proposal.base_version = Some(head.version);
        }
        Ok(outcome)
    }
}
