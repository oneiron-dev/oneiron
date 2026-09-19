//! Vault adapter and retained proposal compatibility over the document organ.
use super::{
    AppliedEdit, EditManifest, EditPlan, EditSession, OfficeDoc, OfficeFormat, RecalcStatus,
    StructureSummary, ValidationReport,
};
use crate::blob_artifact::BlobVersionProvenance;
use crate::{EntityId, Error, Result};
use oneiron_docedit::roundtrip as organ;

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
    pub engine: oneiron_docedit::calc::EngineId,
    pub prepared: oneiron_docedit::PreparedEdit,
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
    Proposed(Box<EditProposal>),
    Rejected {
        inspection: StructureSummary,
        report: ValidationReport,
    },
}

struct SessionAdapter<'a, S>(&'a S);
impl<S: EditSession> organ::EditSession<Error> for SessionAdapter<'_, S> {
    fn engine_id(&self) -> oneiron_docedit::calc::EngineId {
        self.0.engine_id()
    }
    fn apply_edits(&self, doc: &OfficeDoc, plan: &EditPlan) -> Result<AppliedEdit> {
        self.0.apply_edits(doc, plan)
    }
    fn recalc(&self, doc: &OfficeDoc) -> Result<Vec<u8>> {
        self.0.recalc(doc)
    }
    fn supports_recalc(&self) -> bool {
        self.0.supports_recalc()
    }
}
fn from_organ(outcome: organ::EditOutcome) -> EditOutcome {
    match outcome {
        organ::EditOutcome::Rejected { inspection, report } => {
            EditOutcome::Rejected { inspection, report }
        }
        organ::EditOutcome::Proposed(p) => EditOutcome::Proposed(Box::new(EditProposal {
            run_ref: p.run_ref,
            format: p.format,
            new_bytes: p.new_bytes,
            manifest: p.manifest,
            inspection: p.inspection,
            validation: p.validation,
            recalc: p.recalc,
            base_version: p.base_version,
            base_content_hash: p.base_content_hash,
            prepared: p.prepared,
            engine: p.engine,
        })),
    }
}
pub fn run_edit_roundtrip<S: EditSession>(
    session: &S,
    input_bytes: &[u8],
    format: OfficeFormat,
    plan: &EditPlan,
    run_ref: &str,
) -> Result<EditOutcome> {
    organ::run_edit_roundtrip(&SessionAdapter(session), input_bytes, format, plan, run_ref)
        .map(from_organ)
}
impl organ::DocumentStore for crate::Vault {
    type Error = Error;
    fn document_head(&self, artifact: &[u8; 16]) -> Result<Option<organ::DocumentHead>> {
        let id = EntityId::from_bytes(*artifact)?;
        let Some(head) = self.blob_artifact_head(&id)? else {
            return Ok(None);
        };
        let body = self.get_blob_artifact(&id)?.ok_or(Error::EntityNotFound)?;
        Ok(Some(organ::DocumentHead {
            version: head.version,
            content_hash: head.content_hash,
            format: OfficeFormat::from_media_type(&body.media_type)?,
        }))
    }
    fn document_bytes(&self, artifact: &[u8; 16], version: u64) -> Result<Option<Vec<u8>>> {
        self.read_blob_artifact_version(&EntityId::from_bytes(*artifact)?, version)
    }
}
impl crate::Vault {
    pub fn propose_blob_artifact_edit<S: EditSession>(
        &self,
        artifact_id: &EntityId,
        session: &S,
        plan: &EditPlan,
        run_ref: &str,
    ) -> Result<EditOutcome> {
        organ::propose_document_edit(
            self,
            artifact_id.as_bytes(),
            &SessionAdapter(session),
            plan,
            run_ref,
        )
        .map(from_organ)
    }
}

impl crate::Vault {
    /// Propose a native Word edit. Select/discard use the same ARTL settlement
    /// door as spreadsheet edits, with the base version committed here.
    pub fn propose_blob_artifact_docx_edit(
        &self,
        artifact_id: &EntityId,
        plan: &oneiron_docedit::docx::DocxPlan,
        run_ref: &str,
    ) -> Result<EditOutcome> {
        use organ::DocumentStore;
        let head = self
            .document_head(artifact_id.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        if head.format != OfficeFormat::Docx {
            return Err(
                oneiron_docedit::Error::InvalidManifest("native Word plan requires docx").into(),
            );
        }
        let bytes = self
            .document_bytes(artifact_id.as_bytes(), head.version)?
            .ok_or(Error::EntityNotFound)?;
        if blake3::hash(&bytes).as_bytes() != &head.content_hash {
            return Err(oneiron_docedit::Error::CommitMismatch.into());
        }
        let outcome = oneiron_docedit::docx::run_docx_roundtrip(&bytes, plan, run_ref)?
            .into_edit_outcome(Some(head.version))?;
        Ok(from_organ(outcome))
    }
}
