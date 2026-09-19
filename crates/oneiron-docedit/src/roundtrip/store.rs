//! Narrow storage interface: the document organ cannot open a vault or write a ledger.
use super::{EditOutcome, EditPlan, EditSession, OfficeFormat, run_edit_roundtrip};
use crate::Error;

#[derive(Debug, Clone, Copy)]
pub struct DocumentHead {
    pub version: u64,
    pub content_hash: [u8; 32],
    pub format: OfficeFormat,
}
/// Storage owns identity resolution and durability. The organ consumes snapshots only.
pub trait DocumentStore {
    type Error: From<Error>;
    fn document_head(
        &self,
        artifact: &[u8; 16],
    ) -> std::result::Result<Option<DocumentHead>, Self::Error>;
    fn document_bytes(
        &self,
        artifact: &[u8; 16],
        version: u64,
    ) -> std::result::Result<Option<Vec<u8>>, Self::Error>;
}

pub fn propose_document_edit<D: DocumentStore, S: EditSession<D::Error>>(
    store: &D,
    artifact: &[u8; 16],
    session: &S,
    plan: &EditPlan,
    run_ref: &str,
) -> std::result::Result<EditOutcome, D::Error> {
    let head = store
        .document_head(artifact)?
        .ok_or(Error::EditFailed("document head missing"))?;
    let bytes = store
        .document_bytes(artifact, head.version)?
        .ok_or(Error::EditFailed("document version missing"))?;
    if blake3::hash(&bytes).as_bytes() != &head.content_hash {
        return Err(Error::EditFailed("document version hash mismatch").into());
    }
    let mut result = run_edit_roundtrip(session, &bytes, head.format, plan, run_ref)?;
    if let EditOutcome::Proposed(proposal) = &mut result {
        proposal.base_version = Some(head.version);
        proposal.prepared = crate::prepare(crate::PrepareInput {
            base_content_hash: proposal.base_content_hash,
            base_version: proposal.base_version,
            run_ref: &proposal.run_ref,
            output: &proposal.new_bytes,
            writes: &proposal.manifest,
            report: &proposal.validation,
            engine: &proposal.engine,
        })?;
    }
    Ok(result)
}
