//! Modern comments use the existing retained-output proposal and consume-once settle.

use super::super::{
    EDIT_MANIFEST_SCHEMA_VERSION, EditManifest, EditOp, EditProposal, MutationMode, OfficeFormat,
    RecalcStatus, ValidationCheck, ValidationReport,
};
use super::super::{inspect, opc};
use super::comments::patch_with_mints;
use super::package::*;
use crate::entity_id::EntityId;

/// Produces one unsettled, byte-preserving comment proposal. No vault writes,
/// subprocess, recalc, or Office visibility claim occurs here.
pub fn run_comment_roundtrip(
    input: &[u8],
    patches: &[PptxCommentPatch],
    run_ref: &str,
) -> Result<EditProposal, PptxError> {
    if run_ref.trim().is_empty()
        || run_ref.len() > crate::blob_artifact::BLOB_ARTIFACT_RUN_REF_MAX_BYTES
    {
        return Err(PptxError::InvalidPatch);
    }
    let effects = super::comment_patch(input, patches)?;
    let package = opc::read(input).map_err(|_| PptxError::InvalidPackage)?;
    let mut ops: Vec<_> = patches
        .iter()
        .cloned()
        .map(|patch| EditOp::PptxComment { patch })
        .collect();
    ops.extend(
        effects
            .minted_slide_creation_ids
            .into_iter()
            .map(|(slide, creation_id)| EditOp::MintPptxSlideCreationId { slide, creation_id }),
    );
    Ok(EditProposal{
        run_ref:run_ref.to_owned(),format:OfficeFormat::Pptx,new_bytes:effects.new_bytes,
        manifest:EditManifest{schema_version:EDIT_MANIFEST_SCHEMA_VERSION,format:OfficeFormat::Pptx,ops,touched_parts:effects.touched_parts,mutation_mode:MutationMode::Minimal,warnings:Vec::new(),slide_judgments:Vec::new()},
        inspection:inspect::inspect(&package,OfficeFormat::Pptx),
        validation:ValidationReport{ok:true,checks:vec![
            ValidationCheck{name:"well_formed_opc",passed:true,detail:"bounded ZIP records and checksums verified".into()},
            ValidationCheck{name:"pptx_comment_links",passed:true,detail:"modern author/comment references and XML verified".into()},
            ValidationCheck{name:"pptx_semantic_write_set",passed:true,detail:"only declared comment, author, extension and relationship insertions; no Office-host proof".into()},
        ]},recalc:RecalcStatus::NotNeeded,calc_engine:None,base_version:None,base_content_hash:*blake3::hash(input).as_bytes(),
    })
}

/// Independently regenerates the declared semantic edit over the actual base.
/// Settlement must call this against its in-transaction base before append;
/// public proposal fields and a caller-provided validation report are not proof.
/// This also rejects tampering inside an otherwise allowed slide/comment part.
pub fn verify_comment_proposal(base: &[u8], proposal: &EditProposal) -> Result<(), PptxError> {
    if proposal.format != OfficeFormat::Pptx
        || proposal.manifest.format != OfficeFormat::Pptx
        || proposal.manifest.schema_version != EDIT_MANIFEST_SCHEMA_VERSION
        || proposal.base_content_hash != *blake3::hash(base).as_bytes()
        || proposal.manifest.mutation_mode != MutationMode::Minimal
    {
        return Err(PptxError::InvalidPatch);
    }
    let mut patches = Vec::new();
    let mut mints = Vec::new();
    for op in &proposal.manifest.ops {
        match op {
            EditOp::PptxComment { patch } if mints.is_empty() => patches.push(patch.clone()),
            EditOp::MintPptxSlideCreationId { slide, creation_id } => {
                mints.push((*slide, *creation_id));
            }
            _ => return Err(PptxError::InvalidPatch),
        }
    }
    let effects = patch_with_mints(base, &patches, Some(&mints))?;
    if effects.new_bytes != proposal.new_bytes
        || effects.touched_parts != proposal.manifest.touched_parts
    {
        return Err(PptxError::PartDiffOutsideTransaction);
    }
    Ok(())
}

impl crate::Vault {
    /// Binds a comment proposal to the artifact head. The caller owns managed
    /// annotation threads and settles through `settle_select_edit_proposal`.
    /// No version or annotation head is written while making this preview.
    pub fn propose_pptx_comment_edit(
        &self,
        artifact: &EntityId,
        patches: &[PptxCommentPatch],
        run_ref: &str,
    ) -> Result<EditProposal, PptxProposalError> {
        let head = self
            .blob_artifact_head(artifact)?
            .ok_or(crate::error::Error::EntityNotFound)?;
        let body = self
            .get_blob_artifact(artifact)?
            .ok_or(crate::error::Error::EntityNotFound)?;
        if OfficeFormat::from_media_type(&body.media_type)? != OfficeFormat::Pptx {
            return Err(PptxError::InvalidPatch.into());
        }
        let bytes = self
            .read_blob_artifact_version(artifact, head.version)?
            .ok_or(crate::error::Error::EntityNotFound)?;
        let mut proposal = run_comment_roundtrip(&bytes, patches, run_ref)?;
        proposal.base_version = Some(head.version);
        Ok(proposal)
    }
}
