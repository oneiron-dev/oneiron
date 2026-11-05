//! Core half of `blob_artifact::deck_doors`: its store-layer items live in `oneiron_store::blob_artifact::deck_doors` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::blob_artifact::deck_doors::*;

use crate::blob_artifact::deck_inspection::DeckRejectionInspection;
use crate::blob_artifact::office_address::OfficeFormat;
use crate::edit_roundtrip::DeckEditRejection;
use crate::edit_roundtrip::pptx::inspect_pptx_with_limits;
use crate::entity_doc::document_resources::{document_refused, document_resources};
use crate::entity_id::EntityId;
use crate::error::{ArtifactError, Error};
use crate::memory::Memory;
use crate::vault::entity_refs::resolve_entity_ref;
use oneiron_contracts::memory::{MEMORY_CODE_FORBIDDEN, MemoryError, MemoryResult};
use oneiron_docedit::edit::transaction::{Digest, IdMarks};
use oneiron_docedit::edit::wire::{
    DeckIdentityAmbiguity, DeckSlideInspection, DeckTransactionRefusal, inspect_deck,
};
use oneiron_docedit::pptx_comments::PptxInspection;
use oneiron_docedit::retained_opc::Package;
use serde::{Deserialize, Serialize};

/// A refused deck transaction: the refusal by name, beside the base read as
/// a deck (FIX 4486) and the corruption-gate report the editor wrote for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DeckProposeRejection {
    pub inspection: DeckRejectionInspection,
    pub report: DeckRejectionReport,
    /// Why it refused: a `step` refusal names the step's index and verb and
    /// its canon refusal (`target_changed`, `ambiguous_anchor`, ...).
    pub refusal: DeckTransactionRefusal,
}

impl From<DeckEditRejection> for DeckProposeRejection {
    fn from(rejection: DeckEditRejection) -> Self {
        let DeckEditRejection {
            inspection,
            report,
            refusal,
        } = rejection;
        Self {
            inspection,
            report: DeckRejectionReport {
                ok: report.ok,
                checks: report
                    .checks
                    .into_iter()
                    .map(|check| DeckRejectionCheck {
                        name: check.name.to_owned(),
                        passed: check.passed,
                        detail: check.detail,
                    })
                    .collect(),
            },
            refusal: DeckTransactionRefusal::from(&refusal),
        }
    }
}

impl Memory<'_> {
    /// `vault.artifacts.inspect_deck`: one PPTX version's native edit targets,
    /// read through the caller's file sight like its units, under the vault's
    /// package and comment budgets.
    pub fn artifacts_inspect_deck(
        &self,
        input: &DeckInspectRequest,
    ) -> MemoryResult<DeckInspectionView> {
        let vault = self.vault();
        let artifact = resolve_entity_ref(vault, &input.artifact_ref)?;
        let file = self
            .export_blob_artifact_sighted(&artifact, input.version, None)?
            .ok_or_else(|| MemoryError::not_found("artifact version not found"))?;
        if OfficeFormat::from_media_type(&file.media_type).ok() != Some(OfficeFormat::Pptx) {
            return Err(MemoryError::bad_request(
                "a deck inspection reads a pptx blob artifact",
            ));
        }
        // A masked read is not the version's bytes: its fingerprints would
        // address nothing a transaction can edit.
        if *blake3::hash(&file.bytes).as_bytes() != file.content_hash {
            return Err(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "this version reads masked to this caller, so its edit targets are not the version's",
                &[
                    "A deck stored with keys in it is inspected by a reader whose file sight covers them.",
                ],
            ));
        }
        let (limits, comment_limits, history) = {
            let txn = vault.store.env.read_txn().map_err(Error::from)?;
            let limits = vault.docedit_package_limits_in_txn(&txn)?;
            let comment_limits =
                crate::gate::resolve_policy_manifest(&vault.store, &txn)?.pptx_comment_limits();
            (
                limits,
                comment_limits,
                vault.deck_id_marks_in_txn(&txn, &artifact)?,
            )
        };
        let comment_limits = comment_limits.ok_or(Error::Artifact(
            ArtifactError::InvalidEditManifest("PowerPoint comment limits policy failed closed"),
        ))?;
        // The entry count is an observation (FIX 9617): the package reserves
        // its memory through the host's port, and only the machine's floor
        // or the host's wait refuses, typed, never as a bad request.
        let package =
            Package::open(&file.bytes, limits, &document_resources()).map_err(|error| {
                error.resource().map_or_else(
                    || {
                        MemoryError::bad_request(format!(
                            "the deck package cannot be opened: {error}"
                        ))
                    },
                    |refusal| document_refused(refusal).into(),
                )
            })?;
        let deck = inspect_deck(&package).map_err(|error| {
            error.resource().map_or_else(
                || MemoryError::bad_request(format!("the deck cannot be read: {error}")),
                |refusal| document_refused(refusal).into(),
            )
        })?;
        let mut marks = history;
        marks.join(&deck.marks);
        let comments = match inspect_pptx_with_limits(&file.bytes, &comment_limits) {
            Ok(inspection) => DeckCommentInspection::Inspected { inspection },
            Err(refusal) => match refusal.resource() {
                Some(resource) => return Err(document_refused(resource).into()),
                None => DeckCommentInspection::Refused {
                    reason: refusal.to_string(),
                },
            },
        };
        Ok(DeckInspectionView {
            artifact_id: artifact,
            version: file.version,
            base: Digest(file.content_hash),
            marks,
            slides: deck.slides,
            ambiguities: deck.ambiguities,
            comments,
        })
    }
}
