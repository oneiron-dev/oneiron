//! The native deck edit door's typed wire (DOOR-142 A, ARCH-0077 "Edit target
//! choice"): `vault.artifacts.inspect_deck`, the read an edit is addressed
//! from, and the typed rejection `vault.artifacts.propose_deck` answers a
//! refused transaction with.
//!
//! An inspection reads one version through the caller's file sight, as its
//! units do, and returns what the organ reads: each slide part and native
//! slide and shape id with the content fingerprints a transaction step
//! expects, every duplicate identity the deck view reports, the managed
//! native-id marks, and, apart, the comment inspection with its own
//! fingerprints. It mints no id and computes no fingerprint of its own.

use oneiron_docedit::edit::transaction::{Digest, IdMarks};
use oneiron_docedit::edit::wire::{
    DeckIdentityAmbiguity, DeckSlideInspection, DeckTransactionRefusal, inspect_deck,
};
use oneiron_docedit::pptx_comments::PptxInspection;
use oneiron_docedit::retained_opc::Package;
use serde::{Deserialize, Serialize};

use crate::edit_roundtrip::pptx::inspect_pptx_with_limits;
use crate::edit_roundtrip::{DeckEditRejection, DeckRejectionInspection, OfficeFormat};
use crate::entity_id::EntityId;
use crate::error::{ArtifactError, Error};
use crate::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult, resolve_entity_ref};
use crate::office_body::{document_refused, document_resources};

/// One PPTX version to inspect: `version`, or the head when absent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeckInspectRequest {
    pub artifact_ref: String,
    #[serde(default)]
    pub version: Option<u64>,
}

/// One PPTX version's native edit targets and, apart, its comment identities.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DeckInspectionView {
    pub artifact_id: EntityId,
    pub version: u64,
    /// BLAKE3 of this version's bytes: the `base` a transaction over it
    /// names. A transaction over an older version refuses `base_changed`.
    pub base: Digest,
    /// The deck's managed native-id history joined with the marks this
    /// version shows; a transaction's new ids go above them.
    pub marks: IdMarks,
    /// Every slide in presentation order, each shape with the content
    /// fingerprint a step's `expected` names. Duplicate ids are kept.
    pub slides: Vec<DeckSlideInspection>,
    /// Duplicate identity evidence, reported and never repaired.
    pub ambiguities: Vec<DeckIdentityAmbiguity>,
    /// The comment inspection. Its fingerprints are the comment writer's
    /// own hash (the one a slide review checks), not an edit's `expected`.
    pub comments: DeckCommentInspection,
}

/// The comment inspection of the same bytes, or why the comment inspector
/// refused a package the deck view read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum DeckCommentInspection {
    Inspected { inspection: PptxInspection },
    Refused { reason: String },
}

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

/// The corruption-gate report: `ok` is the conjunction of its checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DeckRejectionReport {
    pub ok: bool,
    pub checks: Vec<DeckRejectionCheck>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DeckRejectionCheck {
    pub name: String,
    pub passed: bool,
    pub detail: String,
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
