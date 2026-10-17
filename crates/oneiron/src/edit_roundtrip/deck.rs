//! Native deck edits (ARCH-0077, "Edit in place with passthrough"): one
//! docedit deck transaction over the exact PPTX blob head, retained as one
//! fork-and-diff proposal for the consume-once settle door.
//!
//! The organ crate owns the verbs, their independent checks and the closed
//! transaction grammar. The vault owns the base pin, the managed native-id
//! history, asset resolution, the anchored thread the proposal answers, and
//! settlement: [`verify_deck_proposal`] replays the transaction over the
//! pinned base and binds bytes and report to the run's handoff hash before
//! any version is appended. There is no second proposal or settle protocol.

use super::inspect::inspect;
use super::opc;
use super::{
    EDIT_MANIFEST_SCHEMA_VERSION, EditManifest, EditOp, EditOutcome, EditProposal, EditWarning,
    MutationMode, OfficeFormat, RecalcStatus, ValidationCheck, ValidationReport, WarningCode,
};
use crate::blob_artifact::{BLOB_ARTIFACT_RUN_REF_MAX_BYTES, read_blob_artifact_head_in_txn};
use crate::entity_id::EntityId;
use crate::error::{ArtifactError, Error, Result};
use crate::side_table::{self, Named, SideTable};
use oneiron_docedit::design_plan::MediaType;
use oneiron_docedit::edit::transaction::{
    AssetRef, Assets, DeckTransaction, DeckTransactionReport, IdMarks, run_transaction,
};
use oneiron_docedit::graphic::{AssetRecord, Origin};
use oneiron_docedit::retained_opc::Limits;
use serde::{Deserialize, Serialize};

/// Managed native-id history per deck artifact, raised at each settle.
const DECK_ID_MARKS: SideTable<EntityId, IdMarks, Named> =
    SideTable::new(&side_table::BLOB_ARTIFACT_DECK_ID_MARKS);

/// Removes an erased deck artifact's native-id history.
pub(super) fn erase_in_txn(
    store: &crate::store::Store,
    txn: &mut heed::RwTxn<'_>,
    artifact: &EntityId,
) -> Result<()> {
    DECK_ID_MARKS.delete(store, txn, artifact).map(drop)
}

const MAX_RENDERS: usize = 4_096;
const MAX_RENDERER_BYTES: usize = 256;

/// Which side of the diff a review image shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeckRenderSide {
    /// The pinned base version.
    Base,
    /// The proposal's candidate bytes.
    Candidate,
}

/// Host-rendered review evidence for one slide. The engine renders nothing;
/// the renderer's identity is kept so LibreOffice evidence stays provisional
/// beside the PowerPoint oracle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeckRender {
    pub side: DeckRenderSide,
    /// The slide part the image shows.
    pub slide: String,
    /// BLAKE3 of the image bytes.
    pub image_hash: [u8; 32],
    pub renderer: String,
}

/// Who made the operations and what they answer; kept with the receipt.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeckEditContext {
    /// The actor the operations are attributed to (ARCH-0035 made_by).
    #[serde(default)]
    pub made_by: Option<EntityId>,
    /// The open anchored thread this proposal answers. A standing-grant
    /// settle must ride that thread's brief.
    #[serde(default)]
    pub thread: Option<EntityId>,
    /// Before/after review images, attached by the host after proposing.
    #[serde(default)]
    pub renders: Vec<DeckRender>,
}

/// One line of the semantic diff for a deck transaction.
pub(super) fn render_report(report: &str) -> String {
    match serde_json::from_str::<DeckTransactionReport>(report) {
        Ok(report) => {
            let verbs: Vec<_> = report.steps.iter().map(|step| step.verb.as_str()).collect();
            format!(
                "deck transaction {}: {} ({} part(s) changed)",
                report.handoff.to_hex(),
                verbs.join(", "),
                report.parts.len()
            )
        }
        Err(_) => "deck transaction (unreadable report)".to_owned(),
    }
}

fn invalid(message: &'static str) -> Error {
    Error::Artifact(ArtifactError::InvalidEditManifest(message))
}

/// Run one deck transaction over `input` and return an uncommitted
/// proposal, or a rejection naming the refused step. The transaction's marks
/// are raised to `history` first, so new ids sit above managed history.
pub fn run_deck_transaction(
    input: &[u8],
    transaction_json: &str,
    run_ref: &str,
    limits: Limits,
    history: &IdMarks,
    assets: &dyn Assets,
    context: DeckEditContext,
) -> Result<EditOutcome> {
    if run_ref.trim().is_empty() || run_ref.len() > BLOB_ARTIFACT_RUN_REF_MAX_BYTES {
        return Err(Error::Artifact(ArtifactError::EditRoundtripFailed(
            "run_ref must be non-empty and within the run-ref length bound",
        )));
    }
    validate_context(&context)?;
    let mut transaction = DeckTransaction::parse(transaction_json)
        .map_err(|_| invalid("deck transaction is invalid"))?;
    transaction.marks.join(history);
    let package = opc::read(input)?;
    let inspection = inspect(&package, OfficeFormat::Pptx);
    let (bytes, report) = match run_transaction(input, &transaction, limits, assets) {
        Ok(run) => run,
        Err(refusal) => {
            return Ok(EditOutcome::Rejected {
                inspection,
                report: ValidationReport::single_failure("deck_transaction", refusal.to_string()),
            });
        }
    };
    let warnings = report
        .fit_unverified()
        .map(|fit| {
            EditWarning::new(
                WarningCode::FitUnverified,
                format!("{} shape {}", fit.part, fit.shape),
            )
        })
        .collect();
    Ok(EditOutcome::Proposed(Box::new(EditProposal {
        run_ref: run_ref.to_owned(),
        format: OfficeFormat::Pptx,
        new_bytes: bytes,
        manifest: EditManifest {
            schema_version: EDIT_MANIFEST_SCHEMA_VERSION,
            format: OfficeFormat::Pptx,
            ops: vec![EditOp::DeckTransaction {
                transaction: transaction.canonical(),
                report: report.canonical(),
                context,
            }],
            touched_parts: report
                .parts
                .iter()
                .map(|change| change.part.clone())
                .collect(),
            mutation_mode: MutationMode::Minimal,
            warnings,
            pptx_holder_limits: None,
            slide_judgments: Vec::new(),
            paragraph_judgments: Vec::new(),
            paragraph_question: None,
        },
        inspection,
        validation: ValidationReport {
            ok: true,
            checks: vec![
                ValidationCheck {
                    name: "well_formed_opc",
                    passed: true,
                    detail: "bounded ZIP records and checksums verified".into(),
                },
                ValidationCheck {
                    name: "deck_verb_checks",
                    passed: true,
                    detail: "each verb's independent check on its exported, re-opened copy held"
                        .into(),
                },
                ValidationCheck {
                    name: "deck_part_diff",
                    passed: true,
                    detail: format!(
                        "{} part(s) changed, all inside the derived allowed set; {} untouched; \
                         handoff {}",
                        report.parts.len(),
                        report.untouched,
                        report.handoff.to_hex()
                    ),
                },
            ],
        },
        recalc: RecalcStatus::NotNeeded,
        calc_engine: None,
        base_version: None,
        base_content_hash: *blake3::hash(input).as_bytes(),
        sheet_answers: None,
    })))
}

fn validate_context(context: &DeckEditContext) -> Result<()> {
    if context.renders.len() > MAX_RENDERS
        || context.renders.iter().any(|render| {
            render.renderer.trim().is_empty()
                || render.renderer.len() > MAX_RENDERER_BYTES
                || render.slide.is_empty()
        })
    {
        return Err(invalid("deck review renders are invalid"));
    }
    Ok(())
}

/// The settled deck transaction, kept with the consume-once ledger row: the
/// handoff hash it settled, its canonical report (part diff, effects, marks,
/// fit) and its context (made_by, thread, review renders).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeckSettleEvidence {
    pub handoff: [u8; 32],
    pub report: String,
    pub context: DeckEditContext,
}

/// What a replay at the settle door proved, and the managed marks after it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CheckedDeck {
    pub(crate) evidence: DeckSettleEvidence,
    pub(crate) marks: IdMarks,
}

/// The single deck operation of a proposal, if it is a deck proposal.
pub(crate) fn deck_op(proposal: &EditProposal) -> Option<(&str, &str, &DeckEditContext)> {
    proposal.manifest.ops.iter().find_map(|op| match op {
        EditOp::DeckTransaction {
            transaction,
            report,
            context,
        } => Some((transaction.as_str(), report.as_str(), context)),
        _ => None,
    })
}

/// Replay a deck proposal over its pinned base. A public proposal is not an
/// engine certificate: the transaction must name this base and marks at or
/// above managed history, and the replay must reproduce the exact candidate
/// bytes, part diff and report the proposal carries.
pub(crate) fn verify_deck_proposal(
    base: &[u8],
    proposal: &EditProposal,
    limits: Limits,
    history: &IdMarks,
    assets: &dyn Assets,
) -> Result<CheckedDeck> {
    let [
        EditOp::DeckTransaction {
            transaction,
            report,
            context,
        },
    ] = proposal.manifest.ops.as_slice()
    else {
        return Err(invalid(
            "deck proposal requires exactly one deck transaction",
        ));
    };
    validate_context(context)?;
    if proposal.format != OfficeFormat::Pptx
        || proposal.manifest.format != OfficeFormat::Pptx
        || proposal.manifest.schema_version != EDIT_MANIFEST_SCHEMA_VERSION
        || proposal.manifest.mutation_mode != MutationMode::Minimal
        || proposal.base_content_hash != *blake3::hash(base).as_bytes()
    {
        return Err(invalid("deck proposal does not name its pinned base"));
    }
    let parsed =
        DeckTransaction::parse(transaction).map_err(|_| invalid("deck transaction is invalid"))?;
    if parsed.canonical() != *transaction || !parsed.marks.covers(history) {
        return Err(invalid(
            "deck transaction is not canonical or its marks are below managed history",
        ));
    }
    let (bytes, expected) = run_transaction(base, &parsed, limits, assets)
        .map_err(|_| invalid("deck transaction cannot replay against its pinned base"))?;
    let touched: std::collections::BTreeSet<_> = expected
        .parts
        .iter()
        .map(|change| change.part.clone())
        .collect();
    if bytes != proposal.new_bytes
        || expected.canonical() != *report
        || touched != proposal.manifest.touched_parts
    {
        return Err(invalid(
            "deck output does not implement its transaction over its base",
        ));
    }
    Ok(CheckedDeck {
        evidence: DeckSettleEvidence {
            handoff: expected.handoff.0,
            report: report.clone(),
            context: context.clone(),
        },
        marks: expected.marks,
    })
}

/// Resolves `set_picture` assets from PNG and JPEG blob artifact versions
/// held in this vault, read in the caller's transaction.
pub(crate) struct VaultAssets<'v, 't> {
    pub(crate) vault: &'v crate::Vault,
    pub(crate) txn: &'v heed::RoTxn<'t>,
}

impl Assets for VaultAssets<'_, '_> {
    fn resolve(&self, asset: &AssetRef) -> Option<(AssetRecord, Vec<u8>)> {
        let artifact = EntityId::from_hex(&asset.artifact).ok()?;
        let body = self
            .vault
            .get_blob_artifact_in_txn(self.txn, &artifact)
            .ok()??;
        let media = match body.media_type.as_str() {
            "image/png" => MediaType::Png,
            "image/jpeg" => MediaType::Jpeg,
            _ => return None,
        };
        let version = self
            .vault
            .blob_artifact_version_metadata_in_txn(self.txn, &artifact, asset.version)
            .ok()??;
        let bytes = self
            .vault
            .read_blob_artifact_version_in_txn(self.txn, &artifact, asset.version)
            .ok()??;
        Some((
            AssetRecord {
                artifact: asset.artifact.clone(),
                version: asset.version,
                content_hash: version.content_hash,
                media,
                origin: Origin::Held,
                provenance: vec![format!(
                    "blob:{}@{}:{}",
                    asset.artifact,
                    asset.version,
                    version.provenance.as_str()
                )],
                rights: Vec::new(),
                description: asset.description.clone(),
            },
            bytes,
        ))
    }
}

impl crate::Vault {
    /// The deck's managed native-id history; empty before its first settle.
    pub(crate) fn deck_id_marks_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        artifact: &EntityId,
    ) -> Result<IdMarks> {
        Ok(DECK_ID_MARKS
            .get(&self.store, txn, artifact)?
            .unwrap_or_default())
    }

    /// Raise the deck's managed history to include `marks`.
    pub(crate) fn raise_deck_id_marks_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        artifact: &EntityId,
        marks: &IdMarks,
    ) -> Result<()> {
        let mut history = self.deck_id_marks_in_txn(txn, artifact)?;
        history.join(marks);
        DECK_ID_MARKS.put(&self.store, txn, artifact, &history)
    }

    /// Propose one native deck transaction against the exact current PPTX
    /// head. The result is uncommitted: it is kept or discarded through the
    /// ordinary consent-gated, consume-once settlement door. A named thread
    /// must be open on this artifact.
    pub fn propose_blob_artifact_deck_edit(
        &self,
        artifact_id: &EntityId,
        transaction_json: &str,
        run_ref: &str,
        context: DeckEditContext,
    ) -> Result<EditOutcome> {
        let limits = self.docedit_package_limits()?;
        if let Some(thread) = context.thread {
            let open = self
                .get_annotation_thread(artifact_id, &thread)?
                .is_some_and(|thread| {
                    thread.state == crate::anchored_annotation::ThreadState::Open
                });
            if !open {
                return Err(Error::Artifact(ArtifactError::AnnotationThreadNotFound));
            }
        }
        let rtxn = self.store.env.read_txn()?;
        let head = read_blob_artifact_head_in_txn(&self.store, &rtxn, artifact_id)?
            .ok_or(Error::EntityNotFound)?;
        let body = self
            .get_blob_artifact_in_txn(&rtxn, artifact_id)?
            .ok_or(Error::EntityNotFound)?;
        if OfficeFormat::from_media_type(&body.media_type)? != OfficeFormat::Pptx {
            return Err(invalid("a deck transaction requires a pptx blob artifact"));
        }
        let bytes = self
            .read_blob_artifact_version_in_txn(&rtxn, artifact_id, head.version)?
            .ok_or(Error::EntityNotFound)?;
        let history = self.deck_id_marks_in_txn(&rtxn, artifact_id)?;
        let assets = VaultAssets {
            vault: self,
            txn: &rtxn,
        };
        let mut outcome = run_deck_transaction(
            &bytes,
            transaction_json,
            run_ref,
            limits,
            &history,
            &assets,
            context,
        )?;
        if let EditOutcome::Proposed(proposal) = &mut outcome {
            proposal.base_version = Some(head.version);
        }
        Ok(outcome)
    }
}

impl EditProposal {
    /// Attach host-rendered before/after review images to a deck proposal.
    /// Renders change no bytes; they travel in the manifest to the receipt.
    pub fn attach_deck_renders(&mut self, renders: Vec<DeckRender>) -> Result<()> {
        let Some(EditOp::DeckTransaction { context, .. }) = self
            .manifest
            .ops
            .iter_mut()
            .find(|op| matches!(op, EditOp::DeckTransaction { .. }))
        else {
            return Err(invalid("renders attach only to a deck proposal"));
        };
        let mut next = context.clone();
        next.renders.extend(renders);
        validate_context(&next)?;
        *context = next;
        Ok(())
    }
}
