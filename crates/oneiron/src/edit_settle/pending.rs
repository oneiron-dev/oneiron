//! The proposal landing (ARCH-0078): machine work waits beside the live
//! artifact, never on it, until a person keeps or discards it once.
//!
//! Two kinds wait here. A held [`EditProposal`] (a sheet edit, a Word
//! revision, a deck transaction) keeps its bytes, manifest and inspection so a
//! later Keep replays it through the ordinary settle door. A native organ
//! output ([`NativeOutput`]: a created deck, an image export, any organ's
//! export file) keeps its file and report; its Keep appends the file as a
//! version forked from the head it was made against, with its made_by
//! envelope. Both settle through the one consume-once ledger.

use serde::{Deserialize, Serialize};

use super::codec::{RECORD, settlement_key_parts};
use super::receipts::{already_settled, settlement_receipt_record};
use super::records::{
    SettleConsent, SettleDiscardOutcome, SettleOutcomeKind, SettleSelectOutcome, SettlementRecord,
};
use crate::Vault;
use crate::anchored_annotation::ReanchorSummary;
use crate::blob_artifact::{
    BLOB_ARTIFACT_RUN_REF_MAX_BYTES, BlobVersionProvenance, CalcEngineStamp, hash_hex,
    read_blob_artifact_head_in_txn,
};
use crate::edit_roundtrip::{
    EditManifest, EditProposal, OfficeFormat, RecalcStatus, SheetAnswerBundle, StructureSummary,
    ValidationCheck, ValidationReport,
};
use crate::entity_id::EntityId;
use crate::error::{ArtifactError, Error, Result};
use crate::provenance::made_by::MadeBy;
use crate::side_table::{self, Named, SideTable};
use crate::temporal::TimeRange;
use crate::write_envelope::WriteActor;

/// Key: id16 + hash32 (blake3 of the proposal ref), as the settlement ledger.
pub(super) const PENDING: SideTable<(EntityId, [u8; 32]), PendingRow, Named> =
    SideTable::new(&side_table::EDIT_SETTLE_PENDING_PROPOSAL);

/// The most report text one native output may carry.
pub const NATIVE_OUTPUT_REPORT_MAX_BYTES: usize = 1 << 20;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PendingRow {
    proposal_ref: String,
    retained_by: EntityId,
    retained_at: u64,
    made_by: Option<MadeBy>,
    base_version: Option<u64>,
    base_content_hash: Option<[u8; 32]>,
    new_bytes: Vec<u8>,
    body: PendingBody,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum PendingBody {
    Edit {
        format: OfficeFormat,
        manifest: Vec<u8>,
        inspection: StructureSummary,
        recalc: RecalcStatus,
        calc_engine: Option<(String, String)>,
        sheet_answers: Option<SheetAnswerBundle>,
    },
    Output {
        name: String,
        media_type: String,
        report: String,
    },
}

/// One native organ result offered to an artifact as its next version: the
/// export file the organ produced, its report, and who made it from what.
#[derive(Debug, Clone, PartialEq)]
pub struct NativeOutput {
    /// The run that produced it: the consume-once key and the agent-run provenance.
    pub run_ref: String,
    /// The file name the organ gave its export.
    pub name: String,
    /// Must equal the artifact's media type: an export is a version of its kind.
    pub media_type: String,
    pub bytes: Vec<u8>,
    /// The organ's structured report (JSON), kept with the proposal.
    pub report: serde_json::Value,
    /// The kept version's envelope; `None` gives the writer's own.
    pub made_by: Option<MadeBy>,
}

impl NativeOutput {
    /// An organ's MessagePack report as the JSON report a native output keeps.
    #[must_use]
    pub fn report_from_msgpack(report: &rmpv::Value) -> serde_json::Value {
        serde_json::to_value(report).unwrap_or(serde_json::Value::Null)
    }
}

/// What kind of proposal is waiting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PendingProposalKind {
    Edit,
    Output,
}

/// One proposal waiting beside its artifact, as a review surface lists it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PendingProposalView {
    pub artifact_id: EntityId,
    pub proposal_ref: String,
    pub kind: PendingProposalKind,
    pub base_version: Option<u64>,
    /// BLAKE3 of the proposed bytes, hex.
    pub content_hash: String,
    pub byte_len: usize,
    pub retained_by: EntityId,
    pub retained_at: u64,
    pub made_by: Option<MadeBy>,
    /// The deck's semantic diff line, the edit manifest's op count, or the
    /// organ's report.
    pub summary: serde_json::Value,
}

impl PendingRow {
    fn view(&self, artifact_id: EntityId) -> PendingProposalView {
        let summary = match &self.body {
            PendingBody::Edit {
                format, manifest, ..
            } => {
                let manifest = EditManifest::from_msgpack(manifest).ok();
                serde_json::json!({
                    "format": format,
                    "ops": manifest.as_ref().map_or(0, |manifest| manifest.ops.len()),
                    "deck": manifest.as_ref().and_then(|manifest| {
                        manifest.ops.iter().find_map(|op| match op {
                            crate::edit_roundtrip::EditOp::DeckTransaction { report, .. } => {
                                serde_json::from_str::<serde_json::Value>(report).ok()
                            }
                            _ => None,
                        })
                    }),
                })
            }
            PendingBody::Output {
                name,
                media_type,
                report,
            } => serde_json::json!({
                "name": name,
                "media_type": media_type,
                "report": serde_json::from_str::<serde_json::Value>(report)
                    .unwrap_or(serde_json::Value::Null),
            }),
        };
        PendingProposalView {
            artifact_id,
            proposal_ref: self.proposal_ref.clone(),
            kind: match self.body {
                PendingBody::Edit { .. } => PendingProposalKind::Edit,
                PendingBody::Output { .. } => PendingProposalKind::Output,
            },
            base_version: self.base_version,
            content_hash: hash_hex(blake3::hash(&self.new_bytes).as_bytes()),
            byte_len: self.new_bytes.len(),
            retained_by: self.retained_by,
            retained_at: self.retained_at,
            made_by: self.made_by.clone(),
            summary,
        }
    }

    /// Rebuilds the held proposal. Only a proposal that passed its gate is
    /// ever retained, and every settle door replays or re-checks the bytes.
    fn edit_proposal(&self) -> Result<Option<EditProposal>> {
        let PendingBody::Edit {
            format,
            manifest,
            inspection,
            recalc,
            calc_engine,
            sheet_answers,
        } = &self.body
        else {
            return Ok(None);
        };
        Ok(Some(EditProposal {
            run_ref: self.proposal_ref.clone(),
            format: *format,
            new_bytes: self.new_bytes.clone(),
            manifest: EditManifest::from_msgpack(manifest)?,
            inspection: inspection.clone(),
            validation: ValidationReport {
                ok: true,
                checks: vec![ValidationCheck {
                    name: "retained_after_gate",
                    passed: true,
                    detail: "passed the corruption gate when it was retained".to_owned(),
                }],
            },
            recalc: *recalc,
            calc_engine: calc_engine
                .as_ref()
                .map(|(engine, version)| CalcEngineStamp::new(engine, version).map(Box::new))
                .transpose()?,
            base_version: self.base_version,
            base_content_hash: self.base_content_hash.unwrap_or_default(),
            sheet_answers: sheet_answers.clone().map(Box::new),
        }))
    }
}

/// One held edit proposal that carries typed answers and waits unsettled.
pub(super) struct HeldAnswers {
    pub(super) key: (EntityId, [u8; 32]),
    pub(super) proposal: EditProposal,
    pub(super) retained_by: EntityId,
    pub(super) made_by: Option<MadeBy>,
}

impl Vault {
    /// The held edit proposals that carry typed answers and wait unsettled.
    pub(super) fn held_answer_proposals(&self) -> Result<Vec<HeldAnswers>> {
        let rtxn = self.store.env.read_txn()?;
        let mut out = Vec::new();
        for row in PENDING.iter_from(&self.store, &rtxn, &[])? {
            let (key, row) = row?;
            let typed = matches!(
                &row.body,
                PendingBody::Edit {
                    sheet_answers: Some(_),
                    ..
                } | PendingBody::Edit {
                    format: OfficeFormat::Docx | OfficeFormat::Pptx,
                    ..
                }
            );
            if !typed || RECORD.contains(&self.store, &rtxn, &key)? {
                continue;
            }
            let Some(proposal) = row.edit_proposal()? else {
                continue;
            };
            if proposal.sheet_answers.is_none()
                && proposal.manifest.paragraph_judgments.is_empty()
                && proposal.manifest.slide_judgments.is_empty()
            {
                continue;
            }
            out.push(HeldAnswers {
                key,
                proposal,
                retained_by: row.retained_by,
                made_by: row.made_by,
            });
        }
        Ok(out)
    }

    /// Holds an edit proposal beside its artifact until a Keep or Discard
    /// names it by its ref. A rejected or already settled proposal, or a ref
    /// already waiting, is refused. `made_by` is the envelope Keep gives the
    /// version; its trigger is checked when the version lands.
    pub fn retain_edit_proposal(
        &self,
        artifact_id: &EntityId,
        proposal: &EditProposal,
        made_by: Option<&MadeBy>,
        actor: WriteActor,
        retained_at: u64,
    ) -> Result<PendingProposalView> {
        if !proposal.validation.ok || proposal.new_bytes.is_empty() {
            return Err(Error::Artifact(ArtifactError::EditRoundtripFailed(
                "only a proposal that passed its gate waits for Keep",
            )));
        }
        let row = PendingRow {
            proposal_ref: proposal.run_ref.clone(),
            retained_by: actor.entity_ref(),
            retained_at,
            made_by: made_by.cloned(),
            base_version: proposal.base_version,
            base_content_hash: Some(proposal.base_content_hash),
            new_bytes: proposal.new_bytes.clone(),
            body: PendingBody::Edit {
                format: proposal.format,
                manifest: proposal.manifest.to_msgpack()?,
                inspection: proposal.inspection.clone(),
                recalc: proposal.recalc,
                calc_engine: proposal
                    .calc_engine
                    .as_deref()
                    .map(|stamp| (stamp.engine().to_owned(), stamp.version().to_owned())),
                sheet_answers: proposal.sheet_answers.as_deref().cloned(),
            },
        };
        self.put_pending(artifact_id, &row)
    }

    /// Offers one native organ result to an artifact as a waiting proposal,
    /// pinned to the head it was made against (none for a new artifact).
    pub fn propose_native_output(
        &self,
        artifact_id: &EntityId,
        output: &NativeOutput,
        actor: WriteActor,
        retained_at: u64,
    ) -> Result<PendingProposalView> {
        let body = self
            .get_blob_artifact(artifact_id)?
            .ok_or(Error::EntityNotFound)?;
        if output.media_type != body.media_type {
            return Err(Error::Artifact(ArtifactError::InvalidBlobArtifactBody(
                "a native output must export the artifact's own media type",
            )));
        }
        if output.bytes.is_empty() || output.name.trim().is_empty() {
            return Err(Error::Artifact(ArtifactError::InvalidBlobArtifactBody(
                "a native output needs a file name and non-empty bytes",
            )));
        }
        let report = serde_json::to_string(&output.report).map_err(|_| {
            Error::Artifact(ArtifactError::InvalidBlobArtifactBody(
                "native output report does not encode",
            ))
        })?;
        if report.len() > NATIVE_OUTPUT_REPORT_MAX_BYTES {
            return Err(Error::Artifact(ArtifactError::InvalidBlobArtifactBody(
                "native output report is too large",
            )));
        }
        crate::batch::secret_scan::scan_metadata_field(&output.name)?;
        if OfficeFormat::from_media_type(&output.media_type).is_ok() {
            // An office export must at least open as a package before it waits.
            crate::edit_roundtrip::read_office_package(&output.bytes)?;
        }
        let head = self.blob_artifact_head(artifact_id)?;
        let row = PendingRow {
            proposal_ref: output.run_ref.clone(),
            retained_by: actor.entity_ref(),
            retained_at,
            made_by: output.made_by.clone(),
            base_version: head.as_ref().map(|head| head.version),
            base_content_hash: head.as_ref().map(|head| head.content_hash),
            new_bytes: output.bytes.clone(),
            body: PendingBody::Output {
                name: output.name.clone(),
                media_type: output.media_type.clone(),
                report,
            },
        };
        self.put_pending(artifact_id, &row)
    }

    /// The proposals waiting beside one artifact, oldest ref hash first.
    pub fn pending_proposals(&self, artifact_id: &EntityId) -> Result<Vec<PendingProposalView>> {
        let rtxn = self.store.env.read_txn()?;
        let mut out = Vec::new();
        for row in PENDING.iter_from(&self.store, &rtxn, artifact_id.as_bytes())? {
            let ((artifact, key), row) = row?;
            if RECORD.contains(&self.store, &rtxn, &(artifact, key))? {
                continue;
            }
            out.push(row.view(artifact));
        }
        Ok(out)
    }

    /// One waiting proposal's view, or `None` when nothing waits under the ref.
    pub fn pending_proposal(
        &self,
        artifact_id: &EntityId,
        proposal_ref: &str,
    ) -> Result<Option<PendingProposalView>> {
        Ok(self
            .pending_row(artifact_id, proposal_ref)?
            .map(|row| row.view(*artifact_id)))
    }

    /// The held edit proposal under `proposal_ref`, rebuilt for a settle door.
    pub fn pending_edit_proposal(
        &self,
        artifact_id: &EntityId,
        proposal_ref: &str,
    ) -> Result<Option<EditProposal>> {
        match self.pending_row(artifact_id, proposal_ref)? {
            Some(row) => row.edit_proposal(),
            None => Ok(None),
        }
    }

    /// Keeps one waiting proposal: a held edit settles through
    /// [`Vault::settle_select_edit_proposal_made_by`]; a native output lands
    /// as a version forked from the head it was made against.
    pub fn keep_pending_proposal(
        &self,
        artifact_id: &EntityId,
        proposal_ref: &str,
        consent: &SettleConsent,
        actor: WriteActor,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<SettleSelectOutcome> {
        let row = self
            .pending_row(artifact_id, proposal_ref)?
            .ok_or(Error::EntityNotFound)?;
        let outcome = if let Some(proposal) = row.edit_proposal()? {
            // A held answer whose units changed under it lands what is
            // untouched and withdraws the rest (ARCH-0075 §4).
            match self.split_typed_answers(
                artifact_id,
                &proposal,
                row.retained_by,
                row.made_by.as_ref(),
                true,
            )? {
                Some(split) => self.keep_split(
                    artifact_id,
                    &proposal,
                    split,
                    row.made_by.as_ref(),
                    consent,
                    actor,
                    occurred,
                    learned_at,
                )?,
                None => self.settle_select_edit_proposal_made_by(
                    artifact_id,
                    &proposal,
                    row.made_by.as_ref(),
                    consent,
                    actor,
                    occurred,
                    learned_at,
                )?,
            }
        } else {
            self.keep_native_output(artifact_id, &row, consent, actor, occurred, learned_at)?
        };
        self.drop_pending(artifact_id, proposal_ref)?;
        Ok(outcome)
    }

    /// Discards one waiting proposal through the consume-once ledger.
    pub fn discard_pending_proposal(
        &self,
        artifact_id: &EntityId,
        proposal_ref: &str,
        consent: &SettleConsent,
        actor: WriteActor,
        reason: &str,
        learned_at: u64,
    ) -> Result<SettleDiscardOutcome> {
        let row = self
            .pending_row(artifact_id, proposal_ref)?
            .ok_or(Error::EntityNotFound)?;
        let outcome = if let Some(proposal) = row.edit_proposal()? {
            self.settle_discard_edit_proposal(
                artifact_id,
                &proposal,
                consent,
                actor,
                reason,
                learned_at,
            )?
        } else {
            self.authorize_settle(consent, actor)?;
            let reason = reason.trim();
            let record = output_record(
                &row,
                SettleOutcomeKind::Discarded,
                consent,
                actor,
                learned_at,
                None,
            );
            let key = settlement_key_parts(artifact_id, proposal_ref);
            self.with_write_txn_grouped(|wtxn| {
                self.authorize_settle_in_txn(wtxn, consent, actor)?;
                if let Some(existing) = RECORD.get(&self.store, wtxn, &key)? {
                    return Err(already_settled(&existing));
                }
                let mut record = record;
                record.reason = (!reason.is_empty()).then(|| reason.to_owned());
                RECORD.put(&self.store, wtxn, &key, &record)?;
                Ok(record)
            })
            .and_then(|record| {
                Ok(SettleDiscardOutcome {
                    receipt: settlement_receipt_record(*artifact_id, &record)?,
                })
            })?
        };
        self.drop_pending(artifact_id, proposal_ref)?;
        Ok(outcome)
    }

    fn keep_native_output(
        &self,
        artifact_id: &EntityId,
        row: &PendingRow,
        consent: &SettleConsent,
        actor: WriteActor,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<SettleSelectOutcome> {
        self.authorize_settle(consent, actor)?;
        let key = settlement_key_parts(artifact_id, &row.proposal_ref);
        let provenance = BlobVersionProvenance::AgentRun {
            run_ref: row.proposal_ref.clone(),
        };
        let (version, record) = self.with_write_txn_grouped(|wtxn| {
            self.authorize_settle_in_txn(wtxn, consent, actor)?;
            if let Some(existing) = RECORD.get(&self.store, wtxn, &key)? {
                return Err(already_settled(&existing));
            }
            let head = read_blob_artifact_head_in_txn(&self.store, wtxn, artifact_id)?;
            // The output forks from the version it was made against; a later
            // head keeps both, as a person may keep a machine version beside
            // their own. Made against nothing, it lands on whatever head is.
            let fork_parent = row
                .base_version
                .filter(|base| head.as_ref().is_some_and(|head| head.version != *base));
            let version = match &row.made_by {
                Some(made_by) => self.append_blob_artifact_version_made_by_in_txn(
                    wtxn,
                    artifact_id,
                    fork_parent,
                    &row.new_bytes,
                    &provenance,
                    made_by,
                    actor,
                    occurred,
                    learned_at,
                )?,
                None => self.append_blob_artifact_version_with_engine_and_parent_in_txn(
                    wtxn,
                    artifact_id,
                    &row.new_bytes,
                    &provenance,
                    None,
                    actor,
                    occurred,
                    learned_at,
                    fork_parent,
                    None,
                )?,
            };
            let record = output_record(
                row,
                SettleOutcomeKind::Selected,
                consent,
                actor,
                learned_at,
                Some(&version),
            );
            RECORD.put(&self.store, wtxn, &key, &record)?;
            Ok((version, record))
        })?;
        Ok(SettleSelectOutcome {
            stranded_proposal: None,
            version,
            reanchor: ReanchorSummary::default(),
            receipt: settlement_receipt_record(*artifact_id, &record)?,
        })
    }

    fn put_pending(&self, artifact_id: &EntityId, row: &PendingRow) -> Result<PendingProposalView> {
        validate_pending_ref(&row.proposal_ref)?;
        let key = settlement_key_parts(artifact_id, &row.proposal_ref);
        self.with_write_txn_grouped(|wtxn| {
            if let Some(existing) = RECORD.get(&self.store, wtxn, &key)? {
                return Err(already_settled(&existing));
            }
            if PENDING.contains(&self.store, wtxn, &key)? {
                return Err(Error::Artifact(ArtifactError::InvalidEditManifest(
                    "a proposal already waits under this ref",
                )));
            }
            PENDING.put(&self.store, wtxn, &key, row)
        })?;
        Ok(row.view(*artifact_id))
    }

    fn pending_row(
        &self,
        artifact_id: &EntityId,
        proposal_ref: &str,
    ) -> Result<Option<PendingRow>> {
        let rtxn = self.store.env.read_txn()?;
        let Some(row) = PENDING.get(
            &self.store,
            &rtxn,
            &settlement_key_parts(artifact_id, proposal_ref),
        )?
        else {
            return Ok(None);
        };
        if row.proposal_ref != proposal_ref {
            return Err(Error::CorruptedIndex("pending proposal ref"));
        }
        Ok(Some(row))
    }

    fn drop_pending(&self, artifact_id: &EntityId, proposal_ref: &str) -> Result<()> {
        let key = settlement_key_parts(artifact_id, proposal_ref);
        self.with_write_txn_grouped(|wtxn| PENDING.delete(&self.store, wtxn, &key).map(|_| ()))
    }
}

fn output_record(
    row: &PendingRow,
    outcome: SettleOutcomeKind,
    consent: &SettleConsent,
    actor: WriteActor,
    settled_at: u64,
    version: Option<&crate::blob_artifact::BlobArtifactVersion>,
) -> SettlementRecord {
    let report = match &row.body {
        PendingBody::Output { report, .. } => report.as_bytes(),
        PendingBody::Edit { manifest, .. } => manifest.as_slice(),
    };
    SettlementRecord {
        proposal_ref: row.proposal_ref.clone(),
        outcome,
        settled_at,
        actor_ref: Some(actor.entity_ref().to_hex()),
        brief_ref: consent.brief_ref().map(str::to_owned),
        before_version: version.and(row.base_version),
        version: version.map(|version| version.version),
        content_hash: version.map(|version| version.content_hash),
        manifest_ref: version.map(|_| *blake3::hash(report).as_bytes()),
        manifest_ops: 0,
        pptx_slide_creation_id_mints: Vec::new(),
        pptx_review_identities: Vec::new(),
        pptx_judgments: Vec::new(),
        docx_judgments: Vec::new(),
        anchors: Vec::new(),
        reason: None,
        sheet_answers: None,
        deck: None,
    }
}

pub(super) fn validate_pending_ref(proposal_ref: &str) -> Result<()> {
    if proposal_ref.trim().is_empty() || proposal_ref.len() > BLOB_ARTIFACT_RUN_REF_MAX_BYTES {
        return Err(Error::Artifact(ArtifactError::EditRoundtripFailed(
            "proposal ref must be non-empty and within the run-ref length bound",
        )));
    }
    crate::batch::secret_scan::scan_metadata_field(proposal_ref)
}
