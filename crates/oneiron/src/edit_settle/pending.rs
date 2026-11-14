//! The proposal landing (ARCH-0078): machine work waits beside the live
//! artifact, never on it, until a person keeps or discards it once.
//!
//! Three forms wait here. Paid sheet decisions retain their original base and
//! read rows before byte staging; no proposed workbook bytes exist until the
//! same row is promoted to a validated edit. A held [`EditProposal`] (a sheet
//! edit, a Word revision, a deck transaction) keeps its bytes, manifest and
//! inspection so a later Keep replays it through the ordinary settle door.
//! A native organ
//! output ([`NativeOutput`]: a created deck, an image export, any organ's
//! export file) keeps its file and report; its Keep appends the file as a
//! version forked from the head it was made against, with its made_by
//! envelope. A deck export waits pinned to the version the deck projected
//! over, and its Keep also rebinds the deck to the version it lands
//! ([`DeckExportHold`], FIX 2700). All settle through the one consume-once
//! ledger.

use std::collections::BTreeMap;

use oneiron_docedit::edit::transaction::IdMarks;
use oneiron_docedit::live::{ExportKey, NodeBinding, NodeId};
use serde::{Deserialize, Serialize};

use super::codec::{RECORD, settlement_key_parts};
use super::organ_wait::OrganWait;
use super::receipts::settlement_receipt_record;
use super::records::{SettleConsent, SettleDiscardOutcome, SettleOutcomeKind, SettleSelectOutcome};
use super::ref_state::{RefMove, move_ref_in_txn};
use crate::Vault;
use crate::blob_artifact::{
    BLOB_ARTIFACT_RUN_REF_MAX_BYTES, BlobBodyFile, BlobContent, CalcEngineStamp,
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

mod admission;
mod body_file;
// The native output's Keep.
mod keep_output;
mod output_retention;
mod output_settle;
mod sheet_answers;
mod view;
pub use admission::MadeByReader;
use body_file::{PendingFile, StagedPendingBody};
use output_settle::output_record;
pub use view::{PendingProposalKind, PendingProposalView};

/// Key: id16 + hash32 (blake3 of the proposal ref), as the settlement ledger.
pub(super) const PENDING: SideTable<(EntityId, [u8; 32]), PendingRow, Named> =
    SideTable::new(&side_table::EDIT_SETTLE_PENDING_PROPOSAL);

/// The delta receipt id a Selected Keep answered (FIX 11706): the same key
/// as its pending row, so the undo door anchors the routing outcome.
/// Key: id16 + hash32 (blake3 of the proposal ref).
pub(super) const LINK: SideTable<(EntityId, [u8; 32]), String, Named> =
    SideTable::new(&side_table::EDIT_SETTLE_KEEP_LINK);

/// The most report text one native output may carry.
pub const NATIVE_OUTPUT_REPORT_MAX_BYTES: usize = 1 << 20;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PendingRow {
    proposal_ref: String,
    retained_by: EntityId,
    /// The retaining actor's entity type, read as it retained the row, so
    /// its view names the actor's kind with no read (FIX 9340).
    #[serde(default)]
    retained_by_kind: Option<u8>,
    retained_at: u64,
    made_by: Option<MadeBy>,
    base_version: Option<u64>,
    base_content_hash: Option<[u8; 32]>,
    /// An explicit version fork waits here: its Keep lands a fork version
    /// even against the current head (blind review of #4387). Old rows read
    /// back as false and keep today's behavior.
    #[serde(default)]
    explicit_fork: bool,
    /// The selected suffix begins here; byte staging does not consume it.
    next_sheet_row: Option<u32>,
    new_bytes: Vec<u8>,
    /// A waiting output past the inline size: the body file its bytes are
    /// in, with `new_bytes` empty (FIX 20812). Old rows read back as none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    new_file: Option<PendingFile>,
    body: PendingBody,
    /// The rows its producer read beside its base and its made_by: each
    /// other version an ask read, its evidence and its stored images,
    /// captured as it is retained (FIX 9312).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    read_rows: Vec<EntityId>,
    /// A deck export's projection, which its Keep rebinds the deck to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    deck: Option<DeckExportHold>,
    /// The delta receipt id this rework answered (FIX 11967): its Keep
    /// carries the stamp onto the keep link, and the committed rework's
    /// settle carries it onto the receipt. `None` when no amendment stood
    /// behind the proposal.
    pub(super) delta_receipt: Option<String>,
}

/// A deck export waiting for Keep (FIX 2700): what its Keep needs to bind
/// the deck to the version it lands. Only the deck export door writes one,
/// with the row's base the version the deck projected over, never the head
/// it found, so a version that landed outside the deck stays beside it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DeckExportHold {
    /// The deck body's frontier the export projects.
    pub(crate) frontier: Vec<u8>,
    /// The projection's key: its state hash pins the deck state it binds.
    pub(crate) key: ExportKey,
    pub(crate) document_version: u64,
    /// Every live node's binding in the exported bytes.
    pub(crate) bindings: BTreeMap<NodeId, NodeBinding>,
    /// BLAKE3 of every non-slide part in the exported bytes.
    pub(crate) opaque_parts: BTreeMap<String, [u8; 32]>,
    pub(crate) id_marks: IdMarks,
    /// The export record's count of changed parts and effect receipts.
    pub(crate) changes: u64,
    pub(crate) effects: Vec<String>,
}

/// The version a native output is proposed over, as a version number and
/// its content hash. Keep forks from it when the head has moved past it.
#[derive(Clone, Copy)]
pub(super) enum OutputBase {
    /// The head as the output is retained; a deck export's base is the
    /// version its deck projected over (FIX 2700).
    Head,
    /// The version the producer read (review of #7368).
    MadeAgainst((u64, [u8; 32])),
    /// A fork from this version even while it is the head (FIX 8208).
    Fork((u64, [u8; 32])),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum PendingBody {
    SheetAnswers {
        bundle: SheetAnswerBundle,
    },
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
        /// The version claim reserved by a direct machine append without a
        /// run reference; its hex is the proposal key. Born only on Keep.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        version_claim_id: Option<EntityId>,
        /// The world and facet its producing run's host bound, frozen as it
        /// is retained (FIX 3171): Keep births the version's claim there,
        /// never at the keeper's. Absent for an unbound producer.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        producer_world: Option<EntityId>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        producer_facet: Option<EntityId>,
    },
}

pub use crate::blob_artifact::native_output::NativeOutput;

impl PendingRow {
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
        // Only a native output waits in a body file.
        if self.new_file.is_some() {
            return Err(Error::CorruptedIndex("pending edit proposal body file"));
        }
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

    /// The length of the bytes the row waits with, read from its body
    /// file's descriptor when it has one.
    fn payload_len(&self) -> u64 {
        self.new_file
            .as_ref()
            .map_or(self.new_bytes.len() as u64, |file| file.body.bytes)
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
    /// version; a named one is admitted under `reader` as it is retained
    /// (FIX 1229, [`MadeByReader`]), and its trigger is checked again when
    /// the version lands.
    pub fn retain_edit_proposal(
        &self,
        artifact_id: &EntityId,
        proposal: &EditProposal,
        made_by: Option<&MadeBy>,
        reader: Option<MadeByReader<'_>>,
        actor: WriteActor,
        retained_at: u64,
        delta_receipt: Option<&str>,
    ) -> Result<PendingProposalView> {
        self.retain_edit_proposal_with_reads(
            artifact_id,
            proposal,
            made_by,
            reader,
            (actor, retained_at),
            &[],
            delta_receipt,
        )
    }

    /// [`Self::retain_edit_proposal`] for a producer that read `read_rows`
    /// beside its base and its made_by (FIX 9312): the proposal keeps them,
    /// and a narrowed reader lists it only when its lane admits each.
    pub fn retain_edit_proposal_with_reads(
        &self,
        artifact_id: &EntityId,
        proposal: &EditProposal,
        made_by: Option<&MadeBy>,
        reader: Option<MadeByReader<'_>>,
        (actor, retained_at): (WriteActor, u64),
        read_rows: &[EntityId],
        delta_receipt: Option<&str>,
    ) -> Result<PendingProposalView> {
        let kind = self.get_entity_type(&actor.entity_ref())?;
        let row = edit_pending_row(
            proposal,
            made_by,
            (actor, kind),
            retained_at,
            read_rows,
            delta_receipt,
        )?;
        self.put_pending(artifact_id, &row, None, reader, None)
    }

    /// [`Self::retain_edit_proposal`] in the caller's own write transaction, for a
    /// writer that commits the proposal beside rows of its own (a standing question's
    /// ask and its stamp, FIX 2337; a wake's re-ask and its marks, FIX 9174). A named
    /// made_by is admitted here through `lane`, which [`Self::edit_retention_lane`]
    /// settled before the transaction opened; with none, one that names any row but
    /// its writer is refused (FIX 1229).
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn retain_edit_proposal_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        artifact_id: &EntityId,
        proposal: &EditProposal,
        made_by: Option<&MadeBy>,
        lane: Option<&crate::claim::ScopedRead<'_>>,
        actor: WriteActor,
        retained_at: u64,
        delta_receipt: Option<&str>,
    ) -> Result<PendingProposalView> {
        self.retain_edit_proposal_with_reads_in_txn(
            wtxn,
            artifact_id,
            proposal,
            made_by,
            lane,
            (actor, retained_at),
            &[],
            delta_receipt,
        )
    }

    /// [`Self::retain_edit_proposal_in_txn`] for a producer that read
    /// `read_rows` beside its base and its made_by (FIX 9312).
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn retain_edit_proposal_with_reads_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        artifact_id: &EntityId,
        proposal: &EditProposal,
        made_by: Option<&MadeBy>,
        lane: Option<&crate::claim::ScopedRead<'_>>,
        (actor, retained_at): (WriteActor, u64),
        read_rows: &[EntityId],
        delta_receipt: Option<&str>,
    ) -> Result<PendingProposalView> {
        match (lane, made_by) {
            (Some(lane), Some(made_by)) => {
                admission::admit_made_by_in_txn(self, wtxn, lane, made_by, actor.entity_ref())?;
            }
            _ => {
                admission::retention_lane(artifact_id, made_by, actor.entity_ref(), None)?;
            }
        }
        let kind = self.get_entity_type_in_txn(wtxn, &actor.entity_ref())?;
        let row = edit_pending_row(
            proposal,
            made_by,
            (actor, kind),
            retained_at,
            read_rows,
            delta_receipt,
        )?;
        self.put_pending_in_txn(wtxn, artifact_id, &row, None, None)
    }

    /// The lane a retention in the caller's own transaction admits `made_by` through
    /// under `reader` (FIX 1229, 9174), settled before that transaction opens, since a
    /// lane's grant clock commits on its own. `None` when nothing needs admitting.
    pub(crate) fn edit_retention_lane<'v>(
        &self,
        artifact_id: &EntityId,
        made_by: Option<&MadeBy>,
        actor: WriteActor,
        reader: Option<MadeByReader<'v>>,
    ) -> Result<Option<crate::claim::ScopedRead<'v>>> {
        admission::retention_lane(artifact_id, made_by, actor.entity_ref(), reader)
    }

    /// Offers one native organ result to an artifact as a waiting proposal,
    /// pinned to the head as it is retained (none for a new artifact);
    /// [`Self::propose_native_output_made_against`] pins it to the version
    /// it was made from. Its named made_by is admitted under `reader`
    /// (FIX 1229).
    pub fn propose_native_output(
        &self,
        artifact_id: &EntityId,
        output: &NativeOutput,
        reader: Option<MadeByReader<'_>>,
        actor: WriteActor,
        retained_at: u64,
        delta_receipt: Option<&str>,
    ) -> Result<PendingProposalView> {
        self.propose_native_output_with_reads(
            artifact_id,
            output,
            reader,
            (actor, retained_at),
            &[],
            delta_receipt,
        )
    }

    /// [`Self::propose_native_output`] with additional rows the producer
    /// declares it read. A waiting-proposal reader must admit each row.
    /// This declaration grants no authority and does not prove completeness.
    pub fn propose_native_output_with_reads(
        &self,
        artifact_id: &EntityId,
        output: &NativeOutput,
        reader: Option<MadeByReader<'_>>,
        (actor, retained_at): (WriteActor, u64),
        read_rows: &[EntityId],
        delta_receipt: Option<&str>,
    ) -> Result<PendingProposalView> {
        self.propose_output(
            artifact_id,
            output,
            BlobContent::Bytes(&output.bytes),
            reader,
            (actor, retained_at),
            None,
            OutputBase::Head,
            false,
            read_rows,
            delta_receipt,
            None,
        )
    }

    /// [`Self::propose_native_output_with_reads`] of an output made from
    /// `made_against`, the version (and its content hash) of this same
    /// artifact the producer read: the proposal is pinned to that version,
    /// not to the head as it is retained, so a head that moved after the
    /// read keeps the output as a fork of the version it was made from
    /// (review of #7368). `None` pins it to the head. An organ call's
    /// output carries no delta receipt.
    pub fn propose_native_output_made_against(
        &self,
        artifact_id: &EntityId,
        output: &NativeOutput,
        reader: Option<MadeByReader<'_>>,
        (actor, retained_at): (WriteActor, u64),
        made_against: Option<(u64, [u8; 32])>,
        read_rows: &[EntityId],
    ) -> Result<PendingProposalView> {
        self.propose_output(
            artifact_id,
            output,
            BlobContent::Bytes(&output.bytes),
            reader,
            (actor, retained_at),
            None,
            made_against.map_or(OutputBase::Head, OutputBase::MadeAgainst),
            false,
            read_rows,
            None,
            None,
        )
    }

    /// [`Self::propose_native_output_with_reads`] of a body file an ingress
    /// door decoded before any writer opened (FIX 22074): `output` names the
    /// output and holds no bytes; `body` holds them. A body no longer than
    /// the asset plane's inline size is read once and waits in its row; a
    /// longer one waits in its own body file, staged from `body`, never held
    /// whole, and an office export is opened as a package from the file.
    ///
    /// # Errors
    ///
    /// [`Self::propose_native_output_with_reads`]'s errors, the file's read
    /// errors, and [`Error::InvariantViolation`] for an `output` that holds
    /// bytes or a file that changes under the door.
    pub fn propose_native_output_file(
        &self,
        artifact_id: &EntityId,
        output: &NativeOutput,
        body: &BlobBodyFile<'_>,
        reader: Option<MadeByReader<'_>>,
        (actor, retained_at): (WriteActor, u64),
        read_rows: &[EntityId],
        delta_receipt: Option<&str>,
    ) -> Result<PendingProposalView> {
        if !output.bytes.is_empty() {
            return Err(Error::InvariantViolation(
                "a native output proposed from a body file holds no bytes of its own",
            ));
        }
        if let Some(bytes) = body.inline_bytes()? {
            let output = NativeOutput {
                bytes,
                ..output.clone()
            };
            return self.propose_native_output_with_reads(
                artifact_id,
                &output,
                reader,
                (actor, retained_at),
                read_rows,
                delta_receipt,
            );
        }
        self.propose_output(
            artifact_id,
            output,
            BlobContent::File(body),
            reader,
            (actor, retained_at),
            None,
            OutputBase::Head,
            false,
            read_rows,
            delta_receipt,
            None,
        )
    }

    /// [`Self::propose_native_output`] for a direct AgentRun append that did
    /// not settle: the proposal and the caller's live content-write authority
    /// commit under one check (FIX 8208).
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn propose_native_output_with_write_grant(
        &self,
        artifact_id: &EntityId,
        output: &NativeOutput,
        content: BlobContent<'_>,
        reader: Option<MadeByReader<'_>>,
        actor: WriteActor,
        retained_at: u64,
        fork_base: Option<(u64, [u8; 32])>,
        delta_receipt: Option<&str>,
    ) -> Result<PendingProposalView> {
        self.propose_output(
            artifact_id,
            output,
            content,
            reader,
            (actor, retained_at),
            None,
            fork_base.map_or(OutputBase::Head, OutputBase::Fork),
            true,
            &[],
            delta_receipt,
            None,
        )
    }

    /// Offers a deck export as a waiting proposal pinned to `base`, the
    /// version and hash the deck projected over, holding what its Keep needs
    /// to bind the deck to the version it lands (FIX 2700).
    pub(crate) fn propose_deck_export(
        &self,
        artifact_id: &EntityId,
        output: &NativeOutput,
        reader: Option<MadeByReader<'_>>,
        (actor, retained_at): (WriteActor, u64),
        base: (u64, [u8; 32]),
        hold: DeckExportHold,
        delta_receipt: Option<&str>,
    ) -> Result<PendingProposalView> {
        self.propose_output(
            artifact_id,
            output,
            BlobContent::Bytes(&output.bytes),
            reader,
            (actor, retained_at),
            Some((base, hold)),
            OutputBase::Head,
            false,
            &[],
            delta_receipt,
            None,
        )
    }

    /// Retains `output`, whose bytes are `content`, as a waiting proposal.
    /// `held` is the organ call landing its own output at a redrive
    /// ([`Self::propose_held_organ_output`]).
    #[expect(clippy::too_many_arguments)]
    pub(super) fn propose_output(
        &self,
        artifact_id: &EntityId,
        output: &NativeOutput,
        content: BlobContent<'_>,
        reader: Option<MadeByReader<'_>>,
        (actor, retained_at): (WriteActor, u64),
        deck: Option<((u64, [u8; 32]), DeckExportHold)>,
        base: OutputBase,
        authorize_content_write: bool,
        read_rows: &[EntityId],
        delta_receipt: Option<&str>,
        held: Option<&OrganWait>,
    ) -> Result<PendingProposalView> {
        let body = self
            .get_blob_artifact(artifact_id)?
            .ok_or(Error::EntityNotFound)?;
        let report = output_retention::validate_native_output(
            output,
            content,
            &body,
            authorize_content_write,
        )?;
        let explicit_fork = matches!(base, OutputBase::Fork(_));
        let base = match (base, &deck) {
            (OutputBase::Fork(base) | OutputBase::MadeAgainst(base), _) => Some(base),
            (OutputBase::Head, Some((base, _))) => Some(*base),
            (OutputBase::Head, None) => self
                .blob_artifact_head(artifact_id)?
                .map(|head| (head.version, head.content_hash)),
        };
        // An output past the inline size waits in its body file, written
        // before the writer that keeps its row opens; the row names it
        // (FIX 20812).
        let staged = self
            .stage_pending_output_body(content, self.asset_body_mint([content.len()])?.as_ref())?;
        // The producer is bound once, here, at proposal authentication and
        // retention: Keep preserves this envelope instead of rebinding it to
        // the keeper, and the provenance matches what Keep settles under
        // (blind review of #4554).
        let mut row = output_retention::native_output_pending_row(
            output,
            (actor, self.get_entity_type(&actor.entity_ref())?),
            retained_at,
            base,
            explicit_fork,
            deck.map(|(_, hold)| hold),
            report,
            delta_receipt,
            staged.is_some(),
            // An organ's output binds no producing host position (FIX 3171).
            crate::federation::record_scope::BirthPosition::default(),
            None,
        );
        row.read_rows.extend_from_slice(read_rows);
        row.read_rows.sort_unstable();
        row.read_rows.dedup();
        if authorize_content_write {
            self.put_pending_with_content_write_grant(
                artifact_id,
                &row,
                staged.as_ref(),
                reader,
                actor,
            )
        } else {
            self.put_pending(artifact_id, &row, staged.as_ref(), reader, held)
        }
    }

    /// The proposals waiting beside one artifact, oldest ref hash first.
    /// A `NeedsStaging` view retains paid answers, not proposed workbook bytes.
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
    /// Paid `NeedsStaging` answers return `None` until byte validation succeeds.
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
    /// as a version forked from the head it was made against, the head it
    /// replaced kept beside it, and a deck export binds the deck to it.
    /// Retained sheet answers stage first in this same Keep action. Keep has
    /// no work clock, so staging uses the ordinary untimed resource port.
    pub fn keep_pending_proposal(
        &self,
        artifact_id: &EntityId,
        proposal_ref: &str,
        consent: &SettleConsent,
        actor: WriteActor,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<SettleSelectOutcome> {
        let mut row = self
            .pending_row(artifact_id, proposal_ref)?
            .ok_or(Error::EntityNotFound)?;
        if matches!(&row.body, PendingBody::SheetAnswers { .. }) {
            self.authorize_settle(consent, actor)?;
            // This is the existing explicit Keep act, not an extension of the
            // expired ask. With no clock on Keep, its byte work is untimed.
            self.stage_pending_sheet_answers(artifact_id, proposal_ref, None)?;
            row = self
                .pending_row(artifact_id, proposal_ref)?
                .ok_or(Error::EntityNotFound)?;
        }
        let Some(proposal) = row.edit_proposal()? else {
            // A native output's row goes in the writer that settles it
            // (FIX 20812).
            return self.keep_native_output(
                artifact_id,
                &row,
                consent,
                actor,
                occurred,
                learned_at,
            );
        };
        let outcome = if proposal.sheet_answers.is_some() {
            self.settle_select_edit_proposal_made_by(
                artifact_id,
                &proposal,
                row.made_by.as_ref(),
                consent,
                actor,
                occurred,
                learned_at,
                row.delta_receipt.as_deref(),
            )?
        } else {
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
                    row.delta_receipt.as_deref(),
                )?,
                None => self.settle_select_edit_proposal_made_by(
                    artifact_id,
                    &proposal,
                    row.made_by.as_ref(),
                    consent,
                    actor,
                    occurred,
                    learned_at,
                    row.delta_receipt.as_deref(),
                )?,
            }
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
        let Some(proposal) = row.edit_proposal()? else {
            // A native output's row goes in the writer that settles it
            // (FIX 20812).
            return self.discard_native_output(
                artifact_id,
                &row,
                consent,
                actor,
                reason,
                learned_at,
            );
        };
        let outcome = self.settle_discard_edit_proposal(
            artifact_id,
            &proposal,
            consent,
            actor,
            reason,
            learned_at,
        )?;
        self.drop_pending(artifact_id, proposal_ref)?;
        Ok(outcome)
    }

    /// Discards one waiting native output: its consume-once record, and
    /// its row deleted and its body file released, in one writer.
    fn discard_native_output(
        &self,
        artifact_id: &EntityId,
        row: &PendingRow,
        consent: &SettleConsent,
        actor: WriteActor,
        reason: &str,
        learned_at: u64,
    ) -> Result<SettleDiscardOutcome> {
        self.authorize_settle(consent, actor)?;
        let reason = reason.trim();
        let key = settlement_key_parts(artifact_id, &row.proposal_ref);
        let record = self.with_write_txn_grouped(|wtxn| {
            let grant_ref = self.authorize_settle_in_txn(wtxn, consent, actor)?;
            move_ref_in_txn(&self.store, wtxn, &key, RefMove::Settle)?;
            let mut record = output_record(
                row,
                SettleOutcomeKind::Discarded,
                (consent, actor),
                learned_at,
                (None, None),
                grant_ref,
            );
            record.reason = (!reason.is_empty()).then(|| reason.to_owned());
            RECORD.put(&self.store, wtxn, &key, &record)?;
            self.drop_pending_in_txn(wtxn, artifact_id, &key)?;
            Ok(record)
        })?;
        Ok(SettleDiscardOutcome {
            receipt: settlement_receipt_record(*artifact_id, &record)?,
        })
    }

    fn put_pending(
        &self,
        artifact_id: &EntityId,
        row: &PendingRow,
        staged: Option<&StagedPendingBody>,
        reader: Option<MadeByReader<'_>>,
        held: Option<&OrganWait>,
    ) -> Result<PendingProposalView> {
        let lane =
            admission::retention_lane(artifact_id, row.made_by.as_ref(), row.retained_by, reader)?;
        self.with_write_txn_grouped(|wtxn| {
            // A named envelope is admitted in the transaction that keeps it
            // (FIX 1229).
            if let (Some(lane), Some(made_by)) = (&lane, &row.made_by) {
                admission::admit_made_by_in_txn(self, wtxn, lane, made_by, row.retained_by)?;
            }
            self.put_pending_in_txn(wtxn, artifact_id, row, staged, held)
        })
    }

    /// [`Self::put_pending`] with the direct append door's shared content-write
    /// check in the same transaction as the retained proposal (FIX 8208).
    fn put_pending_with_content_write_grant(
        &self,
        artifact_id: &EntityId,
        row: &PendingRow,
        staged: Option<&StagedPendingBody>,
        reader: Option<MadeByReader<'_>>,
        actor: WriteActor,
    ) -> Result<PendingProposalView> {
        let lane =
            admission::retention_lane(artifact_id, row.made_by.as_ref(), row.retained_by, reader)?;
        self.with_write_txn_grouped(|wtxn| {
            self.put_pending_with_content_write_grant_in_txn(
                wtxn,
                artifact_id,
                row,
                staged,
                lane.as_ref(),
                actor,
            )
        })
    }

    /// Holds `row` beside its artifact in `wtxn`: a settled ref, one already
    /// waiting, or one an organ call holds is refused, unless `held` is that
    /// call landing its own output, whose hold ends here (FIX 22386). An
    /// output staged to its body file (`staged`) is named here, its
    /// descriptor committing with the row (FIX 20812). The view is the row as
    /// it is kept.
    fn put_pending_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        artifact_id: &EntityId,
        row: &PendingRow,
        staged: Option<&StagedPendingBody>,
        held: Option<&OrganWait>,
    ) -> Result<PendingProposalView> {
        validate_pending_ref(&row.proposal_ref)?;
        let key = settlement_key_parts(artifact_id, &row.proposal_ref);
        move_ref_in_txn(&self.store, wtxn, &key, RefMove::LandProposal { held })?;
        if super::artifact_retention_deleted_in_txn(&self.store, wtxn, artifact_id)? {
            return Err(Error::EntityNotFound);
        }
        let Some(staged) = staged else {
            PENDING.put(&self.store, wtxn, &key, row)?;
            return Ok(row.view(*artifact_id));
        };
        let row = PendingRow {
            new_file: Some(self.bind_pending_output_body_in_txn(wtxn, artifact_id, staged)?),
            ..row.clone()
        };
        PENDING.put(&self.store, wtxn, &key, &row)?;
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

    /// Deletes one settled edit proposal's waiting row.
    fn drop_pending(&self, artifact_id: &EntityId, proposal_ref: &str) -> Result<()> {
        let key = settlement_key_parts(artifact_id, proposal_ref);
        self.with_write_txn_grouped(|wtxn| self.drop_pending_in_txn(wtxn, artifact_id, &key))
    }

    /// Deletes the waiting row under `key` in `wtxn` and releases the body
    /// file it names (FIX 20812).
    fn drop_pending_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        artifact_id: &EntityId,
        key: &(EntityId, [u8; 32]),
    ) -> Result<()> {
        if let Some(file) = PENDING
            .get(&self.store, wtxn, key)?
            .and_then(|row| row.new_file)
        {
            body_file::release_pending_output_body_in_txn(&self.store, wtxn, artifact_id, &file)?;
        }
        PENDING.delete(&self.store, wtxn, key).map(|_| ())
    }
}

/// The row a held edit proposal waits in: only one that passed its gate waits.
/// `kind` is the retaining actor's entity type; `read_rows` what its producer
/// read beside its base and its made_by, each kept once.
fn edit_pending_row(
    proposal: &EditProposal,
    made_by: Option<&MadeBy>,
    (actor, kind): (WriteActor, Option<u8>),
    retained_at: u64,
    read_rows: &[EntityId],
    delta_receipt: Option<&str>,
) -> Result<PendingRow> {
    if !proposal.validation.ok || proposal.new_bytes.is_empty() {
        return Err(Error::Artifact(ArtifactError::EditRoundtripFailed(
            "only a proposal that passed its gate waits for Keep",
        )));
    }
    Ok(PendingRow {
        proposal_ref: proposal.run_ref.clone(),
        retained_by: actor.entity_ref(),
        retained_by_kind: kind,
        retained_at,
        made_by: made_by.cloned(),
        base_version: proposal.base_version,
        base_content_hash: Some(proposal.base_content_hash),
        explicit_fork: false,
        next_sheet_row: None,
        new_bytes: proposal.new_bytes.clone(),
        new_file: None,
        read_rows: {
            let mut rows = read_rows.to_vec();
            rows.sort_unstable();
            rows.dedup();
            rows
        },
        deck: None,
        delta_receipt: delta_receipt.map(str::to_owned),
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
    })
}

pub(super) fn validate_pending_ref(proposal_ref: &str) -> Result<()> {
    if proposal_ref.trim().is_empty() || proposal_ref.len() > BLOB_ARTIFACT_RUN_REF_MAX_BYTES {
        return Err(Error::Artifact(ArtifactError::EditRoundtripFailed(
            "proposal ref must be non-empty and within the run-ref length bound",
        )));
    }
    crate::batch::secret_scan::scan_metadata_field(proposal_ref)
}

/// Deletes every row waiting beside `artifact_id`, releasing each body file
/// a row names (FIX 20812). A row that does not decode is deleted all the
/// same; any file it named is the artifact's, which an artifact's own
/// release of its bodies takes.
pub(super) fn purge_artifact_in_txn(
    store: &crate::store::Store,
    txn: &mut heed::RwTxn<'_>,
    artifact_id: &EntityId,
) -> Result<()> {
    for key in PENDING.scan_keys(store, txn, artifact_id.as_bytes())? {
        let file = PENDING
            .get_bytes(store, txn, &key)?
            .and_then(|bytes| PENDING.decode_value(&bytes).ok())
            .and_then(|row| row.new_file);
        if let Some(file) = file {
            body_file::release_pending_output_body_in_txn(store, txn, artifact_id, &file)?;
        }
        PENDING.delete(store, txn, &key)?;
    }
    Ok(())
}
