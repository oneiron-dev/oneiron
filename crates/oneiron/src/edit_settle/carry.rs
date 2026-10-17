//! ARCH-0075 §4: a held answer proposal whose units change under it.
//!
//! A held typed-answer proposal (answers over sheet rows, a folder column or
//! paragraphs) is judged unit by unit against one revision. When somebody
//! edits a unit while it waits, only that unit's answer is withdrawn: Keep
//! carries the untouched answers onto the head and lands them, each still
//! naming the revision it was judged against, and records every withdrawn
//! answer with the revision it changed in. After a quiet interval (the
//! `artifact_answer_quiet_seconds` policy row) the proposer is woken with
//! the changed units: the ask's question is asked of them again as its
//! principal, and the answers wait as a fresh proposal for Keep. A wake
//! never settles anything; acceptance stays a Keep.
//!
//! The wake pass also looks at proposals still waiting: a unit that changes
//! before anyone presses Keep is withdrawn and asked again the same way.
//! Slide reviews and other held edits are not split; a moved base strands
//! them whole.

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use super::codec::{RECORD, settlement_key_parts};
use super::pending::{PENDING, PendingProposalView};
use super::receipts::{already_settled, manifest_ref, settlement_receipt_record};
use super::records::{
    SettleConsent, SettleOutcomeKind, SettleSelectOutcome, SettlementRecord,
};
use crate::Vault;
use crate::anchored_annotation::ReanchorSummary;
use crate::blob_artifact::read_blob_artifact_head_in_txn;
use crate::edit_roundtrip::judgment_cells::named_sheet_cells;
use crate::edit_roundtrip::paragraph_review::carry_paragraph_judgments;
use crate::edit_roundtrip::slides_review::SlideReviewLabels;
use crate::edit_roundtrip::{
    ArtifactAsk, CellRef, CellValue, EditProposal, FolderAsk, FolderItem, OfficeFormat,
    ParagraphAsk, RangeRef, SheetAnswerBundle, SheetRowReads, SheetRowsAsk, UnitDecider,
};
use crate::entity_id::EntityId;
use crate::error::{ArtifactError, Error, Result};
use crate::llm::decision::{
    DecisionBandPolicy, DecisionDial, DecisionQuestion, Reversibility, TypedDecision,
};
use crate::provenance::made_by::MadeBy;
use crate::receipt::ReceiptRecord;
use crate::side_table::{self, Named, SideTable};
use crate::temporal::TimeRange;
use crate::write_envelope::WriteActor;

/// Key: id16 + hash32 (blake3 of the proposal ref), as the settlement ledger.
const WITHDRAWALS: SideTable<(EntityId, [u8; 32]), UnitWithdrawal, Named> =
    SideTable::new(&side_table::EDIT_SETTLE_UNIT_WITHDRAWAL);

/// How long a wake that failed waits before it is tried again.
const FAILED_WAKE_HOLD_SECS: u64 = 300;
/// Each re-asked unit's call clock, and the whole wake's.
const WAKE_UNIT_BUDGET: Duration = Duration::from_secs(30);
const WAKE_DEADLINE: Duration = Duration::from_secs(300);

/// Why an answer was withdrawn.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WithdrawReason {
    /// What the call read changed: the row's cells or the header row, the
    /// paragraph's text, the file.
    UnitChanged,
    /// The unit is gone from the head.
    UnitMissing,
    /// Somebody wrote the answer's own cell.
    AnswerCellChanged,
}

/// A withdrawn answer's unit, as its ask names it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WithdrawnUnit {
    SheetRow { row: u32 },
    Paragraph { block: String },
    FolderItem { file: EntityId, row: u32 },
}

/// One answer withdrawn because its unit changed after it was judged.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WithdrawnAnswer {
    pub unit: WithdrawnUnit,
    /// What the call read, at the revision the answer was judged against.
    pub judged_on: EntityId,
    pub judged_version: Option<u64>,
    pub judged_hash: [u8; 32],
    /// The version the unit was found changed in.
    pub changed_version: Option<u64>,
    pub reason: WithdrawReason,
    /// The withdrawn decision, kept for the record; it never lands.
    pub decision: TypedDecision,
    /// When the proposer was woken to re-evaluate it.
    pub woken_at: Option<u64>,
}

/// How the ask a wake asks again was shaped.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ReaskShape {
    SheetRows {
        sheet: String,
        answer_col: u32,
        reads: SheetRowReads,
        max_count_override: Option<u64>,
    },
    FolderItems {
        sheet: String,
        answer_col: u32,
        max_count_override: Option<u64>,
    },
    Paragraphs {
        author: String,
        labels: SlideReviewLabels,
    },
}

/// The answers withdrawn from one held proposal, and its proposer's wake.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UnitWithdrawal {
    pub artifact: EntityId,
    pub proposal_ref: String,
    pub question: DecisionQuestion,
    pub principal: EntityId,
    pub made_by: Option<MadeBy>,
    pub shape: ReaskShape,
    pub answers: Vec<WithdrawnAnswer>,
    /// The versions of the artifact and the files its answers read when the
    /// proposal was last split.
    pub observed: Vec<(EntityId, u64)>,
    /// The proposals each wake asked the changed units in.
    pub reask_refs: Vec<String>,
    /// A failed wake is tried again from here.
    pub retry_at: Option<u64>,
}

/// A held answer proposal split against what it read now.
pub(super) struct Split {
    /// The untouched answers on the head, when any of them writes a cell or
    /// a comment.
    pub(super) carried: Option<EditProposal>,
    pub(super) withdrawal: UnitWithdrawal,
}

impl Vault {
    /// Splits a held typed-answer proposal against the artifact's head and
    /// the files its answers read. `None` when nothing it read moved, or it
    /// holds no answers a split covers. With `carry`, the untouched answers
    /// are staged on the head as the proposal to land.
    pub(super) fn split_typed_answers(
        &self,
        artifact: &EntityId,
        proposal: &EditProposal,
        principal: EntityId,
        made_by: Option<&MadeBy>,
        carry: bool,
    ) -> Result<Option<Split>> {
        if let Some(bundle) = proposal.sheet_answers.as_deref() {
            return self.split_sheet_answers(artifact, proposal, bundle, made_by, carry);
        }
        if proposal.format == OfficeFormat::Docx
            && !proposal.manifest.paragraph_judgments.is_empty()
        {
            return self.split_paragraphs(artifact, proposal, principal, made_by, carry);
        }
        Ok(None)
    }

    fn split_sheet_answers(
        &self,
        artifact: &EntityId,
        proposal: &EditProposal,
        bundle: &SheetAnswerBundle,
        made_by: Option<&MadeBy>,
        carry: bool,
    ) -> Result<Option<Split>> {
        let Some(base_version) = proposal.base_version else {
            return Ok(None);
        };
        let head = self
            .blob_artifact_head(artifact)?
            .ok_or(Error::EntityNotFound)?;
        let moved =
            head.version != base_version || head.content_hash != proposal.base_content_hash;
        // Each folder answer's file as it stands now: its head and hash.
        let mut files = Vec::with_capacity(bundle.answers.len());
        let mut files_moved = false;
        for answer in &bundle.answers {
            let now = match &answer.source {
                Some(pin) => {
                    let now = self
                        .blob_artifact_head(&pin.id)?
                        .map(|file| (file.version, file.content_hash));
                    files_moved |= now.is_none_or(|(_, hash)| hash != pin.body_hash);
                    now
                }
                None => None,
            };
            files.push(now);
        }
        if !moved && !files_moved {
            return Ok(None);
        }
        let answer_col = bundle.range.start.col;
        let rows: BTreeSet<u32> = bundle.answers.iter().map(|answer| answer.cell.row).collect();
        let reads = bundle.reads;
        let read_cols: Vec<u32> = reads
            .map(|reads| {
                (reads.first_col..=reads.last_col)
                    .filter(|col| *col != answer_col)
                    .collect()
            })
            .unwrap_or_default();
        let header_row = reads.and_then(|reads| reads.header_row);
        let wanted = |cell: &CellRef| {
            (cell.col == answer_col && rows.contains(&cell.row))
                || (read_cols.contains(&cell.col)
                    && (rows.contains(&cell.row) || Some(cell.row) == header_row))
        };
        // The cells the answers read and write, at their base and on the head.
        let (then, now) = if moved {
            let base = self
                .read_blob_artifact_version(artifact, base_version)?
                .ok_or(Error::EntityNotFound)?;
            let current = self
                .read_blob_artifact_version(artifact, head.version)?
                .ok_or(Error::EntityNotFound)?;
            (
                named_sheet_cells(&base, &bundle.sheet, &wanted)?,
                named_sheet_cells(&current, &bundle.sheet, &wanted).ok(),
            )
        } else {
            (Default::default(), None)
        };
        let differs = |cell: CellRef| {
            let read = |cells: &std::collections::BTreeMap<CellRef, CellValue>| {
                cells.get(&cell).cloned().unwrap_or(CellValue::Blank)
            };
            now.as_ref().is_none_or(|now| read(&then) != read(now))
        };
        let header_changed = moved
            && header_row.is_some_and(|row| {
                read_cols
                    .iter()
                    .any(|col| differs(CellRef { col: *col, row }))
            });
        let mut kept = Vec::new();
        let mut withdrawn = Vec::new();
        for (answer, file) in bundle.answers.iter().zip(&files) {
            let reason = if moved && now.is_none() {
                Some(WithdrawReason::UnitMissing)
            } else if moved && differs(answer.cell) {
                Some(WithdrawReason::AnswerCellChanged)
            } else if moved
                && (header_changed
                    || read_cols.iter().any(|col| {
                        differs(CellRef {
                            col: *col,
                            row: answer.cell.row,
                        })
                    }))
            {
                Some(WithdrawReason::UnitChanged)
            } else if let Some(pin) = &answer.source {
                match file {
                    None => Some(WithdrawReason::UnitMissing),
                    Some((_, hash)) if *hash != pin.body_hash => Some(WithdrawReason::UnitChanged),
                    Some(_) => None,
                }
            } else {
                None
            };
            let Some(reason) = reason else {
                kept.push(answer.clone());
                continue;
            };
            let (unit, judged_on, judged_hash, changed_version) = match &answer.source {
                Some(pin) => (
                    WithdrawnUnit::FolderItem {
                        file: pin.id,
                        row: answer.cell.row,
                    },
                    pin.id,
                    pin.body_hash,
                    match reason {
                        WithdrawReason::AnswerCellChanged => Some(head.version),
                        _ => file.map(|(version, _)| version),
                    },
                ),
                None => (
                    WithdrawnUnit::SheetRow {
                        row: answer.cell.row,
                    },
                    *artifact,
                    proposal.base_content_hash,
                    Some(head.version),
                ),
            };
            withdrawn.push(WithdrawnAnswer {
                unit,
                judged_on,
                judged_version: answer.judged_version,
                judged_hash,
                changed_version,
                reason,
                decision: answer.decision.clone(),
                woken_at: None,
            });
        }
        let carried = if carry && kept.iter().any(|answer| answer.value.is_some()) {
            let mut bundle = bundle.clone();
            bundle.answers = kept;
            self.stage_sheet_answers(
                artifact,
                bundle,
                &proposal.run_ref,
                head.version,
                head.content_hash,
            )?
        } else {
            None
        };
        let files: Vec<EntityId> = bundle
            .answers
            .iter()
            .filter_map(|answer| answer.source.as_ref().map(|pin| pin.id))
            .collect();
        let shape = match reads {
            Some(reads) => ReaskShape::SheetRows {
                sheet: bundle.sheet.clone(),
                answer_col,
                reads,
                max_count_override: bundle.max_count_override,
            },
            None => ReaskShape::FolderItems {
                sheet: bundle.sheet.clone(),
                answer_col,
                max_count_override: bundle.max_count_override,
            },
        };
        Ok(Some(Split {
            carried,
            withdrawal: UnitWithdrawal {
                artifact: *artifact,
                proposal_ref: proposal.run_ref.clone(),
                question: bundle.question.clone(),
                principal: bundle.principal,
                made_by: made_by.cloned(),
                shape,
                answers: withdrawn,
                observed: self.observed_versions(artifact, &files)?,
                reask_refs: Vec::new(),
                retry_at: None,
            },
        }))
    }

    fn split_paragraphs(
        &self,
        artifact: &EntityId,
        proposal: &EditProposal,
        principal: EntityId,
        made_by: Option<&MadeBy>,
        carry: bool,
    ) -> Result<Option<Split>> {
        let (Some(base_version), Some(question)) = (
            proposal.base_version,
            proposal.manifest.paragraph_question.as_ref(),
        ) else {
            return Ok(None);
        };
        let head = self
            .blob_artifact_head(artifact)?
            .ok_or(Error::EntityNotFound)?;
        if head.version == base_version && head.content_hash == proposal.base_content_hash {
            return Ok(None);
        }
        let current = self
            .read_blob_artifact_version(artifact, head.version)?
            .ok_or(Error::EntityNotFound)?;
        let limits = {
            let rtxn = self.store.env.read_txn()?;
            self.docx_archive_limits_in_txn(&rtxn, Some(principal))?
        };
        let blocks = oneiron_docedit::docx_body::read_docx_blocks(&current, limits).map_err(|_| {
            Error::Artifact(ArtifactError::InvalidEditManifest(
                "the held paragraphs' document does not read",
            ))
        })?;
        let rows = &proposal.manifest.paragraph_judgments;
        let mut kept = Vec::new();
        let mut withdrawn = Vec::new();
        for row in rows {
            let reason = match blocks.iter().find(|block| block.id == row.block) {
                None => Some(WithdrawReason::UnitMissing),
                Some(block)
                    if block.locked.is_some()
                        || !matches!(
                            block.kind,
                            oneiron_docedit::docx_body::DocxBlockKind::Paragraph
                                | oneiron_docedit::docx_body::DocxBlockKind::Heading(_)
                        )
                        || *blake3::hash(block.text.as_bytes()).as_bytes() != row.text_hash =>
                {
                    Some(WithdrawReason::UnitChanged)
                }
                Some(_) => None,
            };
            match reason {
                None => kept.push(row.clone()),
                Some(reason) => withdrawn.push(WithdrawnAnswer {
                    unit: WithdrawnUnit::Paragraph {
                        block: row.block.clone(),
                    },
                    judged_on: *artifact,
                    judged_version: row.judged_version,
                    judged_hash: row.frontier,
                    changed_version: Some(head.version),
                    reason,
                    decision: row.decision.clone(),
                    woken_at: None,
                }),
            }
        }
        let shape = ReaskShape::Paragraphs {
            author: rows[0].author.clone(),
            labels: rows[0].labels.clone(),
        };
        let carried = if carry && !kept.is_empty() {
            let mut carried = carry_paragraph_judgments(
                &current,
                head.version,
                kept,
                &proposal.run_ref,
                limits,
            )?;
            carried.manifest.paragraph_question = Some(question.clone());
            Some(carried)
        } else {
            None
        };
        Ok(Some(Split {
            carried,
            withdrawal: UnitWithdrawal {
                artifact: *artifact,
                proposal_ref: proposal.run_ref.clone(),
                question: question.clone(),
                principal,
                made_by: made_by.cloned(),
                shape,
                answers: withdrawn,
                observed: self.observed_versions(artifact, &[])?,
                reask_refs: Vec::new(),
                retry_at: None,
            },
        }))
    }

    /// The head versions of `artifact` and `files`, a missing head as 0.
    fn observed_versions(
        &self,
        artifact: &EntityId,
        files: &[EntityId],
    ) -> Result<Vec<(EntityId, u64)>> {
        std::iter::once(artifact)
            .chain(files)
            .map(|id| {
                Ok((
                    *id,
                    self.blob_artifact_head(id)?.map_or(0, |head| head.version),
                ))
            })
            .collect()
    }

    /// Keeps a split proposal: its untouched answers land on the head, the
    /// withdrawn ones are recorded with the select. With none to land, the
    /// ref is consumed and nothing is appended; the withdrawn answers wait
    /// for their wake.
    #[expect(clippy::too_many_arguments)]
    pub(super) fn keep_split(
        &self,
        artifact: &EntityId,
        held: &EditProposal,
        split: Split,
        made_by: Option<&MadeBy>,
        consent: &SettleConsent,
        actor: WriteActor,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<SettleSelectOutcome> {
        let withdrawal =
            (!split.withdrawal.answers.is_empty()).then_some(&split.withdrawal);
        match &split.carried {
            Some(carried) => self.settle_select_carried(
                artifact,
                carried,
                made_by,
                consent,
                actor,
                occurred,
                learned_at,
                Some(withdrawal),
            ),
            None => self.settle_all_withdrawn(
                artifact,
                held,
                &split.withdrawal,
                consent,
                actor,
                learned_at,
            ),
        }
    }

    /// The Keep of a held answer proposal none of whose answers still
    /// stand: the ref is consumed with the withdrawn answers recorded, and
    /// no version is appended.
    fn settle_all_withdrawn(
        &self,
        artifact: &EntityId,
        held: &EditProposal,
        withdrawal: &UnitWithdrawal,
        consent: &SettleConsent,
        actor: WriteActor,
        learned_at: u64,
    ) -> Result<SettleSelectOutcome> {
        self.authorize_settle(consent, actor)?;
        let key = settlement_key_parts(artifact, &held.run_ref);
        let manifest_hash = manifest_ref(&held.manifest)?;
        let (head, record) = self.with_write_txn_grouped(|wtxn| {
            self.authorize_settle_in_txn(wtxn, consent, actor)?;
            if let Some(existing) = RECORD.get(&self.store, wtxn, &key)? {
                return Err(already_settled(&existing));
            }
            let head = read_blob_artifact_head_in_txn(&self.store, wtxn, artifact)?
                .ok_or(Error::EntityNotFound)?;
            let record = SettlementRecord {
                proposal_ref: held.run_ref.clone(),
                outcome: SettleOutcomeKind::Proposed,
                settled_at: learned_at,
                actor_ref: Some(actor.entity_ref().to_hex()),
                brief_ref: consent.brief_ref().map(str::to_owned),
                before_version: held.base_version,
                version: Some(head.version),
                content_hash: Some(head.content_hash),
                manifest_ref: Some(manifest_hash),
                manifest_ops: u64::try_from(held.manifest.ops.len()).unwrap_or(u64::MAX),
                pptx_slide_creation_id_mints: Vec::new(),
                pptx_review_identities: Vec::new(),
                pptx_judgments: Vec::new(),
                docx_judgments: held.manifest.paragraph_judgments.clone(),
                anchors: Vec::new(),
                reason: Some("units_withdrawn".to_owned()),
                sheet_answers: held.sheet_answers.clone(),
                deck: None,
            };
            RECORD.put(&self.store, wtxn, &key, &record)?;
            self.record_unit_withdrawal_in_txn(wtxn, &key, withdrawal)?;
            Ok((head, record))
        })?;
        let receipt = settlement_receipt_record(*artifact, &record)?;
        Ok(SettleSelectOutcome {
            stranded_proposal: None,
            receipt: self.with_withdrawn_units(*artifact, &record, receipt)?,
            version: head,
            reanchor: ReanchorSummary::default(),
        })
    }

    /// Merges `fresh` into the withdrawal under `key`: an answer already
    /// woken keeps its wake, and a unit already withdrawn is not added twice.
    pub(super) fn record_unit_withdrawal_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        key: &(EntityId, [u8; 32]),
        fresh: &UnitWithdrawal,
    ) -> Result<()> {
        let mut row = WITHDRAWALS
            .get(&self.store, wtxn, key)?
            .unwrap_or_else(|| UnitWithdrawal {
                answers: Vec::new(),
                ..fresh.clone()
            });
        for answer in &fresh.answers {
            match row.answers.iter_mut().find(|held| held.unit == answer.unit) {
                Some(held) if held.woken_at.is_some() => {}
                Some(held) => *held = answer.clone(),
                None => row.answers.push(answer.clone()),
            }
        }
        row.observed.clone_from(&fresh.observed);
        WITHDRAWALS.put(&self.store, wtxn, key, &row)?;
        Ok(())
    }

    /// `receipt` with the answers its proposal withdrew, each with the
    /// revision it was judged against, the version it changed in and its
    /// wake. A discarded proposal's withdrawals wake nothing and show none.
    pub(super) fn with_withdrawn_units(
        &self,
        artifact: EntityId,
        record: &SettlementRecord,
        receipt: ReceiptRecord,
    ) -> Result<ReceiptRecord> {
        let rtxn = self.store.env.read_txn()?;
        self.with_withdrawn_units_in_txn(&rtxn, artifact, record, receipt)
    }

    /// [`Self::with_withdrawn_units`] on an open read.
    pub(super) fn with_withdrawn_units_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        artifact: EntityId,
        record: &SettlementRecord,
        mut receipt: ReceiptRecord,
    ) -> Result<ReceiptRecord> {
        if record.outcome == SettleOutcomeKind::Discarded {
            return Ok(receipt);
        }
        let key = settlement_key_parts(&artifact, &record.proposal_ref);
        if let Some(row) = WITHDRAWALS.get(&self.store, txn, &key)?
            && !row.answers.is_empty()
        {
            receipt.fields.insert(
                super::keys::FIELD_WITHDRAWN_UNITS.to_owned(),
                withdrawn_units_field(&row)?,
            );
        }
        Ok(receipt)
    }

    /// When the next proposer wake falls due: the last change to what its
    /// withdrawn answers read, plus the vault's quiet interval.
    pub fn next_answer_wake_at(&self) -> Result<Option<u64>> {
        let rtxn = self.store.env.read_txn()?;
        let quiet = crate::gate::resolve_policy_manifest(&self.store, &rtxn)?
            .artifact_answer_quiet_seconds();
        let mut next: Option<u64> = None;
        for entry in WITHDRAWALS.iter_from(&self.store, &rtxn, &[])? {
            let (key, row) = entry?;
            if let Some(due) = self.wake_due_in_txn(&rtxn, &key, &row, quiet)? {
                next = Some(next.map_or(due, |next| next.min(due)));
            }
        }
        Ok(next)
    }

    /// Withdraws the answers of every waiting proposal whose units changed
    /// since it was last split, then returns the withdrawals due at `now`,
    /// each holding only the answers that wait for a wake.
    pub fn due_answer_wakes(&self, now: u64) -> Result<Vec<UnitWithdrawal>> {
        for held in self.held_answer_proposals()? {
            let (artifact, _) = held.key;
            let prior = self.read_unit_withdrawal(&held.key)?;
            let files: Vec<EntityId> = held
                .proposal
                .sheet_answers
                .iter()
                .flat_map(|bundle| bundle.answers.iter())
                .filter_map(|answer| answer.source.as_ref().map(|pin| pin.id))
                .collect();
            let observed = self.observed_versions(&artifact, &files)?;
            let judged = std::iter::once((artifact, held.proposal.base_version.unwrap_or(0)))
                .chain(
                    held.proposal
                        .sheet_answers
                        .iter()
                        .flat_map(|bundle| bundle.answers.iter())
                        .filter_map(|answer| {
                            Some((answer.source.as_ref()?.id, answer.judged_version?))
                        }),
                )
                .collect::<Vec<_>>();
            if prior.as_ref().map_or(&judged, |row| &row.observed) == &observed {
                continue;
            }
            let Some(split) = self.split_typed_answers(
                &artifact,
                &held.proposal,
                held.retained_by,
                held.made_by.as_ref(),
                false,
            )?
            else {
                continue;
            };
            self.with_write_txn(|wtxn| {
                // The proposal may have settled since it was read.
                if !PENDING.contains(&self.store, wtxn, &held.key)?
                    || RECORD.contains(&self.store, wtxn, &held.key)?
                {
                    return Ok(());
                }
                self.record_unit_withdrawal_in_txn(wtxn, &held.key, &split.withdrawal)
            })?;
        }
        let rtxn = self.store.env.read_txn()?;
        let quiet = crate::gate::resolve_policy_manifest(&self.store, &rtxn)?
            .artifact_answer_quiet_seconds();
        let mut due = Vec::new();
        for entry in WITHDRAWALS.iter_from(&self.store, &rtxn, &[])? {
            let (key, mut row) = entry?;
            if self
                .wake_due_in_txn(&rtxn, &key, &row, quiet)?
                .is_some_and(|at| at <= now)
            {
                row.answers.retain(|answer| answer.woken_at.is_none());
                due.push(row);
            }
        }
        Ok(due)
    }

    /// The actor a wake asks as: the withdrawn answers' principal.
    pub fn answer_wake_actor(&self, wake: &UnitWithdrawal) -> Result<WriteActor> {
        crate::llm::decision::questions::principal_actor(self, wake.principal)
    }

    /// Wakes one withdrawal's proposer: the ask's question is asked again of
    /// each changed unit on the head, as `actor` through `decider`, and the
    /// answers wait as a fresh proposal for Keep. The asked units are marked
    /// woken whatever the answers, so each is asked again once; a wake that
    /// fails is held, then tried again.
    pub fn wake_answer_proposer(
        &self,
        wake: &UnitWithdrawal,
        actor: WriteActor,
        decider: &dyn UnitDecider,
        dial: DecisionDial,
        policy: &DecisionBandPolicy,
        now: u64,
    ) -> Result<Option<PendingProposalView>> {
        let key = settlement_key_parts(&wake.artifact, &wake.proposal_ref);
        let woke = self.reask(wake, actor, decider, dial, policy, now);
        let (proposed, reask_ref) = match woke {
            Ok(woke) => woke,
            Err(error) => {
                let _ = self.with_write_txn(|wtxn| {
                    if let Some(mut row) = WITHDRAWALS.get(&self.store, wtxn, &key)? {
                        row.retry_at = Some(now.saturating_add(FAILED_WAKE_HOLD_SECS));
                        WITHDRAWALS.put(&self.store, wtxn, &key, &row)?;
                    }
                    Ok(())
                });
                return Err(error);
            }
        };
        let units: Vec<&WithdrawnUnit> = wake.answers.iter().map(|answer| &answer.unit).collect();
        self.with_write_txn(|wtxn| {
            let Some(mut row) = WITHDRAWALS.get(&self.store, wtxn, &key)? else {
                return Ok(());
            };
            for answer in &mut row.answers {
                if answer.woken_at.is_none() && units.contains(&&answer.unit) {
                    answer.woken_at = Some(now);
                }
            }
            if !row.reask_refs.contains(&reask_ref) {
                row.reask_refs.push(reask_ref.clone());
            }
            row.retry_at = None;
            WITHDRAWALS.put(&self.store, wtxn, &key, &row)?;
            Ok(())
        })?;
        Ok(proposed)
    }

    /// The ask a wake makes, and the ref its proposal waits under.
    fn reask(
        &self,
        wake: &UnitWithdrawal,
        actor: WriteActor,
        decider: &dyn UnitDecider,
        dial: DecisionDial,
        policy: &DecisionBandPolicy,
        now: u64,
    ) -> Result<(Option<PendingProposalView>, String)> {
        let head = self
            .blob_artifact_head(&wake.artifact)?
            .ok_or(Error::EntityNotFound)?;
        let reask_ref = format!(
            "reask:{}:{}",
            &blake3::hash(wake.proposal_ref.as_bytes()).to_hex()[..16],
            head.version
        );
        // A wake that asked but was not marked asks nothing again.
        if self.pending_proposal(&wake.artifact, &reask_ref)?.is_some()
            || self
                .blob_artifact_settlement(&wake.artifact, &reask_ref)?
                .is_some()
        {
            return Ok((None, reask_ref));
        }
        let ask = ArtifactAsk {
            question: &wake.question,
            principal: wake.principal,
            dial,
            policy,
            reversibility: Reversibility::ReversibleRead,
            decider,
            evidence: &[],
            budget: WAKE_UNIT_BUDGET,
            deadline: Instant::now() + WAKE_DEADLINE,
            run_ref: &reask_ref,
        };
        let run = match &wake.shape {
            ReaskShape::SheetRows {
                sheet,
                answer_col,
                reads,
                max_count_override,
            } => {
                let rows: BTreeSet<u32> = wake
                    .answers
                    .iter()
                    .filter_map(|answer| match answer.unit {
                        WithdrawnUnit::SheetRow { row } => Some(row),
                        _ => None,
                    })
                    .collect();
                let (Some(first), Some(last)) = (rows.first().copied(), rows.last().copied())
                else {
                    return Ok((None, reask_ref));
                };
                self.ask_blob_artifact_sheet_rows(
                    &wake.artifact,
                    &SheetRowsAsk {
                        ask,
                        sheet,
                        rows: RangeRef {
                            start: CellRef {
                                col: reads.first_col,
                                row: first,
                            },
                            end: CellRef {
                                col: reads.last_col,
                                row: last,
                            },
                        },
                        answer_col: *answer_col,
                        header_row: reads.header_row,
                        max_count_override: *max_count_override,
                        only_rows: Some(&rows),
                    },
                )?
            }
            ReaskShape::FolderItems {
                sheet,
                answer_col,
                max_count_override,
            } => {
                let items: Vec<FolderItem> = wake
                    .answers
                    .iter()
                    .filter_map(|answer| match answer.unit {
                        WithdrawnUnit::FolderItem { file, row } => Some(FolderItem {
                            artifact: file,
                            row,
                        }),
                        _ => None,
                    })
                    .collect();
                if items.is_empty() {
                    return Ok((None, reask_ref));
                }
                self.ask_folder_items_into_sheet(
                    &wake.artifact,
                    &FolderAsk {
                        ask,
                        items: &items,
                        sheet,
                        answer_col: *answer_col,
                        max_count_override: *max_count_override,
                        sight: crate::secret_custody::SecretSight::Masked,
                    },
                )?
            }
            ReaskShape::Paragraphs { author, labels } => {
                let blocks: Vec<String> = wake
                    .answers
                    .iter()
                    .filter_map(|answer| match &answer.unit {
                        WithdrawnUnit::Paragraph { block } => Some(block.clone()),
                        _ => None,
                    })
                    .collect();
                if blocks.is_empty() {
                    return Ok((None, reask_ref));
                }
                self.ask_blob_artifact_paragraphs(
                    &wake.artifact,
                    &ParagraphAsk {
                        ask,
                        blocks: &blocks,
                        author,
                        labels,
                    },
                )?
            }
        };
        let proposed = match &run.proposal {
            Some(proposal) => Some(self.retain_edit_proposal(
                &wake.artifact,
                proposal,
                wake.made_by.as_ref(),
                actor,
                now,
            )?),
            None => None,
        };
        Ok((proposed, reask_ref))
    }

    fn read_unit_withdrawal(&self, key: &(EntityId, [u8; 32])) -> Result<Option<UnitWithdrawal>> {
        let rtxn = self.store.env.read_txn()?;
        WITHDRAWALS.get(&self.store, &rtxn, key)
    }

    /// When `row`'s wake falls due, or `None` when it wakes nothing: every
    /// answer was woken, or its proposal was discarded or is gone.
    fn wake_due_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        key: &(EntityId, [u8; 32]),
        row: &UnitWithdrawal,
        quiet: u64,
    ) -> Result<Option<u64>> {
        if row.answers.iter().all(|answer| answer.woken_at.is_some()) {
            return Ok(None);
        }
        let live = match RECORD.get(&self.store, txn, key)? {
            Some(record) => record.outcome != SettleOutcomeKind::Discarded,
            None => PENDING.contains(&self.store, txn, key)?,
        };
        if !live {
            return Ok(None);
        }
        let mut changed = read_blob_artifact_head_in_txn(&self.store, txn, &row.artifact)?
            .map_or(0, |head| head.created_at);
        for answer in &row.answers {
            if let WithdrawnUnit::FolderItem { file, .. } = &answer.unit
                && let Some(head) = read_blob_artifact_head_in_txn(&self.store, txn, file)?
            {
                changed = changed.max(head.created_at);
            }
        }
        let due = changed.saturating_add(quiet);
        Ok(Some(row.retry_at.map_or(due, |retry| retry.max(due))))
    }
}

/// The receipt's `withdrawn_units` field: each withdrawn answer's unit, the
/// revision it was judged against, the version it changed in, its decision
/// and its wake, and the proposals the wakes asked in.
fn withdrawn_units_field(row: &UnitWithdrawal) -> Result<String> {
    let answers: Vec<serde_json::Value> = row
        .answers
        .iter()
        .map(|answer| {
            serde_json::json!({
                "unit": answer.unit,
                "judged_on": answer.judged_on.to_hex(),
                "judged_version": answer.judged_version,
                "judged_hash": crate::receipt::hex_lower(&answer.judged_hash),
                "changed_version": answer.changed_version,
                "reason": answer.reason,
                "answer": answer.decision.answer,
                "probability": answer.decision.probability,
                "woken_at": answer.woken_at,
            })
        })
        .collect();
    serde_json::to_string(&serde_json::json!({
        "answers": answers,
        "reask_refs": row.reask_refs,
    }))
    .map_err(|_| Error::InvariantViolation("withdrawn units receipt encoding"))
}
