//! ARCH-0075 §4: a held answer proposal whose units change under it.
//!
//! A held typed-answer proposal (answers over sheet rows, a folder column,
//! paragraphs or slides) is judged unit by unit against one revision. When
//! somebody edits a unit while it waits, only that unit's answer is
//! withdrawn: Keep carries the untouched answers onto the head and lands
//! them, each still naming the revision it was judged against, and records
//! every withdrawn answer with the revision it changed in. After a quiet interval (the
//! `artifact_answer_quiet_seconds` policy row) the proposer is woken with
//! the changed units: the ask's question is asked of them again as its
//! principal, and the answers wait as a fresh proposal for Keep. A wake
//! never settles anything; acceptance stays a Keep.
//!
//! The wake pass also looks at proposals still waiting: a unit that changes
//! before anyone presses Keep is withdrawn and asked again the same way. A
//! changed slide is asked again over the host's fresh render of it. Other
//! held edits are not split; a moved base strands them whole.
//!
//! An edit to the artifact's live body that was never exported moves no
//! version, so each ask also pins the live body it stood beside, and the
//! split diffs the body at that frontier and at its head unit by unit
//! ([`live`], FIX 2115).

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use super::codec::{RECORD, settlement_key_parts};
use super::pending::{PENDING, PendingProposalView};
use super::receipts::{already_settled, manifest_ref, settlement_receipt_record};
use super::records::{
    SettleConsent, SettleOutcomeKind, SettleSelectOutcome, SettledReview, SettlementRecord,
};
use crate::Vault;
use crate::anchored_annotation::ReanchorSummary;
use crate::blob_artifact::read_blob_artifact_head_in_txn;
use crate::edit_roundtrip::judgment_cells::named_sheet_cells;
use crate::edit_roundtrip::paragraph_review::carry_paragraph_judgments;
use crate::edit_roundtrip::pptx::PptxAuthor;
use crate::edit_roundtrip::slides_review::{
    SlideNow, SlideRenderer, SlideReviewError, SlideReviewImage, SlideReviewLabels,
    SlideReviewRequest, SlideReviewUnit, carry_slide_judgments, deck_slides_now, review_copy_bytes,
};
use crate::edit_roundtrip::{
    ArtifactAsk, CellRef, CellValue, EditOp, EditProposal, FolderAsk, FolderItem, OfficeFormat,
    ParagraphAsk, ParagraphJudgment, RangeRef, SheetAnswerBundle, SheetRowReads, SheetRowsAsk,
    UnitDecider,
};
use crate::entity_id::EntityId;
use crate::error::{ArtifactError, Error, Result};
use crate::llm::decision::{
    DecisionBandPolicy, DecisionDial, DecisionQuestion, Reversibility, TypedDecision,
};
use crate::office_body::LivePin;
use crate::provenance::made_by::MadeBy;
use crate::receipt::ReceiptRecord;
use crate::side_table::{self, Named, SideTable};
use crate::temporal::TimeRange;
use crate::write_envelope::WriteActor;

mod live;
mod sheet_keep;
mod split;
mod wake;

pub(super) use sheet_keep::SheetKeep;

/// Key: id16 + hash32 (blake3 of the proposal ref), as the settlement ledger.
pub(super) const WITHDRAWALS: SideTable<(EntityId, [u8; 32]), UnitWithdrawal, Named> =
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
    /// paragraph's text, the file, what the slide shows.
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
    SheetRow {
        row: u32,
    },
    Paragraph {
        block: String,
    },
    FolderItem {
        file: EntityId,
        row: u32,
    },
    /// A slide by its managed identity, and the shape on it a shape unit
    /// names by creation id.
    Slide {
        part: String,
        sld_id: u32,
        shape: Option<String>,
    },
}

/// One answer withdrawn because its unit changed after it was judged.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WithdrawnAnswer {
    pub unit: WithdrawnUnit,
    /// What the call read, at the revision the answer was judged against.
    pub judged_on: EntityId,
    pub judged_version: Option<u64>,
    pub judged_hash: [u8; 32],
    /// The version the unit was found changed in; none when only an edit to
    /// the live body, never exported, changed it.
    pub changed_version: Option<u64>,
    /// The live body the answer was judged against, and the one an edit
    /// never exported changed the unit in (FIX 2115).
    #[serde(default)]
    pub judged_live: Option<LivePin>,
    #[serde(default)]
    pub changed_live: Option<LivePin>,
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
    Slides {
        author: PptxAuthor,
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
    /// The live bodies of the artifact and the files, those with one, when
    /// the proposal was last split (FIX 2115).
    #[serde(default)]
    pub observed_live: Vec<(EntityId, LivePin)>,
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
        if proposal.format == OfficeFormat::Pptx && !proposal.manifest.slide_judgments.is_empty() {
            return self.split_slides(artifact, proposal, principal, made_by, carry);
        }
        Ok(None)
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
        let withdrawal = (!split.withdrawal.answers.is_empty()).then_some(&split.withdrawal);
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
        let (head, record) = self.with_write_txn_grouped(|wtxn| {
            self.settle_all_withdrawn_in_txn(
                wtxn, artifact, held, withdrawal, consent, actor, learned_at,
            )
        })?;
        let receipt = settlement_receipt_record(*artifact, &record)?;
        let receipt = self.with_withdrawn_units(*artifact, &record, receipt)?;
        Ok(SettleSelectOutcome {
            stranded_proposal: None,
            receipt,
            version: head,
            reanchor: ReanchorSummary::default(),
            reconciliation: None,
            review: SettledReview::of(record),
        })
    }

    #[expect(clippy::too_many_arguments)]
    pub(super) fn settle_all_withdrawn_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        artifact: &EntityId,
        held: &EditProposal,
        withdrawal: &UnitWithdrawal,
        consent: &SettleConsent,
        actor: WriteActor,
        learned_at: u64,
    ) -> Result<(crate::blob_artifact::BlobArtifactVersion, SettlementRecord)> {
        let key = settlement_key_parts(artifact, &held.run_ref);
        let manifest_hash = manifest_ref(&held.manifest)?;
        let grant_ref = self.authorize_settle_in_txn(wtxn, consent, actor)?;
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
            grant_ref,
            before_version: held.base_version,
            version: Some(head.version),
            content_hash: Some(head.content_hash),
            manifest_ref: Some(manifest_hash),
            manifest_ops: u64::try_from(held.manifest.ops.len()).unwrap_or(u64::MAX),
            pptx_slide_creation_id_mints: Vec::new(),
            pptx_review_identities: super::settle::pptx_review_identities(held),
            pptx_judgments: held.manifest.slide_judgments.clone(),
            docx_judgments: held.manifest.paragraph_judgments.clone(),
            anchors: Vec::new(),
            reason: Some("units_withdrawn".to_owned()),
            sheet_answers: held.sheet_answers.clone(),
            deck: None,
            discarded_words: None,
        };
        RECORD.put(&self.store, wtxn, &key, &record)?;
        self.record_unit_withdrawal_in_txn(wtxn, &key, withdrawal)?;
        Ok((head, record))
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
        row.observed_live.clone_from(&fresh.observed_live);
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
            // A live body an edit never exported moved counts as a move too (FIX 2115).
            let observed_live = self.observed_live(&artifact, &files)?;
            let judged_live = live::judged_live(artifact, &held.proposal);
            let (seen, seen_live) = prior.as_ref().map_or((&judged, &judged_live), |row| {
                (&row.observed, &row.observed_live)
            });
            if seen == &observed && seen_live == &observed_live {
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

    /// The actor a wake asks as: the withdrawn answers' principal, under the
    /// class its standing question's version keeps (FIX 1588).
    pub fn answer_wake_actor(&self, wake: &UnitWithdrawal) -> Result<WriteActor> {
        let question = &wake.question;
        crate::llm::decision::questions::standing_asker_for_question(
            self,
            question.id,
            question.version,
            wake.principal,
        )
    }

    /// Commits what a wake's ask made in ONE transaction (FIX 9174): its
    /// proposal, held for Keep under `reask_ref`; its entry in the standing
    /// question's ask log; and the wake's marks (each asked unit woken, the
    /// ref listed, the hold cleared). A replay marks nothing and logs no
    /// ask; a terminal ask with no unit left retires the wake and logs no ask.
    #[expect(clippy::too_many_arguments)]
    fn commit_reask(
        &self,
        wake: &UnitWithdrawal,
        key: &(EntityId, [u8; 32]),
        actor: WriteActor,
        now: u64,
        reasked: Reasked,
        reask_ref: &str,
        read: Option<&[(EntityId, u64)]>,
    ) -> Result<Option<PendingProposalView>> {
        let (asked, proposal, unit_receipts, read_rows, retire) = match reasked {
            Reasked::Nothing => (false, None, Vec::new(), Vec::new(), true),
            Reasked::Replay => (false, None, Vec::new(), Vec::new(), false),
            Reasked::Asked {
                proposal,
                units,
                read_rows,
            } => (true, proposal, units, read_rows, false),
        };
        // The carried envelope is admitted through the principal's own read,
        // inside the asking version's saved lane, as the fresh proposal waits
        // (FIX 1229, FIX 11831), its grant clock settled before the commit
        // opens.
        let lane = match (&proposal, &wake.made_by) {
            (Some(_), Some(made_by)) => self.edit_retention_lane(
                &wake.artifact,
                Some(made_by),
                actor,
                Some(super::MadeByReader::Lane(
                    crate::llm::decision::questions::wake_lane(
                        self,
                        wake.principal,
                        &wake.question,
                    )?,
                )),
            )?,
            _ => None,
        };
        let units: Vec<&WithdrawnUnit> = wake.answers.iter().map(|answer| &answer.unit).collect();
        self.with_write_txn(|wtxn| {
            let proposed = match &proposal {
                Some(proposal) => Some(self.retain_edit_proposal_with_reads_in_txn(
                    wtxn,
                    &wake.artifact,
                    proposal,
                    wake.made_by.as_ref(),
                    lane.as_ref(),
                    (actor, now),
                    &read_rows,
                )?),
                None => None,
            };
            if asked && let Some(read) = read {
                crate::llm::decision::questions::record_standing_reask_in_txn(
                    self,
                    wtxn,
                    &standing_reask(wake, read, &unit_receipts, now),
                    proposed.as_ref().map(|_| reask_ref),
                    None,
                )?;
            }
            let Some(mut row) = WITHDRAWALS.get(&self.store, wtxn, key)? else {
                return Ok(proposed);
            };
            // A replay marks nothing: its first ask already covered the
            // evaluation. Any evaluation that ran — a real ask, or a
            // terminal one with no unit left — retires this wake's own
            // units. Only units present in this wake's snapshot are marked:
            // newly appended units stay due for their own evaluation, and
            // a later fresh wake covering them retires or asks them in turn,
            // so no expired deadline can pump forever (FIX 9826).
            if asked || retire {
                for answer in &mut row.answers {
                    if answer.woken_at.is_none() && units.contains(&&answer.unit) {
                        answer.woken_at = Some(now);
                    }
                }
            }
            if !row
                .reask_refs
                .iter()
                .any(|known| known.as_str() == reask_ref)
            {
                row.reask_refs.push(reask_ref.to_owned());
            }
            row.retry_at = None;
            WITHDRAWALS.put(&self.store, wtxn, key, &row)?;
            Ok(proposed)
        })
    }

    /// The refs the wakes of `proposal_ref`'s withdrawn answers asked again under, for a
    /// standing question that follows the artifact past them.
    pub(crate) fn answer_reask_refs(
        &self,
        artifact: &EntityId,
        proposal_ref: &str,
    ) -> Result<Vec<String>> {
        Ok(self
            .read_unit_withdrawal(&settlement_key_parts(artifact, proposal_ref))?
            .map(|row| row.reask_refs)
            .unwrap_or_default())
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
        // A live body's newest commit is a change too (FIX 2115).
        for (id, _) in &row.observed_live {
            if let Some((_, at)) = self.office_body_pin_in_txn(txn, id)? {
                changed = changed.max(at);
            }
        }
        let due = changed.saturating_add(quiet);
        Ok(Some(row.retry_at.map_or(due, |retry| retry.max(due))))
    }
}

/// What a wake's ask made, before anything commits (FIX 9174).
enum Reasked {
    /// No unit was left to ask: the wake retires with no ask logged.
    Nothing,
    /// A replay of a wake already asked under this ref: nothing is marked.
    Replay,
    /// The ask ran: its answers' proposal, none when no unit was answered,
    /// the units it left without an answer, as the first ask keeps them,
    /// and the rows its reads picked, which the proposal keeps (FIX 9312).
    Asked {
        proposal: Option<EditProposal>,
        units: Vec<crate::llm::decision::questions::ArtifactUnitReceipt>,
        read_rows: Vec<EntityId>,
    },
}

/// `wake`'s re-ask at `now` of the head versions it `read`, as its standing
/// question's ask log keeps it (FIX 9174): the withdrawn answers' proposal is
/// its parent, and `units` the units it left without an answer.
fn standing_reask<'a>(
    wake: &'a UnitWithdrawal,
    read: &'a [(EntityId, u64)],
    units: &'a [crate::llm::decision::questions::ArtifactUnitReceipt],
    now: u64,
) -> crate::llm::decision::questions::StandingReask<'a> {
    crate::llm::decision::questions::StandingReask {
        question: wake.question.id,
        question_version: wake.question.version,
        principal: wake.principal,
        artifact: wake.artifact,
        parent_proposal_ref: &wake.proposal_ref,
        versions: read,
        asked_at: now,
        units,
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
                "judged_live": answer.judged_live.as_ref().map(live::live_field),
                "changed_live": answer.changed_live.as_ref().map(live::live_field),
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
