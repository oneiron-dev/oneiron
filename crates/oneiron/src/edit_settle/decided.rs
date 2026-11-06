//! Typed sheet decisions and their original inputs kept between paid units.

mod encoding;

pub(crate) use encoding::ExpectedAnswers as DecidedSheetExpected;

use serde::{Deserialize, Serialize};
use std::time::Instant;

use super::SettleConsent;
use super::codec::{RECORD, settlement_key_parts};
use super::pending::{PENDING, validate_pending_ref};
use super::receipts::already_settled;
use crate::Vault;
use crate::edit_roundtrip::{
    ArtifactAsk, ArtifactAskRun, CellRef, CellValue, FolderItem, RangeRef, SheetAnswerBundle,
    UnitAbstention, UnitRefusal,
};
use crate::entity_id::EntityId;
use crate::error::{ArtifactError, Error, Result};
use crate::llm::decision::{EvidenceVersion, TypedDecision};
use crate::model_decision::{DecisionQuestion, Reversibility};
use crate::side_table::{self, Named, SideTable};
use crate::write_envelope::WriteActor;

const DECIDED: SideTable<(EntityId, [u8; 32]), DecidedSheetAnswers, Named> =
    SideTable::new(&side_table::EDIT_SETTLE_DECIDED_SHEET_ANSWERS);

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DecidedSheetRequest {
    run_ref: String,
    question: DecisionQuestion,
    principal: EntityId,
    reversibility: Reversibility,
    evidence: Vec<EntityId>,
    shape: DecidedSheetShape,
}

impl DecidedSheetRequest {
    pub(crate) fn new(ask: &ArtifactAsk<'_>, shape: DecidedSheetShape) -> Self {
        Self {
            run_ref: ask.run_ref.to_owned(),
            question: ask.question.clone(),
            principal: ask.principal,
            reversibility: ask.reversibility,
            evidence: ask.evidence.to_vec(),
            shape,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum DecidedSheetShape {
    SheetRows {
        sheet: String,
        rows: RangeRef,
        answer_col: u32,
        header_row: Option<u32>,
        max_count_override: Option<u64>,
        only_rows: Option<Vec<u32>>,
    },
    FolderItems {
        sheet: String,
        items: Vec<FolderItem>,
        answer_col: u32,
        max_count_override: Option<u64>,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DecidedSheetRow {
    pub(crate) cell: CellRef,
    pub(crate) before: CellValue,
    pub(crate) read: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum DecidedSheetInputs {
    SheetRows {
        headers: serde_json::Map<String, serde_json::Value>,
        rows: Vec<DecidedSheetRow>,
    },
    FolderItems {
        before: Vec<CellValue>,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DecidedSheetUnitDecision {
    pub(crate) decision: TypedDecision,
    pub(crate) source: Option<EvidenceVersion>,
    pub(crate) version: u64,
    pub(crate) live: Option<crate::office_body::LivePin>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DecidedSheetProgress {
    pub(crate) next: usize,
    pub(crate) inputs: DecidedSheetInputs,
    /// The validated result for `next`, before cell conversion and outcome commit.
    pub(crate) decision: Option<DecidedSheetUnitDecision>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DecidedSheetAnswers {
    pub(crate) request: DecidedSheetRequest,
    pub(crate) generation: EntityId,
    pub(crate) bundle: SheetAnswerBundle,
    pub(crate) version: u64,
    pub(crate) frontier: [u8; 32],
    pub(crate) read_rows: Vec<EntityId>,
    pub(crate) abstained: Vec<UnitAbstention>,
    pub(crate) refused: Vec<UnitRefusal>,
    /// None only after every selected unit has a committed outcome.
    pub(crate) progress: Option<DecidedSheetProgress>,
    /// Folder decisions made from stored secret spans cannot be resumed by
    /// a caller now reading only masked spans. This is not a grant receipt.
    pub(crate) unmasked: bool,
}

impl Vault {
    pub(crate) fn decided_sheet_answers(
        &self,
        artifact: &EntityId,
        request: &DecidedSheetRequest,
        unmasked: bool,
    ) -> Result<Option<DecidedSheetAnswers>> {
        validate_pending_ref(&request.run_ref)?;
        let txn = self.store.env.read_txn()?;
        check_available(&self.store, &txn, artifact, &request.run_ref)?;
        let key = settlement_key_parts(artifact, &request.run_ref);
        let row = DECIDED.get(&self.store, &txn, &key)?;
        if let Some(row) = &row {
            row.matches(request, unmasked)?;
        }
        Ok(row)
    }

    /// The facade checks these original version rows through its current
    /// credential before restaging; the principal alone is not read authority.
    pub(crate) fn decided_sheet_answer_read_rows(
        &self,
        artifact: &EntityId,
        run_ref: &str,
        principal: EntityId,
    ) -> Result<Vec<EntityId>> {
        let txn = self.store.env.read_txn()?;
        let key = settlement_key_parts(artifact, run_ref);
        let Some(row) = DECIDED.get(&self.store, &txn, &key)? else {
            return Ok(Vec::new());
        };
        if row.request.run_ref != run_ref || row.request.principal != principal {
            return Err(Error::EntityNotFound);
        }
        Ok(row.read_rows)
    }

    /// The first prepared read basis wins, before any paid unit is called.
    /// Racing initial asks are not single-flight.
    pub(crate) fn retain_decided_sheet_answers(
        &self,
        artifact: &EntityId,
        row: DecidedSheetAnswers,
        deadline: Instant,
    ) -> Result<DecidedSheetAnswers> {
        validate_pending_ref(&row.request.run_ref)?;
        let key = settlement_key_parts(artifact, &row.request.run_ref);
        {
            let txn = self.store.env.read_txn()?;
            check_available(&self.store, &txn, artifact, &row.request.run_ref)?;
            if super::artifact_retention_deleted_in_txn(&self.store, &txn, artifact)? {
                return Err(Error::EntityNotFound);
            }
            if let Some(existing) = DECIDED.get(&self.store, &txn, &key)? {
                existing.matches(&row.request, row.unmasked)?;
                return Ok(existing);
            }
        }
        let encoded = encoding::EncodedAnswers::new(&key, &row, deadline)?;
        self.with_write_txn_grouped(|txn| {
            check_available(&self.store, txn, artifact, &row.request.run_ref)?;
            if super::artifact_retention_deleted_in_txn(&self.store, txn, artifact)? {
                return Err(Error::EntityNotFound);
            }
            if let Some(existing) = DECIDED.get(&self.store, txn, &key)? {
                existing.matches(&row.request, row.unmasked)?;
                return Ok(existing);
            }
            encoded.put(&self.store, txn)?;
            Ok(row)
        })
    }

    /// Commit only a continuation of the exact canonical prefix it read.
    /// A racing writer follows the committed row instead of replacing it.
    pub(crate) fn advance_decided_sheet_answers(
        &self,
        artifact: &EntityId,
        expected: &DecidedSheetExpected,
        row: DecidedSheetAnswers,
        deadline: Instant,
    ) -> Result<DecidedSheetAnswers> {
        let decoded_expected = expected.decode()?;
        let key = settlement_key_parts(artifact, &row.request.run_ref);
        {
            let txn = self.store.env.read_txn()?;
            check_available(&self.store, &txn, artifact, &row.request.run_ref)?;
            if super::artifact_retention_deleted_in_txn(&self.store, &txn, artifact)? {
                return Err(Error::EntityNotFound);
            }
            if let Some(existing) =
                competing_answers(&self.store, &txn, &key, expected, &decoded_expected, &row)?
            {
                return Ok(existing);
            }
        }
        let encoded = encoding::EncodedAnswers::new(&key, &row, deadline)?;
        self.with_write_txn_grouped(|txn| {
            check_available(&self.store, txn, artifact, &row.request.run_ref)?;
            if super::artifact_retention_deleted_in_txn(&self.store, txn, artifact)? {
                return Err(Error::EntityNotFound);
            }
            if let Some(existing) =
                competing_answers(&self.store, txn, &key, expected, &decoded_expected, &row)?
            {
                return Ok(existing);
            }
            encoded.put(&self.store, txn)?;
            Ok(row)
        })
    }

    pub(crate) fn stage_decided_sheet_answers(
        &self,
        artifact: &EntityId,
        row: DecidedSheetAnswers,
        deadline: Instant,
    ) -> Result<ArtifactAskRun> {
        if row.progress.is_some() {
            return Err(Error::Artifact(ArtifactError::InvalidEditManifest(
                "typed sheet answers are not complete",
            )));
        }
        Ok(ArtifactAskRun {
            proposal: self.stage_sheet_answers(
                artifact,
                row.bundle,
                &row.request.run_ref,
                row.version,
                row.frontier,
                Some(deadline),
            )?,
            abstained: row.abstained,
            refused: row.refused,
            read_rows: row.read_rows,
        })
    }

    /// Release partial or completed answers that have not become a held proposal.
    /// Uses the same actor and consent as Discard, but creates no fabricated
    /// proposal or settlement receipt and does not consume the run ref.
    pub fn release_decided_sheet_answers(
        &self,
        artifact: &EntityId,
        run_ref: &str,
        consent: &SettleConsent,
        actor: WriteActor,
    ) -> Result<bool> {
        validate_pending_ref(run_ref)?;
        self.authorize_settle(consent, actor)?;
        self.with_write_txn_grouped(|txn| {
            self.authorize_settle_in_txn(txn, consent, actor)?;
            DECIDED.delete(&self.store, txn, &settlement_key_parts(artifact, run_ref))
        })
    }
}

impl DecidedSheetAnswers {
    pub(crate) fn expected(&self, deadline: Instant) -> Result<DecidedSheetExpected> {
        DecidedSheetExpected::new(self, deadline)
    }

    fn matches(&self, request: &DecidedSheetRequest, unmasked: bool) -> Result<()> {
        if &self.request != request || (self.unmasked && !unmasked) {
            return Err(Error::Artifact(ArtifactError::InvalidEditManifest(
                "completed answers under this ref belong to a different ask or visibility",
            )));
        }
        Ok(())
    }
}

fn competing_answers(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    key: &(EntityId, [u8; 32]),
    encoded_expected: &DecidedSheetExpected,
    expected: &DecidedSheetAnswers,
    proposed: &DecidedSheetAnswers,
) -> Result<Option<DecidedSheetAnswers>> {
    let bytes = DECIDED
        .get_borrowed(store, txn, key)?
        .ok_or(Error::EntityNotFound)?;
    // Identical bytes already passed this codec outside the transaction.
    // Non-reflexive values (NaN) must keep the original typed comparison.
    if encoded_expected.matches_encoded(&bytes) && expected.eq(expected) {
        expected.matches(&proposed.request, proposed.unmasked)?;
        return Ok(None);
    }
    let existing = DECIDED.decode_value(&bytes)?;
    existing.matches(&proposed.request, proposed.unmasked)?;
    if existing.generation != expected.generation {
        return Err(Error::EntityNotFound);
    }
    if &existing != expected {
        return Ok(Some(existing));
    }
    Ok(None)
}

fn check_available(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    artifact: &EntityId,
    run_ref: &str,
) -> Result<()> {
    let key = settlement_key_parts(artifact, run_ref);
    if let Some(existing) = RECORD.get(store, txn, &key)? {
        return Err(already_settled(&existing));
    }
    if PENDING.contains(store, txn, &key)? {
        return Err(Error::Artifact(ArtifactError::InvalidEditManifest(
            "a proposal already waits under this ref",
        )));
    }
    Ok(())
}

pub(super) fn drop_in_txn(
    store: &crate::store::Store,
    txn: &mut heed::RwTxn<'_>,
    key: &(EntityId, [u8; 32]),
) -> Result<()> {
    DECIDED.delete(store, txn, key).map(|_| ())
}

pub(super) fn purge_artifact_in_txn(
    store: &crate::store::Store,
    txn: &mut heed::RwTxn<'_>,
    artifact: &EntityId,
) -> Result<()> {
    for key in DECIDED.scan_keys(store, txn, artifact.as_bytes())? {
        DECIDED.delete(store, txn, &key)?;
    }
    Ok(())
}
