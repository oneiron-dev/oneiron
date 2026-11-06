//! Completed typed sheet decisions kept before workbook staging can fail.

use serde::{Deserialize, Serialize};
use std::time::Instant;

use super::SettleConsent;
use super::codec::{RECORD, settlement_key_parts};
use super::pending::{PENDING, validate_pending_ref};
use super::receipts::already_settled;
use crate::Vault;
use crate::edit_roundtrip::{
    ArtifactAsk, ArtifactAskRun, FolderItem, RangeRef, SheetAnswerBundle, UnitAbstention,
    UnitRefusal,
};
use crate::entity_id::EntityId;
use crate::error::{ArtifactError, Error, Result};
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
pub(crate) struct DecidedSheetAnswers {
    pub(crate) request: DecidedSheetRequest,
    pub(crate) bundle: SheetAnswerBundle,
    pub(crate) version: u64,
    pub(crate) frontier: [u8; 32],
    pub(crate) read_rows: Vec<EntityId>,
    pub(crate) abstained: Vec<UnitAbstention>,
    pub(crate) refused: Vec<UnitRefusal>,
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

    /// Never overwrite the first completed answers under a run ref. Racing
    /// initial asks are not single-flight; the committed original wins.
    pub(crate) fn retain_decided_sheet_answers(
        &self,
        artifact: &EntityId,
        row: DecidedSheetAnswers,
    ) -> Result<DecidedSheetAnswers> {
        validate_pending_ref(&row.request.run_ref)?;
        let key = settlement_key_parts(artifact, &row.request.run_ref);
        self.with_write_txn_grouped(|txn| {
            check_available(&self.store, txn, artifact, &row.request.run_ref)?;
            if super::artifact_retention_deleted_in_txn(&self.store, txn, artifact)? {
                return Err(Error::EntityNotFound);
            }
            if let Some(existing) = DECIDED.get(&self.store, txn, &key)? {
                existing.matches(&row.request, row.unmasked)?;
                return Ok(existing);
            }
            DECIDED.put(&self.store, txn, &key, &row)?;
            Ok(row)
        })
    }

    pub(crate) fn stage_decided_sheet_answers(
        &self,
        artifact: &EntityId,
        row: &DecidedSheetAnswers,
        deadline: Instant,
    ) -> Result<ArtifactAskRun> {
        Ok(ArtifactAskRun {
            proposal: self.stage_sheet_answers(
                artifact,
                row.bundle.clone(),
                &row.request.run_ref,
                row.version,
                row.frontier,
                Some(deadline),
            )?,
            abstained: row.abstained.clone(),
            refused: row.refused.clone(),
            read_rows: row.read_rows.clone(),
        })
    }

    /// Release completed answers that have not become a held proposal.
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
    fn matches(&self, request: &DecidedSheetRequest, unmasked: bool) -> Result<()> {
        if &self.request != request || (self.unmasked && !unmasked) {
            return Err(Error::Artifact(ArtifactError::InvalidEditManifest(
                "completed answers under this ref belong to a different ask or visibility",
            )));
        }
        Ok(())
    }
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
