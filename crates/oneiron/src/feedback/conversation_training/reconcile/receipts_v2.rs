//! The intake's V2 receipts (C2, C3, C5), applied per scope: each scope
//! keeps its own cursor, and no scope's publisher sequence is compared with
//! another's. A receipt for a scope this vault never used is refused and
//! left where it is. The writer that applies the last `removed` receipt of
//! the purge (TL-5) stages the training link key's retirement; the pass
//! finishes it after the commit.

use oneiron_vault_contract::conversation_training::{
    TrainingReceiptBodyV2, TrainingReceiptStatusV2, TrainingReceiptSubjectV2,
};

use crate::Vault;
use crate::error::Result;

use super::super::crypto::{IntakeReceiptKey, receipt_verifies};
use super::super::custody::{
    self, ControlChange, ReceiptMark, UsedRun, put_control_in, put_submission_in,
};
use super::super::lifecycle::{
    PublisherTrainingLifecycle, ReceivedTrainingReceipt, TrainingControlId, TrainingScope,
    TrainingSubmissionId,
};
use super::TrainingUpkeep;

impl Vault {
    /// Applies the intake's receipts the key authenticates, each for one of
    /// this vault's scopes and past that scope's cursor, by scope and in
    /// publisher order within it, then removes their files. A receipt for a
    /// scope this vault never used, or not signed by the key, stays where it
    /// is and is named.
    pub(super) fn apply_training_receipts(
        &self,
        sink: &dyn PublisherTrainingLifecycle,
        key: &IntakeReceiptKey,
        upkeep: &mut TrainingUpkeep,
    ) -> Result<()> {
        let cursors = {
            let txn = self.store.env.read_txn()?;
            custody::state(self, &txn)?.cursors()
        };
        let page = sink.receipts(&cursors)?;
        for file in &page.stale {
            sink.retire_receipt(file)?;
        }
        let mut accepted: Vec<(TrainingScope, ReceivedTrainingReceipt)> = Vec::new();
        for received in page.receipts {
            let scope = cursors
                .iter()
                .find(|cursor| cursor.scope.to_hex() == received.receipt.body.scope)
                .map(|cursor| cursor.scope);
            match scope {
                Some(scope) if receipt_verifies(key, &received.receipt) => {
                    accepted.push((scope, received));
                }
                _ => upkeep.receipts_refused.push(received.file),
            }
        }
        if accepted.is_empty() {
            return Ok(());
        }
        accepted
            .sort_by_key(|(scope, received)| (*scope, received.receipt.body.publisher_sequence));
        self.with_write_txn_grouped(|txn| {
            for (_, received) in &accepted {
                apply_receipt_in(self, txn, &received.receipt.body)?;
            }
            Ok(())
        })?;
        for (_, received) in &accepted {
            sink.retire_receipt(&received.file)?;
        }
        upkeep.receipts_applied = accepted.len();
        Ok(())
    }
}

/// Applies one authenticated receipt in its scope: past that scope's
/// cursor, its subject's mark when the subject rides the same scope, and
/// each used run on the submissions it names (C3). A receipt for a scope
/// this vault never used applies nothing.
fn apply_receipt_in(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    body: &TrainingReceiptBodyV2,
) -> Result<()> {
    let mut state = custody::state(vault, txn)?;
    let link_generation = state.link_generation;
    let Some(entry) = state
        .months
        .iter_mut()
        .find(|entry| oneiron_vault_contract::hex(&entry.scope) == body.scope)
    else {
        return Ok(());
    };
    if body.publisher_sequence <= entry.receipt_cursor {
        return Ok(());
    }
    entry.receipt_cursor = body.publisher_sequence;
    let (month, generation) = (entry.month.clone(), entry.generation);
    custody::put_state_in(vault, txn, &state)?;
    let mark = ReceiptMark {
        status: body.status,
        attested: body.no_human_read.is_some(),
        sequence: body.publisher_sequence,
    };
    match &body.subject {
        TrainingReceiptSubjectV2::Submission(id) => {
            if let Some(id) = TrainingSubmissionId::from_hex(id)
                && let Some(mut row) = custody::submission(vault, txn, id)?
                && row.month == month
                && row.generation == generation
            {
                row.receipt = Some(mark);
                put_submission_in(vault, txn, id, &row)?;
            }
        }
        TrainingReceiptSubjectV2::Control(id) => {
            if let Some(id) = TrainingControlId::from_hex(id)
                && let Some(mut row) = custody::control(vault, txn, id)?
                && row.month == month
                && row.generation == generation
            {
                row.receipt = Some(mark);
                put_control_in(vault, txn, id, &row)?;
                if row.change == ControlChange::PurgeScope
                    && mark.status == TrainingReceiptStatusV2::Removed
                    && custody::purge_removed(vault, txn)?
                {
                    // TL-5: the last purge control is removed; the training
                    // link key may retire. Finished after this write commits.
                    vault
                        .store
                        .stage_training_link_retirement_in_txn(txn, link_generation)?;
                }
            }
        }
    }
    record_used_runs_in(vault, txn, body)
}

/// Each run a receipt names, appended to the submissions it used (C3).
fn record_used_runs_in(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    body: &TrainingReceiptBodyV2,
) -> Result<()> {
    for run in &body.used_runs {
        for submission in &run.submissions {
            let Some(id) = TrainingSubmissionId::from_hex(submission) else {
                continue;
            };
            let Some(mut row) = custody::submission(vault, txn, id)? else {
                continue;
            };
            if row.used_runs.iter().any(|used| used.run_id == run.run_id) {
                continue;
            }
            row.used_runs.push(UsedRun {
                run_id: run.run_id.clone(),
                model: run.model.clone(),
                used_at: run.used_at,
            });
            put_submission_in(vault, txn, id, &row)?;
        }
    }
    Ok(())
}
