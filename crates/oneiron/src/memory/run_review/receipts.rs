//! FIX 4727: each reviewed run's settlement projects into `vault.receipts`
//! as the common `ProposalOutcome` kind, one receipt per settled change. Its
//! time and actor are the owner decision the settlement recorded.
//!
//! Each change's receipt names that change's own row as its trigger, so the
//! credential and off-device screens judge every member on its own row: a
//! reader sees the outcome of each change it may read, and nothing of the
//! others, not even how many there are.
use std::collections::BTreeMap;

use super::{RunChangeVerdict, SETTLEMENTS};
use crate::receipt::{ReceiptKind, ReceiptQuery, ReceiptRecord};
use crate::store::GateDecisionId;
use crate::{EntityId, Result, Vault};

/// The run the settlement answers, as `run:<job id>`.
const FIELD_RUN_REF: &str = "run_ref";
/// The handle `vault.runs.revert` takes for the run.
const FIELD_REVERT_HANDLE: &str = "revert_handle";
/// The owner decision the settlement recorded, as `gate:<id>`.
const FIELD_DECISION_REF: &str = "decision_ref";
/// The settled change, as the review named it.
const FIELD_CHANGE_REF: &str = "change_ref";

/// Every run settlement change the query matches, read in its own
/// transaction. A settlement whose owner decision no longer reads names no
/// time or actor, and projects nothing.
///
/// # Errors
/// A store failure.
pub(crate) fn run_settlement_receipts(
    vault: &Vault,
    query: &ReceiptQuery,
) -> Result<Vec<ReceiptRecord>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut count = crate::scan_check::ScanCount::start(
        &vault.store,
        &rtxn,
        crate::scan_check::EngineScan::ReceiptSourceRows,
        b"run_review_settlement",
    )?;
    let mut out = Vec::new();
    for (run, stored) in SETTLEMENTS.scan(&vault.store, &rtxn)? {
        count.row();
        let settlement = &stored.settlement;
        let Some(decision) = settlement
            .receipt
            .strip_prefix("gate:")
            .and_then(|hex| EntityId::from_hex(hex).ok())
            .map(|id| GateDecisionId::from_bytes(*id.as_bytes()))
        else {
            continue;
        };
        let Some(record) = vault.store.gate_decision_in_txn(&rtxn, decision)? else {
            continue;
        };
        for (index, change) in stored.changes.iter().enumerate() {
            // A change that names no row (an external effect) keeps its
            // owner decision as its trigger, which no credential reads.
            let trigger = change
                .member
                .rows()
                .ok()
                .and_then(|rows| rows.first().copied())
                .map_or_else(
                    || settlement.receipt.clone(),
                    |row| format!("run_change:{}", row.to_hex()),
                );
            let fields = BTreeMap::from([
                (FIELD_RUN_REF.to_owned(), format!("run:{run}")),
                (FIELD_DECISION_REF.to_owned(), settlement.receipt.clone()),
                (
                    FIELD_REVERT_HANDLE.to_owned(),
                    settlement.revert_handle.clone(),
                ),
                (
                    FIELD_CHANGE_REF.to_owned(),
                    change.member.change().to_owned(),
                ),
            ]);
            let receipt = ReceiptRecord {
                receipt_id: format!("proposal_outcome:run:{run}:{index}"),
                receipt_kind: ReceiptKind::ProposalOutcome,
                occurred_at: record.created_at,
                actor: record.actor_ref.clone(),
                on_behalf_of: None,
                outcome: verdict_word(change.verdict).to_owned(),
                job_ref: Some(run.clone()),
                trigger_ref: Some(trigger),
                policy_trace: Vec::new(),
                fields,
            };
            if query.matches(&receipt) {
                out.push(receipt);
            }
        }
    }
    count.finish(vault);
    Ok(out)
}

/// A change's verdict as its wire word.
const fn verdict_word(verdict: RunChangeVerdict) -> &'static str {
    match verdict {
        RunChangeVerdict::Landed => "landed",
        RunChangeVerdict::Rejected => "rejected",
        RunChangeVerdict::Waiting => "waiting",
        RunChangeVerdict::LetGo => "let_go",
    }
}
