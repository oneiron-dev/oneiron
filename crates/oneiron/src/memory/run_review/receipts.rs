//! FIX 4727: each reviewed run's settlement projects into `vault.receipts`
//! as the common `ProposalOutcome` kind. Its time and actor are the owner
//! decision the settlement recorded; its fields are the settlement's own.
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
/// How many changes the settlement names, and how many of them landed.
const FIELD_CHANGE_COUNT: &str = "change_count";
const FIELD_LANDED_COUNT: &str = "landed_count";

/// Every run settlement the query matches, read in its own transaction.
/// A settlement whose owner decision no longer reads names no time or
/// actor, and projects nothing.
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
        let landed = settlement
            .changes
            .iter()
            .filter(|change| change.verdict == RunChangeVerdict::Landed)
            .count();
        // A credential-bound reader sees the settlement through a row it
        // settles: the first member that names one. A settlement of external
        // effects alone keeps its owner decision, which no credential reads.
        let trigger = stored
            .changes
            .iter()
            .find_map(|change| change.member.rows().ok()?.first().copied())
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
                FIELD_CHANGE_COUNT.to_owned(),
                settlement.changes.len().to_string(),
            ),
            (FIELD_LANDED_COUNT.to_owned(), landed.to_string()),
        ]);
        let receipt = ReceiptRecord {
            receipt_id: format!("proposal_outcome:run:{run}"),
            receipt_kind: ReceiptKind::ProposalOutcome,
            occurred_at: record.created_at,
            actor: record.actor_ref.clone(),
            on_behalf_of: None,
            outcome: verdict_word(settlement.verdict).to_owned(),
            job_ref: Some(run.clone()),
            trigger_ref: Some(trigger),
            policy_trace: Vec::new(),
            fields,
        };
        if query.matches(&receipt) {
            out.push(receipt);
        }
    }
    count.finish(vault);
    Ok(out)
}

/// The settlement's verdict as its wire word.
const fn verdict_word(verdict: RunChangeVerdict) -> &'static str {
    match verdict {
        RunChangeVerdict::Landed => "landed",
        RunChangeVerdict::Rejected => "rejected",
        RunChangeVerdict::Waiting => "waiting",
        RunChangeVerdict::LetGo => "let_go",
    }
}
