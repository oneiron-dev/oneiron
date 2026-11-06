//! Original mutation requests; placement is optional and never minted on replay.

use crate::{EntityId, Result, Vault};

use super::codec::invalid;
use super::ledger::{DISPLACED, DisplacedMark, OutcomeRef, OutcomeRow};
use super::outcome_position::{OutcomePlacement, OutcomeReadPosition};
use super::outcome_row::{LedgerOutcomeRow, OriginalOutcomeRow};

pub(crate) fn record_outcome_positioned_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    skill: &EntityId,
    executor: Option<&str>,
    receipt_ref: &str,
    win: bool,
    at: u64,
    read_position: Option<&OutcomeReadPosition>,
) -> Result<()> {
    if receipt_ref.is_empty() {
        return Err(invalid("a reliability outcome must cite a receipt"));
    }
    let model = executor.ok_or(invalid("a skill outcome requires its executor revision"))?;
    super::read::validate_executor(model)?;
    let receipt = crate::receipt::attempt_pack_receipt_in_txn(&vault.store, wtxn, receipt_ref)?
        .ok_or(invalid("a skill outcome requires a terminal pack receipt"))?;
    super::projector::receipt_query(&receipt)?;
    let key = OutcomeRef::new(skill, executor, receipt_ref);
    // The original win branch reads fatally; the formerly unconditional loss
    // put must not gain a new fatal lookup or mistake an error for birth.
    let held = if win {
        Some(key.get(vault, wtxn)?)
    } else {
        key.get(vault, wtxn).ok()
    };
    if win
        && let Some(Some(existing)) = &held
        && !existing.win
    {
        return Ok(());
    }
    let placement = match held {
        Some(None) => OutcomePlacement::birth(vault, read_position),
        Some(Some(LedgerOutcomeRow::Original(held))) => held
            .placement
            .retained(held.outcome.win == win && held.outcome.at == at),
        Some(Some(LedgerOutcomeRow::Rule { native, .. })) => OutcomePlacement {
            row_id: native.and_then(|row| row.row_id),
            read_position: None,
        },
        None => OutcomePlacement::unknown(),
    };
    key.put(
        vault,
        wtxn,
        &LedgerOutcomeRow::Original(OriginalOutcomeRow {
            outcome: OutcomeRow { win, at },
            placement,
        }),
    )
}

pub(crate) fn mark_displaced_outcome_positioned_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    skill: &EntityId,
    executor: Option<&str>,
    receipt: &str,
    old: &str,
    replacement: &str,
    read_position: Option<&OutcomeReadPosition>,
) -> Result<bool> {
    let outcome = OutcomeRef::new(skill, executor, receipt);
    let existed = outcome.contains(vault, txn)?;
    let placement = match DISPLACED.get(&vault.store, txn, &outcome) {
        Ok(None) => OutcomePlacement::birth(vault, read_position),
        Ok(Some(held)) => held
            .placement
            .retained(held.displaced == old && held.replacement == replacement),
        Err(_) => OutcomePlacement::unknown(),
    };
    let mark = DisplacedMark {
        displaced: old.to_owned(),
        replacement: replacement.to_owned(),
        placement,
    };
    DISPLACED.put(&vault.store, txn, &outcome, &mark)?;
    Ok(existed)
}
