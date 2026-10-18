//! A wait's receipts as the consent Gate ledger holds them (DOOR-079 PR 2).
//!
//! The control row keeps each receipt's id; the ledger keeps the receipt,
//! whose links name the wait, the owner's word, the receipt it follows and
//! the digest of the facts it closes. A read joins the two in one snapshot
//! and refuses a ledger record that disagrees with the row, never showing
//! one fact from each.

use crate::Vault;
use crate::consent::{CodeWaitReceiptLinks, ConsentReceipt};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::store::GateDecisionId;

use super::types::{CodeConsentSettleOutcome, CodeConsentWaitRow};

/// The links of one wait's settlement and consumption receipts, as the
/// ledger holds them. Either is `None` before its fact, or once an opted-in
/// retention sweep dropped its record (CALLS: receipt ledger join).
pub(super) struct LedgerLinks {
    pub(super) settled: Option<CodeWaitReceiptLinks>,
    pub(super) consumed: Option<CodeWaitReceiptLinks>,
}

/// Reads `row`'s receipts back from the ledger, in the reader's snapshot.
/// A settlement names the answer's word and act, when one was answered; a
/// consumption names the same word and the settlement it consumed.
///
/// # Errors
///
/// A record that is not the code wait receipt the row names, or whose links
/// name another wait, word or prior receipt ([`Error::CorruptedIndex`]), or
/// storage errors.
pub(super) fn ledger_links_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    row: &CodeConsentWaitRow,
) -> Result<LedgerLinks> {
    let wait_id = row.binding.wait_id;
    let word = row.answer.as_ref().map(|answer| answer.word_ref);
    let settled = match &row.settlement {
        Some(settled) => receipt_links_in_txn(vault, txn, settled.receipt, Some(settled.outcome))?
            .map(|links| {
                joined(
                    links,
                    wait_id,
                    word,
                    row.answer.as_ref().map(|answer| answer.decision),
                )
            })
            .transpose()?,
        None => None,
    };
    let consumed = match &row.consumption {
        Some(consumed) => receipt_links_in_txn(vault, txn, consumed.receipt, None)?
            .map(|links| joined(links, wait_id, word, Some(consumed.settlement_receipt)))
            .transpose()?,
        None => None,
    };
    Ok(LedgerLinks { settled, consumed })
}

/// The links of receipt `id`: a settlement with `outcome`, or a consumption
/// when `outcome` is `None`. `None` when the ledger holds no record by it.
fn receipt_links_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: GateDecisionId,
    outcome: Option<CodeConsentSettleOutcome>,
) -> Result<Option<CodeWaitReceiptLinks>> {
    let Some(record) = vault.store.gate_decision_in_txn(txn, id)? else {
        return Ok(None);
    };
    match (CodeWaitReceiptLinks::from_gate_record(&record), outcome) {
        (
            Some(ConsentReceipt::CodeWaitSettled {
                links,
                outcome: recorded,
                ..
            }),
            Some(outcome),
        ) if recorded == outcome => Ok(Some(links)),
        (Some(ConsentReceipt::CodeWaitConsumed { links, .. }), None) => Ok(Some(links)),
        _ => Err(Error::CorruptedIndex(
            "a code consent wait receipt is not the one its row names",
        )),
    }
}

/// `links`, once they name this wait, this word and this prior receipt.
fn joined(
    links: CodeWaitReceiptLinks,
    wait_id: EntityId,
    word: Option<EntityId>,
    prior: Option<GateDecisionId>,
) -> Result<CodeWaitReceiptLinks> {
    if links.wait_id != wait_id || links.word_ref != word || links.prior_receipt != prior {
        return Err(Error::CorruptedIndex(
            "a code consent wait receipt names another wait, word or prior receipt",
        ));
    }
    Ok(links)
}
