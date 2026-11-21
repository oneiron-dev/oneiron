//! The amendment rows a Gate decision's receipt keeps, dropped where the
//! decision's content goes (FIX [GATE-RECEIPT-ATTRIBUTION-ROWS-OUTLIVE-SKELETON]).
//!
//! An amended approval's receipt `gate:<hex>` keys its Δ and every row
//! judged from it: the routing facts (who was amended, on which skill and
//! attempt), the judgment with its share split, the preference note, the
//! edit proposal the judgment minted, and the write-once cause rows with
//! their attempt index entries. The decision's retention skeleton keeps the
//! receipt id and its `approved_amended` outcome, so a row left behind would
//! still be attached to the redacted receipt and say who the skeleton no
//! longer names. No measurement, no judgment: with the Δ gone, the judgment
//! would charge by itself (`judge_amendment_hunks` withdraws one whose Δ is
//! missing).
//!
//! What the judgment held up follows on the projection passes, which
//! recompute from the judgment ledger: the edit-cost target rows stay as the
//! record of the cells and lessons the next `project_edit_cost_claims` or
//! `project_amendment_lessons` pass retracts, and `project_amendment_reliability`
//! withdraws the amended outcome, as after a withdrawal.
//!
//! The receipt's unclear row is not dropped here: withdrawing it takes a note
//! waiting in a label proposal with it, which needs the vault's custody
//! write, and these writers hold only the store. An erase of the claim drops
//! it, notes and the proposals that copied them included, through its
//! derived-row eraser, because its context names the measured claim as a
//! source (FIX 7824). The writers that erase no claim withdraw it themselves:
//! the retention sweep and a restore's drop through their custody write
//! (`skill_attribution::delete_gate_receipt_unclear_in_txn`; a proposal a hold
//! keeps stays), and the owner's discard of a world copy, which is local,
//! without touching the proposals (`release_gate_receipt_unclear_in_txn`).

use heed::RwTxn;

use super::stored::{EVIDENCE, JUDGMENT, PREFERENCE};
use crate::edit_distance::delta::forget_gate_amendment_delta_in_txn;
use crate::error::Result;
use crate::store::skill_attribution_judgments::EDIT_PROPOSAL;
use crate::store::{GateDecisionId, Store};

/// Drops the Δ recorded for the Gate decision `decision`'s receipt and the
/// amendment attribution judged from it. The ledger calls it wherever the
/// decision's content goes: its retention skeleton (an erase, a delete, a
/// discard, a held scrub's settle, a restore's rerun), a restore's drop of a
/// row an erase retired, and the row's removal. A judgment row that does not
/// decode goes too, without the edit proposal it named.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn forget_gate_amendment_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    decision: GateDecisionId,
) -> Result<()> {
    forget_gate_amendment_delta_in_txn(store, wtxn, decision)?;
    let receipt = format!("gate:{}", decision.to_hex());
    if let Some(sequence) = JUDGMENT
        .get_lenient(store, &*wtxn, &receipt)?
        .and_then(|row| row.proposal)
    {
        EDIT_PROPOSAL.delete(store, wtxn, &sequence)?;
    }
    JUDGMENT.delete(store, wtxn, &receipt)?;
    PREFERENCE.delete(store, wtxn, &receipt)?;
    EVIDENCE.delete(store, wtxn, &receipt)?;
    super::causes::forget_amendment_causes_in_txn(store, wtxn, &receipt)
}
