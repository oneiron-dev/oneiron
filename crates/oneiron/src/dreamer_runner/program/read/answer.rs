//! A program write step's kept answer (FIX 5837): the rows its receipt says
//! the answer was served from, and the verb's JSON output the receipt keeps,
//! read from the receipt, never from the step (whose own result is none) and
//! never by running the call again.

use base64::Engine as _;

use crate::Vault;
use crate::code_run::agent_verb_rows_of;
use crate::entity_id::EntityId;
use crate::error::Result;

/// What a write step's receipt keeps as its answer.
pub(super) enum ReceiptAnswer {
    /// No receipt, or one that holds no answer.
    Absent,
    /// An answer that does not list the rows it was served from.
    Unlisted,
    /// An answer and the rows it was served from, with the verb's JSON output
    /// when the receipt keeps one.
    Rows {
        rows: Vec<EntityId>,
        output: Option<serde_json::Value>,
    },
}

/// The answer the receipt `receipt` keeps as its first row, in `txn`. An
/// output that does not decode leaves the answer without one: it never
/// fails the read.
pub(super) fn receipt_answer_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    receipt: &EntityId,
) -> Result<ReceiptAnswer> {
    let Some(record) = vault.get_code_run_replay_record_in_txn(txn, receipt)? else {
        return Ok(ReceiptAnswer::Absent);
    };
    let Some(first) = record.bridge_calls.first() else {
        return Ok(ReceiptAnswer::Absent);
    };
    let Some(rows) = agent_verb_rows_of(std::slice::from_ref(first)) else {
        return Ok(ReceiptAnswer::Unlisted);
    };
    let output = first.program_stored_answer().ok().flatten();
    Ok(ReceiptAnswer::Rows { rows, output })
}

/// A write's kept output as its step's body: its JSON bytes, base64. The
/// step's `result_digest` stays the digest of the receipt's stored outcome,
/// not of these bytes.
pub(super) fn answer_body_base64(output: &serde_json::Value) -> Option<String> {
    let bytes = serde_json::to_vec(output).ok()?;
    Some(base64::engine::general_purpose::STANDARD.encode(bytes))
}
