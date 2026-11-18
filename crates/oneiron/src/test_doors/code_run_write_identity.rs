//! Doors for `tests/write_receipt_float_input.rs` (census L1-06) and
//! `tests/write_receipt_held_input.rs` (FIX RECEIPT-RECORDS-CALL-HELD-INPUT):
//! whether a resumed write meets the receipt row its first making recorded.
//! Compiled only under `--cfg oneiron_test_support`; never API.

use crate::code_run::SelfAgentVerbCall;
use crate::error::Result;

/// Records `first` as the bridge records a verb write, then answers whether
/// `again`, the step's write made again after a resume, meets that row: the
/// row's input is read back from the JSON text the receipt keeps and its
/// identity compared with `again`'s live input.
///
/// # Errors
///
/// A call the bridge cannot record.
pub fn resumed_write_meets_its_receipt(
    first: &SelfAgentVerbCall,
    again: &SelfAgentVerbCall,
) -> Result<bool> {
    crate::code_run::resumed_write_meets_recorded_row(first, again)
}

/// How a resumed write met its receipt as the vault stores it (FIX
/// RECEIPT-RECORDS-CALL-HELD-INPUT).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredReceiptMeet {
    /// The compare a resumed write makes with its receipt
    /// (`kept_write_answer`): `false` fails the step with "a resumed step
    /// changed a write it already made".
    pub write_meets: bool,
    /// The compare a step's close makes with each receipt it holds
    /// (`refuse_a_step_that_dropped_a_write`): `false` fails the close with
    /// "a resumed step left out a write it already made".
    pub close_meets: bool,
    /// The input text the stored receipt row kept, after the side-row wall.
    pub kept_input: String,
}

/// Records `first` as the bridge records a verb write, stores that row as
/// its receipt through `vault` (the side-row wall admits it there) and reads
/// it back, then answers how `again`, the step's write made again after a
/// resume, meets the stored row.
///
/// # Errors
///
/// A call the bridge cannot record, or a receipt the vault cannot store or
/// read back.
pub fn resumed_write_meets_its_stored_receipt(
    vault: &crate::Vault,
    first: &SelfAgentVerbCall,
    again: &SelfAgentVerbCall,
) -> Result<StoredReceiptMeet> {
    let (write_meets, close_meets, kept_input) =
        crate::code_run::resumed_write_meets_stored_receipt(vault, first, again)?;
    Ok(StoredReceiptMeet {
        write_meets,
        close_meets,
        kept_input,
    })
}
