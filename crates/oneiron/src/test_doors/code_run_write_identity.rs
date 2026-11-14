//! Doors for `tests/write_receipt_float_input.rs` (census L1-06): whether a
//! resumed write meets the receipt row its first making recorded.
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
