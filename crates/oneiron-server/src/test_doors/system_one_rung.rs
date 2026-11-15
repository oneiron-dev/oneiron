//! Doors for `tests/systemone_pack_run_no_cancel.rs` (SYSTEMONE-PACK-RUN-NO-CANCEL):
//! the System One rung bound to a stub endpoint. Thin re-export of the
//! decision host's door. Compiled only under `--cfg oneiron_test_support`;
//! hidden, never API.

#[doc(hidden)]
pub use crate::decision_host::{SystemOneRungForTest, system_one_rung_for_test};
