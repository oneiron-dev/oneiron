//! Canonical runtime-file occurrences before their bodies finish.

use crate::code_run::storage::response_erase::response_erased_in_txn;
use crate::provenance::body::{owned_body_in_txn, publish_body_in_txn};
use crate::store::body_descriptor::{BodyState, OwnedBody};
use crate::store::result_manifest::{
    CODE_RUN_REPLAY_MAX_OUTPUT_PATH_BYTES, ResultOccurrence, validate_text,
};
use crate::{EntityId, Result, Vault};

impl Vault {
    /// Records the unfinished occurrence before a runtime file's first frame.
    /// Existing occurrences and erased owners remain unchanged.
    pub(crate) fn begin_code_run_output(&self, owner: EntityId, path: &str) -> Result<()> {
        validate_text(
            path,
            CODE_RUN_REPLAY_MAX_OUTPUT_PATH_BYTES,
            "raw output path",
        )?;
        let occurrence = ResultOccurrence::owned(owner, path)?.id();
        self.with_write_txn_grouped(|txn| {
            if response_erased_in_txn(&self.store, txn, &owner)?
                || owned_body_in_txn(&self.store, txn, &owner, &occurrence)?.is_some()
            {
                return Ok(());
            }
            publish_body_in_txn(
                &self.store,
                txn,
                &OwnedBody {
                    owner,
                    occurrence,
                    state: BodyState::Incomplete { retained: None },
                    result: None,
                },
            )
        })
    }
}
