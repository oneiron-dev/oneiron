//! The finalized-run writer needed by `tests/retrieval_policy_default_floor.rs`
//! and `tests/read_shape_bandit_per_model.rs`.
//! Compiled only under `--cfg oneiron_test_support`; never API.

use crate::store::RetrievalRunRecord;
use crate::{Result, Vault};

/// Publishes a fixture run through the ordinary telemetry writer.
pub fn record_retrieval_run(vault: &Vault, record: &RetrievalRunRecord) -> Result<()> {
    vault.store.record_retrieval_run(record)
}
