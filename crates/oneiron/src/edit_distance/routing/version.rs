//! The executor serving now.

use super::keys::{DRAFTING_ROLE, ROW_VERSION, SERVING_MODEL, ServingExecutor, StoredExecutor};
use crate::Vault;
use crate::error::Result;
use crate::llm::ModelId;

// ---------------------------------------------------------------------------
// The serving executor
// ---------------------------------------------------------------------------

/// The executor identity at revision serving now: the declared model, else
/// the drafting role's compiled default.
///
/// No fold reads this. A receipt folds under the executor its own judgment was
/// stamped with when the drafting run began (FIX 9812); this answers a caller
/// asking what serves now, which says nothing about history.
///
/// # Errors
///
/// Storage errors; [`Error::CorruptedIndex`](crate::Error::CorruptedIndex) on an undecodable row.
pub fn serving_model_version(vault: &Vault) -> Result<String> {
    let rtxn = vault.store.env.read_txn()?;
    Ok(SERVING_MODEL.get(&vault.store, &rtxn, &())?.map_or_else(
        || DRAFTING_ROLE.default_model_id().as_str().to_owned(),
        |row| row.0.executor,
    ))
}

/// Declares which model is serving.
///
/// Folded runs are untouched by design, and so are runs folded later: each
/// folds under the executor stamped on its own receipt, and a swap is not new
/// information about any of them.
///
/// # Errors
///
/// Storage errors.
pub fn set_serving_model(vault: &Vault, model: &ModelId) -> Result<()> {
    let row = ServingExecutor(StoredExecutor {
        v: ROW_VERSION,
        executor: model.as_str().to_owned(),
        outcome: None,
        head: None,
    });
    vault.with_write_txn_grouped(|wtxn| SERVING_MODEL.put(&vault.store, wtxn, &(), &row))
}
