//! The extraction attempt's recorded claim outputs, without changing its state.

use crate::{AttemptId, EntityId, Result, Vault};

/// Reads the promotion output list exactly as the nightly reader does.
///
/// # Errors
///
/// The vault's storage errors.
pub fn recorded_outputs(vault: &Vault, attempt: AttemptId) -> Result<Vec<EntityId>> {
    crate::dreamer_consolidation::nightly_merge::extraction_outputs(vault, attempt)
}
