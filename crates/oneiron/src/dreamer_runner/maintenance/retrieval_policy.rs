//! The Coach's retrieval-policy update on the shared nightly maintenance lane.

use crate::{Result, Vault};

pub(super) fn run(vault: &Vault) -> Result<()> {
    vault.store.update_retrieval_policy_at_sleep()?;
    // Keep the already-shipped blend tuner, including its quiet-night behavior.
    let _ = vault
        .store
        .tune_retrieval_blend_weights_when_ready(Default::default())?;
    Ok(())
}
