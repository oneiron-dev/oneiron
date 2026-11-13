//! The Coach's retrieval-policy update on the shared nightly maintenance lane:
//! the fast loop, then the slow loop's queue (ARCH-0053 #tune-retrieval:
//! "automatic bandit updates and then dreamer reviews").

use super::super::DreamerAdmittedAttempt;
use crate::{Result, Vault};

pub(super) fn run(vault: &Vault, attempt: &DreamerAdmittedAttempt, now: u64) -> Result<()> {
    vault.store.update_retrieval_policy_at_sleep()?;
    // Keep the already-shipped blend tuner, including its quiet-night behavior.
    let _ = vault
        .store
        .tune_retrieval_blend_weights_when_ready(Default::default())?;
    super::retrieval_skill_review::queue_after_tune(vault, attempt, now)
}
