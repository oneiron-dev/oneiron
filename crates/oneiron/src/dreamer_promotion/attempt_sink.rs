//! An owned promotion sink for a long-lived host. One sink serves every
//! attempt a supervisor admits: each sealed write names its own run, so the
//! host never builds (or can forge) a per-attempt run context.
use std::sync::Arc;

use super::{DreamerRunContext, promote_scoped_consolidation};
use crate::Vault;
use crate::attempt_queue::AttemptQueue;
use crate::dreamer_consolidation::{
    ConsolidationSink, PromotionCandidate, ScopedConsolidationWrite,
};
use crate::entity_id::bytes_to_hex_lower;
use crate::error::{Error, Result};

/// [`ConsolidationSink`] over the one promotion door, owned rather than
/// borrowed, for executors built once and lent to many passes.
pub struct AttemptPromotionSink {
    vault: Arc<Vault>,
}

impl AttemptPromotionSink {
    #[must_use]
    pub fn new(vault: Arc<Vault>) -> Self {
        Self { vault }
    }
}

impl ConsolidationSink for AttemptPromotionSink {
    /// Unsealed candidates carry no run, so this sink refuses them.
    fn accept(&mut self, _candidates: Vec<PromotionCandidate>) -> Result<()> {
        Err(Error::InvalidClaimBody(
            "attempt promotion sink needs a sealed scoped write",
        ))
    }

    fn accept_scoped(&mut self, write: ScopedConsolidationWrite) -> Result<()> {
        let (agent_actor, attempt_id) = write.fence.run_identity();
        let run_id = AttemptQueue::new(&self.vault)
            .get(attempt_id)?
            .and_then(|row| row.run_id)
            .unwrap_or_else(|| bytes_to_hex_lower(attempt_id.as_bytes()));
        let run = DreamerRunContext {
            run_id,
            attempt_id,
            agent_actor,
            now_ms: self.vault.now_recorded_at().saturating_mul(1_000),
        };
        let outcome = promote_scoped_consolidation(&self.vault, &run, write, None)?;
        if outcome.rejected.is_empty() {
            Ok(())
        } else {
            Err(Error::InvalidClaimBody(
                "scoped consolidation write refused",
            ))
        }
    }
}
