//! A policy snapshot bound to one call's admission and human delivery.

use std::sync::Arc;

use crate::llm::RunAdmission;
use crate::llm::decision::{HeldLadder, HumanDecisionQueue, ProviderPin};

use super::PolicyDecisions;

impl PolicyDecisions {
    /// This question snapshot on the caller's existing run.
    /// Provider admission and settlement stay on that run; the ladder's
    /// retention and capture behavior are unchanged.
    #[must_use]
    pub fn for_run(&self, run: RunAdmission) -> Self {
        Self {
            run: Some(run),
            ..self.clone()
        }
    }

    /// This question snapshot on the caller's run and request-owned human queue.
    /// The other providers, questions, principal, dial and budget stay unchanged.
    #[must_use]
    pub fn for_run_with_human(
        &self,
        run: RunAdmission,
        human: Arc<dyn HumanDecisionQueue>,
        human_pin: ProviderPin,
    ) -> Self {
        Self {
            ladder: Arc::new(HeldLadder {
                human,
                human_pin,
                ..(*self.ladder).clone()
            }),
            run: Some(run),
            ..self.clone()
        }
    }
}
