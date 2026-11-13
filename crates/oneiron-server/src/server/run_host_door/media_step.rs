//! The resident entry's dispatcher-owned context for a durable media call.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use oneiron::attempt_queue::AttemptRecord;
use oneiron::llm::{DurableStepContext, StepSpendScope};
use oneiron::{EntityId, Vault, WriteActor};

#[derive(Clone)]
pub(crate) struct RunMediaStep {
    vault: Arc<Vault>,
    attempt: oneiron::attempt_queue::AttemptId,
    run_id: Option<String>,
    actor: WriteActor,
    subject: EntityId,
    /// The run's spend scope, read before its meter's guard: a spent media
    /// step parks on the scope whose top-up gives it room, or refuses typed.
    spend_scope: Option<StepSpendScope>,
    trapped: Arc<AtomicBool>,
}

impl RunMediaStep {
    pub(in crate::server) fn new(
        vault: &Arc<Vault>,
        attempt: &AttemptRecord,
        actor: WriteActor,
        subject: EntityId,
        spend_scope: Option<StepSpendScope>,
    ) -> Self {
        Self {
            vault: Arc::clone(vault),
            attempt: attempt.id,
            run_id: attempt.run_id.clone(),
            actor,
            subject,
            spend_scope,
            trapped: Arc::new(AtomicBool::new(false)),
        }
    }

    pub(crate) fn context(&self) -> DurableStepContext<'_> {
        DurableStepContext {
            vault: &self.vault,
            attempt_id: self.attempt,
            run_id: self.run_id.clone(),
            envelope_actor: self.actor,
            subject: self.subject,
            deadline: None,
            now_ms: self.vault.now_recorded_at().saturating_mul(1_000),
            spend_scope: self.spend_scope.clone(),
            wake_pass_bound: false,
        }
    }

    pub(crate) fn mark_trapped(&self) {
        self.trapped.store(true, Ordering::Release);
    }

    pub(crate) fn trapped(&self) -> bool {
        self.trapped.load(Ordering::Acquire)
    }
}
