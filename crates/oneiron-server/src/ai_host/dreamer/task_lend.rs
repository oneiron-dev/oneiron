//! The host's loan to a Dreamer-lane TASK's realization and its weave lens
//! render.

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::attempt_queue::AttemptQueue;
use oneiron::dreamer_consolidation::{
    RoleBackend, TaskRealizeModel, WeaveLensModel, run_task_realize, run_weave_lens,
};
use oneiron::llm::HostInferenceContext;
use oneiron::llm::manifest::ModelRole;
use oneiron::{DreamerAdmittedAttempt, DreamerAttemptExecution, WakeAttemptContext, WriteActor};

use super::request_sources::ServedRealization;
use super::{RoleSends, extraction_egress};

/// The host's loan to a Dreamer-lane TASK's realization: the pass's route
/// and line, the Dreamer's stamp and the wording.
#[derive(Clone, Copy)]
pub(super) struct TaskLend<'p> {
    pub(super) role: ModelRole,
    pub(super) route: &'p RoleBackend,
    /// The ladder and run `route` sends on, which a realization sends on
    /// itself to learn which rung answered.
    pub(super) sends: &'p RoleSends,
    pub(super) guard: &'p oneiron::BudgetGuard,
    pub(super) egress: bool,
    pub(super) actor: WriteActor,
    pub(super) instruction: &'p str,
    pub(super) confession: &'p str,
}

impl TaskLend<'_> {
    pub(super) async fn realize(
        self,
        attempt: &DreamerAdmittedAttempt,
        ctx: &WakeAttemptContext<'_>,
    ) -> oneiron::Result<DreamerAttemptExecution> {
        let egress = self
            .egress
            .then(|| extraction_egress(BTreeSet::from([self.route.model.clone()])));
        let (ladder, run) = self.sends;
        let backend = ServedRealization::new(Arc::clone(ladder), run.clone());
        let realized = run_task_realize(
            attempt,
            ctx,
            TaskRealizeModel {
                backend: &backend,
                guard: self.guard,
                model: self.route.model.clone(),
                inference: HostInferenceContext {
                    binding: self.route.binding.clone(),
                    extraction_egress: egress.as_deref(),
                },
                role: self.role,
                actor: self.actor,
                instruction: self.instruction,
                confession: self.confession,
                sourced: Some(&backend),
            },
        )
        .await?;
        // The rung that answered, fallback included, is the try's executor
        // (OF-540), stamped while its lease holds: its confession seals
        // against it (OF-544). A refused stamp leaves the try unattributed,
        // not failed.
        let record = &attempt.status.attempt;
        if matches!(realized, DreamerAttemptExecution::Completed { .. })
            && let Some(served) = backend.served()
            && let Some(owner) = record.lease_owner.as_deref()
            && let Err(error) = AttemptQueue::new(ctx.vault).set_executor_model(
                record.id,
                owner,
                record.attempt_count,
                served.as_str(),
            )
        {
            tracing::warn!(kind = ?error.kind(), "a TASK realization's executor was not stamped");
        }
        Ok(realized)
    }

    /// The weave lens's generate step on the same route; the shipped
    /// weave-report skill is its instruction.
    pub(super) async fn render_lens(
        self,
        attempt: &DreamerAdmittedAttempt,
        ctx: &WakeAttemptContext<'_>,
    ) -> oneiron::Result<DreamerAttemptExecution> {
        let egress = self
            .egress
            .then(|| extraction_egress(BTreeSet::from([self.route.model.clone()])));
        let rendered = run_weave_lens(
            attempt,
            ctx,
            WeaveLensModel {
                backend: self.route.backend.as_ref(),
                guard: self.guard,
                model: self.route.model.clone(),
                inference: HostInferenceContext {
                    binding: self.route.binding.clone(),
                    extraction_egress: egress.as_deref(),
                },
                role: self.role,
                actor: self.actor,
                sourced: self.route.sourced.as_deref(),
            },
        )
        .await?;
        // The weave-report pack it loaded closes attributed (FIX 1875), bound
        // while its lease holds. A bind that fails leaves the receipt
        // unattributed; the render stands.
        let record = &attempt.status.attempt;
        if matches!(rendered, DreamerAttemptExecution::Completed { .. })
            && let Some(owner) = record.lease_owner.as_deref()
            && let Err(error) = oneiron::skill_attribution::bind_dreamer_weave_attribution(
                ctx.vault, record.id, owner, None,
            )
        {
            tracing::warn!(kind = ?error.kind(), "a weave lens render's pack attribution did not bind");
        }
        Ok(rendered)
    }
}
