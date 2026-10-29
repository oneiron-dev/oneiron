//! A resident's free-time items on this server (FIX 4453). Each runs on a run
//! of its own, bound to its item by the engine's stamp, on the resident's
//! own served model or else the weaver's ladder and model, and is metered on
//! what its cycle's spend scope may still spend, never on the pass's line.

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::agent_dispatch::AgentDispatcher;
use oneiron::dreamer_consolidation::{
    DREAMER_NARRATIVE_ROLE, ResidentDreamModel, run_free_time_for_human, run_resident_dream,
};
use oneiron::dreamer_runner::{DREAMER_FREE_TIME_FOR_HUMAN_ATTEMPT_KIND, FreeTimeItemBinding};
use oneiron::llm::run_admission::RunAttribution;
use oneiron::llm::{HostInferenceBinding, HostInferenceContext};
use oneiron::{DreamerAdmittedAttempt, DreamerAttemptExecution, WakeAttemptContext, WriteActor};

use super::super::policy::extraction_egress;
use super::request_sources::SourcedRunBackend;
use super::{DREAMER_PASS_RUN, ResidentLend, own_dreaming_slot, served_slot_model};

impl ResidentLend<'_> {
    /// Runs one free-time item for `binding`'s resident: its free time for
    /// its human, or its dreaming as its own time. The run carries the
    /// item's attribution, and its line and step meter hold no more than its
    /// cycle's spend scope may still spend; an item with nothing left ends
    /// without a call. Without a weaver's ladder or a served model of its
    /// own, it ends without its work.
    pub(super) async fn free_time_item(
        self,
        attempt: &DreamerAdmittedAttempt,
        ctx: &WakeAttemptContext<'_>,
        binding: FreeTimeItemBinding,
    ) -> oneiron::Result<DreamerAttemptExecution> {
        let resident = binding.agent;
        let available = AgentDispatcher::new(self.vault).available_units(&binding.spend_scope)?;
        if available == 0 {
            return Ok(DreamerAttemptExecution::Completed { completed_units: 0 });
        }
        let own = match own_dreaming_slot(self.vault, resident)? {
            Some(slot) => served_slot_model(self.vault, self.runtime, &slot)?,
            None => None,
        };
        let (model, host_binding, ladder, role) = match own {
            Some((model, locality, ladder)) => (
                model.clone(),
                HostInferenceBinding::Advertised { model, locality },
                ladder,
                None,
            ),
            None => {
                let Some(ladder) = self.weaver_ladder else {
                    return Ok(DreamerAttemptExecution::Completed { completed_units: 0 });
                };
                (
                    self.weaver.model.clone(),
                    self.weaver.binding.clone(),
                    Arc::clone(ladder),
                    Some(DREAMER_NARRATIVE_ROLE),
                )
            }
        };
        let limit = self.guard.read().limit_units.min(available);
        let reserve = self.guard.reserve_units().min(limit);
        let line_id = format!("{DREAMER_PASS_RUN}/free_time/{}", binding.item.to_hex());
        let line = self.vault.policy_budget_guard(
            line_id.clone(),
            limit,
            reserve,
            oneiron::BudgetExhaustionPolicy::Suspend,
            WriteActor::new(resident, oneiron::EdgeActorClass::Agent),
        )?;
        // The driver settles what this line charges if the item fails or
        // parks before it reports its spend (SCAN C012).
        ctx.meter_run_line(&line);
        let backend = SourcedRunBackend::new(
            ladder,
            self.runtime.attributed_run(
                line_id.clone(),
                line,
                RunAttribution {
                    agent: resident,
                    cycle: binding.cycle,
                    item: binding.item,
                    purpose: binding.kind.purpose(),
                    spend_scope: binding.spend_scope.as_str().to_owned(),
                },
            ),
        );
        // Its durable step meters on a line of its own: one meter on both
        // layers would charge twice.
        let step = self.vault.policy_budget_guard(
            format!("{line_id}/step"),
            limit,
            reserve,
            oneiron::BudgetExhaustionPolicy::Suspend,
            WriteActor::new(resident, oneiron::EdgeActorClass::Agent),
        )?;
        let egress = self
            .egress
            .then(|| extraction_egress(BTreeSet::from([model.clone()])));
        let window_tokens = self.windows.get(&model).copied();
        let lent = ResidentDreamModel {
            backend: &backend,
            guard: &step,
            model,
            inference: HostInferenceContext {
                binding: host_binding,
                extraction_egress: egress.as_deref(),
            },
            role,
            instruction: self.instruction,
            window_tokens,
            sourced: Some(&backend),
        };
        if attempt.status.payload.attempt_type == DREAMER_FREE_TIME_FOR_HUMAN_ATTEMPT_KIND {
            run_free_time_for_human(attempt, ctx, lent).await
        } else {
            run_resident_dream(attempt, ctx, lent).await
        }
    }
}
