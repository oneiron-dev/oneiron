//! The priority admission of one wake-pass iteration: cleanup, note review,
//! free time, resident dreaming, skill optimization, maintenance, recipe
//! wakes, TASKs, turn programs, the weave lens, then recipes and connector
//! events in the policy's order. Consolidation is admitted after, by the loop.

use super::super::policy::DreamerWakePolicy;
use super::*;

impl DreamerWakeDriver<'_> {
    /// The highest-priority non-consolidation attempt this iteration admits,
    /// or `Empty`. A refused TASK or turn-program admission sets its flag,
    /// and the rest of the pass admits no more of that kind.
    pub(super) fn admit_priority<E: DreamerAttemptExecutor + ?Sized>(
        &mut self,
        input: &RunWakePass,
        exec: &mut E,
        admission_policy: &DreamerWakePolicy,
        task_admission_refused: &mut bool,
        program_admission_refused: &mut bool,
    ) -> Result<DreamerAdmissionOutcome> {
        let cleanup = if !self.consolidation_only
            && input.trigger == WakeTrigger::Timer
            && input.scope == DreamerConsolidationScope::Macro
        {
            self.store.admit_next_vault_cleanup(AdmitDreamerAttempt {
                lease_owner: input.lease_owner.clone(),
                now: input.now,
                budget_id: self.budget_id.clone(),
                budget_total_units: input.budget_total_units,
                reserve_units: input.reserve_units,
                started_milestone: self
                    .milestone_claim(DreamerMilestoneKind::Started, input.now)?,
            })?
        } else {
            DreamerAdmissionOutcome::Empty
        };
        let cleanup = match cleanup {
            DreamerAdmissionOutcome::Empty
                if !self.consolidation_only
                    && input.trigger == WakeTrigger::Timer
                    && input.scope == DreamerConsolidationScope::Macro =>
            {
                self.store.admit_next_note_review(AdmitDreamerAttempt {
                    lease_owner: input.lease_owner.clone(),
                    now: input.now,
                    budget_id: self.budget_id.clone(),
                    budget_total_units: input.budget_total_units,
                    reserve_units: input.reserve_units,
                    started_milestone: self
                        .milestone_claim(DreamerMilestoneKind::Started, input.now)?,
                })?
            }
            outcome => outcome,
        };
        // Then each resident's free time for its human (FIX 4453), before
        // its own dreaming: its choice of rest ends its own-time item.
        let cleanup = match cleanup {
            DreamerAdmissionOutcome::Empty
                if !self.consolidation_only
                    && input.trigger == WakeTrigger::Timer
                    && input.scope == DreamerConsolidationScope::Macro =>
            {
                self.store.admit_next_free_time_item(AdmitDreamerAttempt {
                    lease_owner: input.lease_owner.clone(),
                    now: input.now,
                    budget_id: self.budget_id.clone(),
                    budget_total_units: input.budget_total_units,
                    reserve_units: input.reserve_units,
                    started_milestone: self
                        .milestone_claim(DreamerMilestoneKind::Started, input.now)?,
                })?
            }
            outcome => outcome,
        };
        // Then each resident's own dreaming (OF-490), on the same pass.
        let cleanup = match cleanup {
            DreamerAdmissionOutcome::Empty
                if !self.consolidation_only
                    && input.trigger == WakeTrigger::Timer
                    && input.scope == DreamerConsolidationScope::Macro =>
            {
                // The host may route a resident's dreaming to its own
                // line (FIX 1152); every settlement below follows the
                // line its admission reserved on.
                self.store.admit_next_resident_dream(
                    AdmitDreamerAttempt {
                        lease_owner: input.lease_owner.clone(),
                        now: input.now,
                        budget_id: self.budget_id.clone(),
                        budget_total_units: input.budget_total_units,
                        reserve_units: input.reserve_units,
                        started_milestone: self
                            .milestone_claim(DreamerMilestoneKind::Started, input.now)?,
                    },
                    &mut |candidate: &crate::attempt_queue::AttemptRecord| {
                        exec.runner_budget_id(candidate)
                    },
                )?
            }
            outcome => outcome,
        };
        let priority = match cleanup {
            DreamerAdmissionOutcome::Empty if !self.consolidation_only => {
                self.store.admit_next_skill_optimize(AdmitDreamerAttempt {
                    lease_owner: input.lease_owner.clone(),
                    now: input.now,
                    budget_id: self.budget_id.clone(),
                    budget_total_units: input.budget_total_units,
                    reserve_units: input.reserve_units,
                    started_milestone: self
                        .milestone_claim(DreamerMilestoneKind::Started, input.now)?,
                })?
            }
            outcome => outcome,
        };
        let priority = match priority {
            DreamerAdmissionOutcome::Empty if !self.consolidation_only => {
                self.store.admit_next_maintenance(AdmitDreamerAttempt {
                    lease_owner: input.lease_owner.clone(),
                    now: input.now,
                    budget_id: self.budget_id.clone(),
                    budget_total_units: input.budget_total_units,
                    reserve_units: input.reserve_units,
                    started_milestone: self
                        .milestone_claim(DreamerMilestoneKind::Started, input.now)?,
                })?
            }
            outcome => outcome,
        };
        // The wake policy's recipe receipts follow maintenance: a recipe
        // body queues work of its own, which admits after it.
        let priority = match priority {
            DreamerAdmissionOutcome::Empty if !self.consolidation_only => {
                self.store.admit_next_recipe_wake(AdmitDreamerAttempt {
                    lease_owner: input.lease_owner.clone(),
                    now: input.now,
                    budget_id: self.budget_id.clone(),
                    budget_total_units: input.budget_total_units,
                    reserve_units: input.reserve_units,
                    started_milestone: self
                        .milestone_claim(DreamerMilestoneKind::Started, input.now)?,
                })?
            }
            outcome => outcome,
        };
        // Then the TASKs routed to the Dreamer: the work a person or agent
        // asked for, before the vault's own weaving.
        // A TASK whose admission is refused (the highway refuses its
        // Accept) rolls its admission back and stays queued; the lanes
        // after it still admit this pass.
        let priority = match priority {
            DreamerAdmissionOutcome::Empty
                if !self.consolidation_only && !*task_admission_refused =>
            {
                let request = AdmitDreamerAttempt {
                    lease_owner: input.lease_owner.clone(),
                    now: input.now,
                    budget_id: self.budget_id.clone(),
                    budget_total_units: input.budget_total_units,
                    reserve_units: input.reserve_units,
                    started_milestone: self
                        .milestone_claim(DreamerMilestoneKind::Started, input.now)?,
                };
                match self.store.admit_next_task_realize(request) {
                    Ok(outcome) => outcome,
                    Err(error) => {
                        tracing::warn!(
                            kind = ?error.kind(),
                            %error,
                            "a TASK realization was not admitted; this pass admits no more TASKs"
                        );
                        *task_admission_refused = true;
                        DreamerAdmissionOutcome::Empty
                    }
                }
            }
            outcome => outcome,
        };
        // Then the turn programs landed turns woke (DOOR-141 PR2), and
        // only on an executor that runs them: a pass whose host binds no
        // program runtime admits none. A program whose admission fails
        // stops program admission for this pass, never the pass.
        let priority = match priority {
            DreamerAdmissionOutcome::Empty
                if !self.consolidation_only
                    && !*program_admission_refused
                    && exec.runs_turn_programs() =>
            {
                let admitted = self
                    .milestone_claim(DreamerMilestoneKind::Started, input.now)
                    .and_then(|started_milestone| {
                        self.store.admit_next_turn_program(AdmitDreamerAttempt {
                            lease_owner: input.lease_owner.clone(),
                            now: input.now,
                            budget_id: self.budget_id.clone(),
                            budget_total_units: input.budget_total_units,
                            reserve_units: input.reserve_units,
                            started_milestone,
                        })
                    });
                match admitted {
                    Ok(outcome) => outcome,
                    Err(error) => {
                        tracing::warn!(
                            kind = ?error.kind(),
                            %error,
                            "a turn program was not admitted; this pass admits no more programs"
                        );
                        *program_admission_refused = true;
                        DreamerAdmissionOutcome::Empty
                    }
                }
            }
            outcome => outcome,
        };
        // Then the weave lens renders: each published digest period
        // through the weave-report skill, for the reader it is for.
        let priority = match priority {
            DreamerAdmissionOutcome::Empty if !self.consolidation_only => {
                self.store.admit_next_weave_lens(AdmitDreamerAttempt {
                    lease_owner: input.lease_owner.clone(),
                    now: input.now,
                    budget_id: self.budget_id.clone(),
                    budget_total_units: input.budget_total_units,
                    reserve_units: input.reserve_units,
                    started_milestone: self
                        .milestone_claim(DreamerMilestoneKind::Started, input.now)?,
                })?
            }
            outcome => outcome,
        };
        // Only the NEW recipe-vs-connector choice is policy data. Cleanup
        // and maintenance remain first; consolidation's home-node stop
        // remains last. Read the owner row once per pass below.
        let order = match admission_policy.weave_recipe_priority {
            super::super::policy::WeaveRecipePriority::BeforeConnectorEvent => [true, false],
            super::super::policy::WeaveRecipePriority::AfterConnectorEvent => [false, true],
        };
        let mut priority = priority;
        for recipe in order {
            if self.consolidation_only || !matches!(&priority, DreamerAdmissionOutcome::Empty) {
                break;
            }
            let request = AdmitDreamerAttempt {
                lease_owner: input.lease_owner.clone(),
                now: input.now,
                budget_id: self.budget_id.clone(),
                budget_total_units: input.budget_total_units,
                reserve_units: input.reserve_units,
                started_milestone: self
                    .milestone_claim(DreamerMilestoneKind::Started, input.now)?,
            };
            priority = if recipe {
                self.store.admit_next_weave_recipe(request)?
            } else {
                self.store.admit_next_connector_event(request)?
            };
        }
        Ok(priority)
    }
}
