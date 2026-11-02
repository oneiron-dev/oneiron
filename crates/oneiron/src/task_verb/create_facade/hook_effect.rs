//! Transaction-composable, brief-less task creation for engine effects.
//! Direct TASK minting and the caller's effect share one write. The proposal
//! path keeps its existing idempotent door and settles the effect immediately
//! afterward, so a retry reuses the parked proposal rather than duplicating it.

use super::*;

impl Memory<'_> {
    /// Creates a brief-less TASK and runs `effect` with its receipt. In the
    /// direct Auto path the TASK, its realizing route and `effect` commit in
    /// one transaction. A ceiling-parked proposal keeps today's dedupe; its
    /// effect commits immediately after, and a retry settles against the same
    /// proposal. No brief or intent-key highway is involved.
    pub(crate) fn tasks_create_briefless_with_effect(
        &self,
        spec: &TaskCreateSpec,
        mut effect: impl FnMut(&mut heed::RwTxn<'_>, &TaskCreateReceipt) -> MemoryResult<()>,
    ) -> MemoryResult<TaskCreateReceipt> {
        if !self.has_task_work_turn() {
            return self
                .task_work_memory()
                .tasks_create_briefless_with_effect(spec, effect);
        }
        if spec.brief.is_some() || spec.intent_key.is_some() {
            return Err(MemoryError::bad_request(
                "composed task creation is brief-less",
            ));
        }
        let verb = task_verb_contract(AgentVerb::TasksCreate);
        verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        let now = spec.now.unwrap_or_else(|| self.vault().now_recorded_at());
        let rate_now = self.vault().store.clock.now_recorded_at();
        let provenance = facade_provenance(verb);
        admit_task_parent(self, spec.parent_ref)?;
        let validated = validate_task_create(self.vault(), spec, now)?;
        let direct = self.with_verified_actor_write_txn(|wtxn| {
            let ceiling =
                task_actor_ceiling(self.vault(), &*wtxn, self.actor(), self.actor_class())?;
            if ceiling != PolicyApprovalCeiling::Auto {
                return Ok(None);
            }
            record_task_create(
                self.vault(),
                wtxn,
                self.actor(),
                rate_now,
                TaskCreateRateLimit::default(),
            )?;
            let owner_ref = spec.owner_ref.unwrap_or_else(|| self.actor());
            let task_ref = self.mint_task_in_txn(
                wtxn,
                &validated,
                spec.label.clone(),
                owner_ref,
                &provenance,
                now,
            )?;
            self.attach_task_parent_in_txn(wtxn, task_ref, spec.parent_ref)?;
            let route = self.route_created_task_in_txn(wtxn, task_ref, &validated, now)?;
            self.witness_human_assignment_in_txn(wtxn, task_ref, &validated, owner_ref, now)?;
            let receipt = TaskCreateReceipt {
                task_ref: Some(task_ref),
                proposal_ref: None,
                approval: ClaimApprovalStatus::Auto,
                effected: true,
                route: Some(route),
                task_record: None,
                proposal_record: None,
            }
            .with_record_refs();
            effect(wtxn, &receipt)?;
            Ok(Some(receipt))
        })?;
        if let Some(receipt) = direct {
            return Ok(receipt);
        }

        let proposal_ref = match self.open_create_proposal_for_spec(spec, now)? {
            Some(existing) => existing,
            None => {
                self.persist_task_proposal_with_origin(
                    TASK_CREATE_PROPOSAL_PREDICATE,
                    task_create_proposal_value(spec, now),
                    self.actor(),
                    now,
                    provenance,
                    self.task_host(),
                )?
                .0
            }
        };
        let receipt = TaskCreateReceipt {
            task_ref: None,
            proposal_ref: Some(proposal_ref),
            approval: ClaimApprovalStatus::Proposed,
            effected: false,
            route: None,
            task_record: None,
            proposal_record: None,
        }
        .with_record_refs();
        self.with_verified_actor_write_txn(|wtxn| effect(wtxn, &receipt))?;
        Ok(receipt)
    }
}
