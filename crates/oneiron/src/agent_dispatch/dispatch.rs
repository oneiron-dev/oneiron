//! Core dispatch admission: dispatchability, depth bound, enqueue, dedupe.

use crate::Vault;
use crate::agent_def::AgentDefinition;
use crate::attempt_queue::{AttemptId, AttemptQueue};
use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus};
use crate::context_projection::{CONTEXT_PROJECTION_MAX_ANCESTORS, normalize_context_spec};
use crate::dreamer_runner::{
    DreamerRunnerStore, EnqueueDreamerAttempt, EnqueueDreamerAttemptOutcome,
    decode_dreamer_attempt_payload,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

use super::attenuation::child_depth_from;
use super::codec::{agent_dispatch_status, encode_agent_dispatch_input, record_dispatch_input};
use super::types::{
    AGENT_DISPATCH_ATTEMPT_TYPE, AgentDispatchInput, AgentDispatchOutcome, AgentDispatchTarget,
    AgentSpawnContext, DEFAULT_BASE_LOGICAL_ID, DispatchAgent,
};
use crate::error::ArtifactError;

/// Dispatch adapter over an already-open vault (house pattern:
/// `RunTreeAdapter::new`, `DreamerRunnerStore::new`). The OF-334 verb home is
/// [`AgentDispatcher::dispatch`]; there is deliberately no `Vault` alias.
pub struct AgentDispatcher<'a> {
    pub(super) vault: &'a Vault,
    pub(super) runner: DreamerRunnerStore<'a>,
}

impl<'a> AgentDispatcher<'a> {
    /// Opens a dispatch adapter over an already-open vault.
    #[must_use]
    pub fn new(vault: &'a Vault) -> Self {
        Self {
            vault,
            runner: DreamerRunnerStore::new(vault),
        }
    }

    /// Checks dispatchability, freezes the composition snapshot, and enqueues
    /// the durable dispatch attempt.
    ///
    /// # Errors
    ///
    /// [`ArtifactError::AgentDefinitionNotFound`](crate::error::ArtifactError::AgentDefinitionNotFound) when the named row is absent;
    /// [`ArtifactError::AgentNotDispatchable`](crate::error::ArtifactError::AgentNotDispatchable) when it is not Active or not approved;
    /// [`ArtifactError::AgentDefinitionDisabled`](crate::error::ArtifactError::AgentDefinitionDisabled) when its stored `enabled` is off;
    /// [`ArtifactError::InvalidAgentDispatchInput`](crate::error::ArtifactError::InvalidAgentDispatchInput) when a deduped-existing row's
    /// payload fails the pinned codec (fail-closed).
    pub fn dispatch(&self, input: DispatchAgent) -> Result<AgentDispatchOutcome> {
        self.dispatch_with_context(input, AgentSpawnContext::default())
    }

    /// [`Self::dispatch`] plus the spawning agent's typed spawn input.
    ///
    /// With a parent this MUST, in this order: enforce the stored depth budget
    /// (zero rejects before any fork, resolution, or enqueue), attenuate the
    /// live target row against the parent's live ceiling, resolve the context
    /// descriptor against fresh state, and only then enqueue once.
    ///
    /// # Errors
    ///
    /// Everything [`Self::dispatch`] raises, plus
    /// [`ArtifactError::InvalidAgentDispatchInput`](crate::error::ArtifactError::InvalidAgentDispatchInput) when the parent's depth budget is
    /// exhausted, when the requested context descriptor widens the parent's, or
    /// when the attenuated fork cannot be registered. A dispatch that cannot
    /// attenuate NEVER falls back to the wider source row.
    pub fn dispatch_with_context(
        &self,
        input: DispatchAgent,
        spawn: AgentSpawnContext,
    ) -> Result<AgentDispatchOutcome> {
        if matches!(input.target, AgentDispatchTarget::Workflow(_)) {
            return self.dispatch_workflow(input, spawn);
        }
        // Normalize the descriptor exactly ONCE here, before it is resolved,
        // compared, or persisted: the stored `AgentDispatchInput.context_spec`
        // is then canonical, so declared-narrowing and dedupe comparisons
        // never false-reject whitespace-equivalent tokens.
        let spawn = AgentSpawnContext {
            context_spec: spawn.context_spec.map(normalize_context_spec),
            ..spawn
        };
        // Zero rejects HERE, before the descriptor is resolved, before any fork
        // row is registered, and before anything is enqueued. The in-transaction
        // computation below is the authority; this is the ordering guarantee.
        let txn = self.vault.store.env.read_txn()?;
        self.project_depth_limit_in_txn(&txn, input.parent_attempt, spawn.project_ref)?;
        drop(txn);
        let target_definition = self.dispatchable_definition(&input.target)?;
        if let Some(outcome) = self.propose_context_widen(&input, &spawn)? {
            return Ok(outcome);
        }
        // Resolution runs outside the write transaction on purpose: it is a
        // pure read of live state, and the vault's read seams open their own
        // snapshots. The resolved projection is deliberately NOT persisted —
        // the executor re-resolves it, so a resumed agent reads fresh state.
        self.resolve_dispatch_context(
            input.parent_attempt,
            spawn.context_spec.as_ref(),
            &spawn.context_from,
            input.run_id.as_deref(),
            target_definition.scope.to_world_scope(),
        )?;

        let mut wtxn = self.vault.store.env.write_txn()?;
        let outcome = self.dispatch_in_txn(&mut wtxn, None, input, spawn)?;
        wtxn.commit()?;
        self.vault.store.notify_attempt_observers();
        Ok(outcome)
    }

    /// Dispatches an in-process child that REALIZES a TASK: identical to
    /// [`Self::dispatch`] except the queued attempt carries the TASK backlink,
    /// and the caller owns the transaction so the TASK and its realizing
    /// dispatch commit together (ONE-1700 assignee routing).
    pub(crate) fn dispatch_for_task_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        task_ref: EntityId,
        input: DispatchAgent,
    ) -> Result<AgentDispatchOutcome> {
        self.dispatch_in_txn(wtxn, Some(task_ref), input, AgentSpawnContext::default())
    }

    pub(super) fn dispatch_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        task_ref: Option<EntityId>,
        input: DispatchAgent,
        spawn: AgentSpawnContext,
    ) -> Result<AgentDispatchOutcome> {
        let requested_parent = input.parent_attempt;
        let dispatch_input = self.prepare_dispatch_in_txn(wtxn, input.clone(), spawn)?;
        let encoded = encode_agent_dispatch_input(&dispatch_input)?;
        let outcome = self.runner.enqueue_with_task_ref_in_txn(
            wtxn,
            EnqueueDreamerAttempt {
                attempt_type: AGENT_DISPATCH_ATTEMPT_TYPE.to_owned(),
                input: encoded,
                parent_attempt: requested_parent,
                dedupe_key: input
                    .dedupe_key
                    .map(|key| format!("{AGENT_DISPATCH_ATTEMPT_TYPE}:{key}")),
                run_id: input.run_id,
                now: input.now,
            },
            task_ref.map(|task_ref| task_ref.to_hex()),
        )?;

        Ok(match outcome {
            EnqueueDreamerAttemptOutcome::Enqueued(status) => {
                if let Some(case) = &dispatch_input.healer_case {
                    crate::failure_ladder::oversight::proposed_in_txn(
                        self.vault,
                        wtxn,
                        &case.case_ref,
                        input.now,
                    )?;
                }
                let mut status = agent_dispatch_status(status)?;
                let index: Vec<_> = status
                    .input
                    .definition
                    .skills
                    .iter()
                    .map(|skill| (&skill.skill_id, &skill.min_version))
                    .collect();
                let bytes = serde_json::to_vec(&index)
                    .map_err(|_| Error::InvariantViolation("skill index encode"))?;
                let agent = status.input.target.agent_definition_ref()?;
                status.attempt = AttemptQueue::new(self.vault).append_manifest_entry_in_txn(
                    wtxn,
                    status.attempt.id,
                    crate::attempt_queue::ManifestEntry::new(
                        crate::attempt_queue::ManifestKind::SkillIndex,
                        agent.to_hex(),
                        blake3::hash(&bytes).to_hex().as_str(),
                        input.now,
                    ),
                )?;
                AgentDispatchOutcome::Dispatched(status)
            }
            EnqueueDreamerAttemptOutcome::Existing(status) => {
                let status = agent_dispatch_status(status)?;
                if status.input.target != dispatch_input.target {
                    return Err(Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
                        "existing dedupe row targets a different agent",
                    )));
                }
                let existing_parent =
                    decode_dreamer_attempt_payload(&status.attempt.payload)?.parent_attempt;
                if existing_parent != requested_parent {
                    return Err(Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
                        "existing dedupe row belongs to a different parent",
                    )));
                }
                // The dedupe key names the INTENT, so the persisted row must
                // carry the SAME effective spawn input; a different one is a
                // typed error, never a silent reuse.
                if status.input.healer_case != dispatch_input.healer_case
                    || status.input.context_spec != dispatch_input.context_spec
                    || status.input.context_from != dispatch_input.context_from
                    || status.input.depth_remaining != dispatch_input.depth_remaining
                    || status.input.project_ref != dispatch_input.project_ref
                    || status.input.scope != dispatch_input.scope
                {
                    return Err(Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
                        "existing dedupe row carries a different spawn context",
                    )));
                }
                AgentDispatchOutcome::Existing(status)
            }
        })
    }

    /// Freezes one real agent after structural and live-authority checks.
    pub(super) fn prepare_dispatch_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        input: DispatchAgent,
        spawn: AgentSpawnContext,
    ) -> Result<AgentDispatchInput> {
        let requested_parent = input.parent_attempt;

        // 1. STRUCTURAL BOUND FIRST. Zero rejects here, before any fork
        //    registration, context resolution, or enqueue — so an exhausted
        //    lineage cannot leave a fork row behind as a side effect.
        let (project_ref, project_limit) =
            self.project_depth_limit_in_txn(wtxn, requested_parent, spawn.project_ref)?;
        let depth_remaining = Some(
            spawn
                .depth_remaining
                .unwrap_or(project_limit)
                .min(project_limit),
        );

        // Resolve resource lineage before any fork is registered. Missing or
        // non-dispatch parents carry deny-all, never an implicit global grant.
        let scope = match requested_parent {
            None => spawn.scope.clone(),
            Some(parent) => {
                let parent_scope = self
                    .parent_dispatch_input_in_txn(wtxn, parent)?
                    .and_then(|input| input.scope)
                    .unwrap_or_default();
                Some(
                    parent_scope
                        .attenuate(spawn.scope.clone().unwrap_or_else(|| parent_scope.clone()))?,
                )
            }
        };
        let requested_definition = self.dispatchable_definition_in_txn(wtxn, &input.target)?;
        if let Some(case) = &spawn.healer_case {
            super::healer_context::validate(case)?;
            crate::failure_ladder::require_healer_case_in_txn(
                self.vault,
                wtxn,
                case,
                input.run_id.as_deref(),
            )?;
            if input.parent_attempt != Some(case.failing_attempt_id)
                || requested_definition.ceiling != crate::agent_def::AgentCeiling::Proposed
            {
                return Err(Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
                    "healer context requires its failing parent and propose-only ceiling",
                )));
            }
        }

        // 2. AUTHORITY BOUND. Both sides read the LIVE stored rows; the frozen
        //    payload ceiling stays non-authoritative on every path.
        let (target, definition) = match requested_parent {
            None => (input.target, requested_definition),
            Some(parent_attempt) => {
                let requested_ref = input.target.agent_definition_ref()?;
                let (attenuated, definition) = self.attenuate_child_target(
                    wtxn,
                    parent_attempt,
                    requested_ref,
                    requested_definition,
                    input.run_id.as_deref(),
                    input.now,
                )?;
                (attenuated.target, definition)
            }
        };

        // 3. The descriptor rides the payload UNRESOLVED. It was validated
        //    against live parent state in `dispatch_with_context`; the executor
        //    resolves it again at read time, which is what keeps it fresh.
        Ok(AgentDispatchInput {
            healer_case: spawn.healer_case,
            target,
            definition,
            context_spec: spawn.context_spec,
            context_from: spawn.context_from,
            depth_remaining,
            project_ref: Some(project_ref),
            scope,
        })
    }

    /// Loads a dispatch target's LIVE stored row and applies the dispatchability
    /// predicate. Fails closed on a missing, non-`AGENT_DEF`, malformed,
    /// inactive, unapproved, or disabled row.
    pub(super) fn dispatchable_definition(
        &self,
        target: &AgentDispatchTarget,
    ) -> Result<AgentDefinition> {
        let txn = self.vault.store.env.read_txn()?;
        self.dispatchable_definition_in_txn(&txn, target)
    }

    pub(super) fn dispatchable_definition_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        target: &AgentDispatchTarget,
    ) -> Result<AgentDefinition> {
        let id = &target.agent_definition_ref()?;
        let definition = match crate::vault::live_entity_row_in_txn(&self.vault.store, txn, id)? {
            crate::vault::LiveEntityRow::Live { entity_type, body }
                if entity_type == crate::registry::ENTITY_TYPE_AGENT_DEF =>
            {
                crate::agent_def::decode_agent_definition(&body)?
            }
            crate::vault::LiveEntityRow::Absent | crate::vault::LiveEntityRow::DeletedShell => {
                return Err(Error::Artifact(ArtifactError::AgentDefinitionNotFound {
                    id: *id,
                }));
            }
            _ => {
                return Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
                    "entity is not a type-17 AGENT_DEF",
                )));
            }
        };
        if definition.lifecycle_status != ClaimLifecycleStatus::Active {
            return Err(Error::Artifact(ArtifactError::AgentNotDispatchable(
                "agent definition is not active",
            )));
        }
        if !matches!(
            definition.approval_status,
            ClaimApprovalStatus::Auto | ClaimApprovalStatus::Approved
        ) {
            return Err(Error::Artifact(ArtifactError::AgentNotDispatchable(
                "agent definition is not approved",
            )));
        }
        if !definition.enabled {
            return Err(Error::Artifact(ArtifactError::AgentDefinitionDisabled {
                id: *id,
            }));
        }
        Ok(definition)
    }

    /// Read the live project in the same snapshot as the stored parent slice.
    /// Root defaults to the vault project; an omitted child project inherits.
    /// A project transition may only enter a direct child responsibility space.
    pub(super) fn project_depth_limit_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        parent_attempt: Option<AttemptId>,
        requested_project: Option<EntityId>,
    ) -> Result<(EntityId, u8)> {
        let parent = parent_attempt
            .map(|id| {
                let row = AttemptQueue::new(self.vault).get_in_txn(txn, id)?;
                if let Some(row) = &row {
                    super::workflow_record::reject_wrapper_parent(row)?;
                }
                Ok::<_, Error>(row.and_then(|row| record_dispatch_input(&row)))
            })
            .transpose()?
            .flatten();
        let root = self.vault.project_for_spawn_in_txn(txn, None)?.0;
        let parent_project = parent
            .as_ref()
            .and_then(|input| input.project_ref)
            .unwrap_or(root);
        let (id, project) = self.vault.project_for_spawn_in_txn(
            txn,
            requested_project.or_else(|| parent_attempt.map(|_| parent_project)),
        )?;
        if id != root && (parent_attempt.is_none() || parent.is_none()) {
            return Err(Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
                "a project spawn requires a real parent in its ancestor project",
            )));
        }
        let ceiling = match parent_attempt {
            None => project.depth,
            Some(_) if id == parent_project => {
                project.depth.checked_sub(1).ok_or(Error::Artifact(
                    ArtifactError::InvalidAgentDispatchInput("project depth is exhausted"),
                ))?
            }
            Some(_) if project.parent.as_deref() == Some(&parent_project.to_hex()) => project.depth,
            Some(_) => {
                return Err(Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
                    "project is not a child of the parent project",
                )));
            }
        };
        let bound = match parent_attempt {
            None => CONTEXT_PROJECTION_MAX_ANCESTORS as u8,
            Some(_) => child_depth_from(parent)?,
        };
        Ok((id, ceiling.min(bound)))
    }

    /// The depth budget a child of `parent_attempt` must be persisted with.
    ///
    /// Reads the parent's persisted [`AgentDispatchInput`]. A stored `Some(0)`
    /// is the exhausted lineage and REJECTS here, before any fork registration,
    /// context resolution, or enqueue — so zero cannot enqueue another level.
    ///
    /// # Errors
    ///
    /// [`ArtifactError::InvalidAgentDispatchInput`](crate::error::ArtifactError::InvalidAgentDispatchInput) when the parent's budget is
    /// exhausted.
    pub fn child_depth_remaining(&self, parent_attempt: AttemptId) -> Result<u8> {
        child_depth_from(self.parent_dispatch_input(parent_attempt)?)
    }

    /// The parent attempt's decoded dispatch input, read outside any caller
    /// transaction.
    pub(super) fn parent_dispatch_input(
        &self,
        parent_attempt: AttemptId,
    ) -> Result<Option<AgentDispatchInput>> {
        let row = AttemptQueue::new(self.vault).get(parent_attempt)?;
        if let Some(row) = &row {
            super::workflow_record::reject_wrapper_parent(row)?;
        }
        Ok(row.and_then(|record| record_dispatch_input(&record)))
    }

    pub(super) fn parent_dispatch_input_in_txn(
        &self,
        wtxn: &heed::RwTxn<'_>,
        parent_attempt: AttemptId,
    ) -> Result<Option<AgentDispatchInput>> {
        let row = AttemptQueue::new(self.vault).get_in_write_txn(wtxn, parent_attempt)?;
        if let Some(row) = &row {
            super::workflow_record::reject_wrapper_parent(row)?;
        }
        Ok(row.and_then(|record| record_dispatch_input(&record)))
    }

    /// Dispatches the always-available generic base without a caller-supplied
    /// definition or target selection: the seeded `sys.default` row, resolved
    /// through the canonical manifest — no compiled pinned-id constant.
    pub fn dispatch_default_base(
        &self,
        parent_attempt: Option<AttemptId>,
        dedupe_key: Option<String>,
        run_id: Option<String>,
        now: u64,
    ) -> Result<AgentDispatchOutcome> {
        let (id, _) = self
            .vault
            .get_seeded_agent_definition_by_logical_id(DEFAULT_BASE_LOGICAL_ID)?
            .ok_or(Error::Artifact(ArtifactError::AgentNotDispatchable(
                "the seeded default base agent definition is absent",
            )))?;
        self.dispatch(DispatchAgent {
            target: AgentDispatchTarget::Custom(id),
            parent_attempt,
            dedupe_key,
            run_id,
            now,
        })
    }
}
