//! Spawner-only killSpawn intervention and healer-slot dispatch arm.

use crate::agent_def::AgentCeiling;
use crate::attempt_queue::{
    AttemptId, AttemptInterventionEffect, AttemptInterventionKind, AttemptQueue, AttemptState,
    CancelStanding, InterveneAttempt, LandingTrigger, RequestAttemptCancel,
};
use crate::dreamer_runner::decode_dreamer_attempt_payload;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

use super::codec::decode_agent_dispatch_input;
use super::dispatch::AgentDispatcher;
use super::types::{
    AGENT_DISPATCH_ATTEMPT_TYPE, AgentDispatchTarget, DispatchHealer, HealerSlot,
    HealerSlotOutcome, KillOutcome, KillProposal,
};
use crate::error::ArtifactError;

impl AgentDispatcher<'_> {
    /// Resolves one failure case onto its configured healer slot.
    ///
    /// Both slots require an authentic ladder case for a durable failed parent.
    /// `Reserved` mutates no queue state and yields immediate surface-card data.
    /// `AgentDef` also enforces the propose-only ceiling against the live row
    /// and revalidates the case in the enqueue transaction.
    ///
    /// There is deliberately no force-cancel handle here or anywhere on the
    /// healer path. A healer asking a live attempt to land calls ONE-1896's
    /// public soft `request_cancel`/landing-request API separately; force
    /// termination stays authority-only.
    ///
    /// # Errors
    ///
    /// [`ArtifactError::InvalidAgentDispatchInput`](crate::error::ArtifactError::InvalidAgentDispatchInput) when `agent_def_ref` is not a hex
    /// EntityId or the case does not match its durable failed-parent binding;
    /// [`ArtifactError::AgentNotDispatchable`](crate::error::ArtifactError::AgentNotDispatchable) when the named row's live ceiling
    /// exceeds propose-only, plus everything the dispatchability predicate
    /// raises for a missing, inactive, unapproved, or disabled row.
    pub fn dispatch_healer_slot(&self, input: DispatchHealer) -> Result<HealerSlotOutcome> {
        match input.slot {
            HealerSlot::Reserved => {
                let txn = self.vault.store.env.write_txn()?;
                crate::failure_ladder::require_healer_case_in_txn(
                    self.vault,
                    &txn,
                    &input.case,
                    input.run_id.as_deref(),
                )?;
                Ok(HealerSlotOutcome::Reserved { case: input.case })
            }
            HealerSlot::AgentDef { agent_def_ref } => {
                let healer_ref = EntityId::from_hex(&agent_def_ref).map_err(|_| {
                    Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
                        "healer agent_def_ref must be a hex-encoded EntityId string",
                    ))
                })?;
                // Read LIVE, never the frozen payload snapshot: a healer that
                // could act at `Auto` would repair the agent it is diagnosing
                // without anyone proposing it.
                let definition =
                    self.dispatchable_definition(&AgentDispatchTarget::Custom(healer_ref))?;
                if definition.ceiling.widens_beyond(AgentCeiling::Proposed) {
                    return Err(Error::Artifact(ArtifactError::AgentNotDispatchable(
                        "healer agent definition exceeds the propose-only ceiling",
                    )));
                }
                let result = self.dispatch_with_context(
                    super::DispatchAgent {
                        target: AgentDispatchTarget::Custom(healer_ref),
                        parent_attempt: Some(input.case.failing_attempt_id),
                        dedupe_key: Some(format!("healer:{}", input.case.case_ref)),
                        run_id: input.run_id,
                        now: input.now,
                    },
                    super::AgentSpawnContext {
                        healer_case: Some(input.case),
                        // The healer cannot recursively spend the failing task's
                        // whole depth budget. Repairs remain proposals.
                        depth_remaining: Some(1),
                        ..Default::default()
                    },
                )?;
                Ok(match result {
                    super::AgentDispatchOutcome::Dispatched(status) => {
                        HealerSlotOutcome::Dispatched(status)
                    }
                    super::AgentDispatchOutcome::Existing(status) => {
                        HealerSlotOutcome::Existing(status)
                    }
                })
            }
        }
    }
}

impl AgentDispatcher<'_> {
    /// Cancels a direct child spawn when the executing attempt is its spawner.
    ///
    /// `killer_attempt` MUST be the runtime-authenticated executing attempt.
    /// The caller/runtime owns that binding; this trusted wrapper is not a raw
    /// agent verb, and queue intervention must not be exposed around it.
    /// Requests from any other attempt leave the spawn unchanged and surface
    /// a typed proposal.
    pub fn kill_spawn(
        &self,
        spawn_attempt_id: &AttemptId,
        killer_attempt: &AttemptId,
        now: u64,
    ) -> Result<KillOutcome> {
        let queue = AttemptQueue::new(self.vault);
        let mut wtxn = self.vault.store.env.write_txn()?;
        let record = queue
            .get_in_write_txn(&wtxn, *spawn_attempt_id)?
            .ok_or(Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
                "kill target attempt not found",
            )))?;
        if record.kind != crate::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND {
            return Err(Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
                "kill target must be a dreamer attempt",
            )));
        }
        let payload = decode_dreamer_attempt_payload(&record.payload)?;
        if payload.attempt_type != AGENT_DISPATCH_ATTEMPT_TYPE {
            return Err(Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
                "kill target must be an agent dispatch attempt",
            )));
        }
        decode_agent_dispatch_input(&payload.input)?;

        let Some(killer) = queue.get_in_write_txn(&wtxn, *killer_attempt)? else {
            return Ok(KillOutcome::Proposed(KillProposal {
                spawn_attempt_id: *spawn_attempt_id,
                proposer: *killer_attempt,
            }));
        };
        // ONE-1896: a LANDING parent is live work — it still holds its lease
        // and its runtime — so it keeps the standing its lease gives it.
        // Omitting it read a landing spawner as dead and downgraded its ask to
        // a proposal precisely when it was tidying up its own children.
        if !matches!(
            killer.state,
            AttemptState::Queued
                | AttemptState::Leased
                | AttemptState::Paused
                | AttemptState::Landing
        ) {
            return Ok(KillOutcome::Proposed(KillProposal {
                spawn_attempt_id: *spawn_attempt_id,
                proposer: *killer_attempt,
            }));
        }
        if killer.kind != crate::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND {
            return Ok(KillOutcome::Proposed(KillProposal {
                spawn_attempt_id: *spawn_attempt_id,
                proposer: *killer_attempt,
            }));
        }
        // The killer's authority is read from its own stored row, and every check that
        // cannot confirm it as a real agent-dispatch parent fails closed to a proposal
        // (found / live / kind / attempt-type / decodes / parent). Its payload bytes are
        // caller-reachable — `AttemptQueue::enqueue` stores arbitrary bytes under any
        // kind, and `DreamerRunnerStore::enqueue` stores an unvalidated input `Value` —
        // so a killer whose envelope or dispatch input does not decode is an
        // unconfirmable killer, not storage corruption: classify it, do not error.
        let Ok(killer_payload) = decode_dreamer_attempt_payload(&killer.payload) else {
            return Ok(KillOutcome::Proposed(KillProposal {
                spawn_attempt_id: *spawn_attempt_id,
                proposer: *killer_attempt,
            }));
        };
        if killer_payload.attempt_type != AGENT_DISPATCH_ATTEMPT_TYPE {
            return Ok(KillOutcome::Proposed(KillProposal {
                spawn_attempt_id: *spawn_attempt_id,
                proposer: *killer_attempt,
            }));
        }
        if decode_agent_dispatch_input(&killer_payload.input).is_err() {
            return Ok(KillOutcome::Proposed(KillProposal {
                spawn_attempt_id: *spawn_attempt_id,
                proposer: *killer_attempt,
            }));
        }

        if payload.parent_attempt != Some(*killer_attempt) {
            return Ok(KillOutcome::Proposed(KillProposal {
                spawn_attempt_id: *spawn_attempt_id,
                proposer: *killer_attempt,
            }));
        }

        let killer_actor = crate::entity_id::bytes_to_hex_lower(killer_attempt.as_bytes());
        let intervention_kind = match record.state {
            // A scheduled child has not started: kill it the same way a queued
            // one is killed.
            AttemptState::Queued
            | AttemptState::Paused
            | AttemptState::Cancelled
            | AttemptState::Scheduled => AttemptInterventionKind::Cancel,
            // A RUNNING child is asked, never killed (ONE-1896 rung 1). The
            // spawner's proven parent link is peer standing, which is standing
            // to ASK; only the owner/authority or a runtime ground can force,
            // and this trusted wrapper mints neither.
            AttemptState::Leased | AttemptState::Landing => AttemptInterventionKind::Interrupt,
            AttemptState::Completed | AttemptState::Failed | AttemptState::Abandoned => {
                return Ok(KillOutcome::AlreadyTerminal);
            }
        };
        if record.state.is_running() {
            queue.request_cancel_in_txn(
                &mut wtxn,
                RequestAttemptCancel {
                    id: *spawn_attempt_id,
                    actor: killer_actor.clone(),
                    standing: CancelStanding::PeerAgent,
                    trigger: LandingTrigger::CancelRequest,
                    reason: None,
                    now,
                },
            )?;
        }
        let outcome = queue.intervene_in_txn(
            &mut wtxn,
            InterveneAttempt {
                id: *spawn_attempt_id,
                kind: intervention_kind,
                actor: killer_actor,
                note: None,
                now,
            },
        )?;
        wtxn.commit()?;
        match outcome.effect {
            AttemptInterventionEffect::Cancelled => Ok(KillOutcome::Killed),
            AttemptInterventionEffect::AlreadyCancelled => Ok(KillOutcome::AlreadyTerminal),
            AttemptInterventionEffect::Interrupted => Ok(KillOutcome::CancellationRequested),
            _ => Err(Error::InvariantViolation("kill spawn intervention effect")),
        }
    }
}
