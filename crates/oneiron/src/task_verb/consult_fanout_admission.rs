//! Meter and admit consult fan-outs before any TASK exists.

use super::consult_fanout_store::{
    FrozenInput, POLICY_KEY, StoredFanout, TxnSurface, encode, policy_in, runs_in, save_run,
};
use super::create_validation::{ValidatedTaskCreate, consult_refusal, validate_task_create};
use super::rate_limit::{consume_create_rate_slot, task_actor_ceiling};
use super::wire_decode::task_verb_body_in;
use super::{
    ConsultFanOutPolicy, ConsultFanOutReceipt, ConsultFanOutSpec, ConsultPayload, TaskAssignee,
    TaskCreateRateLimit, TaskCreateSpec, TaskKind, TaskTtl, TasksVerb,
};
use crate::consent::AuthenticatedOwner;
use crate::context_board::{
    AgentsSection, ChildAgentPresence, PeerPresence, render_agents_section,
};
use crate::edit_distance::escalation::{EscalationTrigger, standing_policy_for};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::fanout_auto::{
    FanoutAskClassifier, FanoutAskContext, FanoutAskTrigger, LearningFanoutAutoDecider,
};
use crate::gate::PolicyApprovalCeiling;
use crate::memory::{
    MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INVALID_STATE, Memory, MemoryError, MemoryResult,
    facade_provenance, verify_actor_binding,
};
use crate::outbound_chokepoint::{
    FanoutAdmission, FanoutAutoDecider, FanoutAutoDisposition, FanoutEstimate, FanoutHistory,
    FanoutPlan, FanoutPlanEdge, PeerRateSnapshot, admit_fanout_with_history, fanout_estimate,
    fanout_history_pathology,
};
use crate::unix_seconds_now;
use rmpv::Value;

struct CachedAuto(FanoutAutoDisposition);
impl FanoutAutoDecider for CachedAuto {
    fn decide(&self, _: &FanoutPlan, _: &FanoutEstimate) -> Result<FanoutAutoDisposition> {
        Ok(self.0)
    }
}

impl Memory<'_> {
    /// Fans one durable question out only after governance admits its frozen plan.
    /// A paused result has no TASKs and includes the durable surface and AGENTS rows.
    pub fn fan_out_consults(
        &self,
        input: &ConsultFanOutSpec,
    ) -> MemoryResult<ConsultFanOutReceipt> {
        self.fan_out_consults_with_classifier(input, None)
    }

    /// Host-injected AUTO classifier. Unavailable or uncertain classifiers surface a pause.
    pub fn fan_out_consults_with_classifier(
        &self,
        input: &ConsultFanOutSpec,
        classifier: Option<&dyn FanoutAskClassifier>,
    ) -> MemoryResult<ConsultFanOutReceipt> {
        verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        let now = input.now.unwrap_or_else(unix_seconds_now);
        let correlation = EntityId::now();
        let validated = self.validate_fanout(input, correlation, now)?;
        let policy = {
            let txn = self
                .vault()
                .store
                .env
                .read_txn()
                .map_err(crate::error::Error::from)?;
            policy_in(self.vault(), &txn)?
        };
        let frozen = FrozenInput::new(input, now);
        let plan = frozen.plan(self.actor(), correlation, &policy)?;
        let estimate = fanout_estimate(&plan)?;
        let mut run = StoredFanout {
            correlation: correlation.to_hex(),
            input: frozen,
            plan,
            estimate,
            pause: None,
            dispatched_at: None,
            task_refs: Vec::new(),
            denied: false,
            choice_receipt_ref: None,
        };
        let scope = run.scope();
        let rate_now = unix_seconds_now();
        let has_pathology = {
            let txn = self.vault().store.env.read_txn().map_err(Error::from)?;
            let (edges, rates) = self.fanout_history(&txn, &run, &policy, rate_now)?;
            fanout_history_pathology(
                &run.plan,
                &FanoutHistory {
                    edges: &edges,
                    peer_rates: &rates,
                },
            )?
            .is_some()
        };
        // Classifier IO never holds the writer. A concurrent standing-policy or
        // knob change invalidates the cached answer before minting.
        let standing = standing_policy_for(self.vault(), &scope, EscalationTrigger::Budget).ok();
        let auto = LearningFanoutAutoDecider::new(
            self.vault(),
            FanoutAskContext {
                task_ref: input.question_ref.entity_ref(),
                scope: scope.clone(),
                trigger: FanoutAskTrigger::Budget {
                    magnitude: u64::from(run.estimate.total_count),
                },
                question: input.question_ref.short_ref(),
            },
            classifier,
        )?;
        let disposition = if !has_pathology
            && run.estimate.total_count > policy.approval_threshold
            && policy.mode == super::ConsultFanOutMode::Auto
        {
            auto.decide(&run.plan, &run.estimate)
                .unwrap_or(FanoutAutoDisposition::SurfaceHuman)
        } else {
            FanoutAutoDisposition::SurfaceHuman
        };
        self.with_verified_actor_write_txn(|txn| {
            self.require_fanout_ceiling(txn)?;
            if policy_in(self.vault(), txn)? != policy
                || standing_policy_for(self.vault(), &scope, EscalationTrigger::Budget).ok()
                    != standing
            {
                return Err(consult_refusal(
                    MEMORY_CODE_INVALID_STATE,
                    "fan-out policy changed during admission",
                    "Retry admission under the current policy.",
                ));
            }
            let (edges, rates) = self.fanout_history(txn, &run, &policy, rate_now)?;
            let plan = run.plan.clone();
            let admission = admit_fanout_with_history(
                &plan,
                Some(policy.approval_threshold),
                FanoutHistory {
                    edges: &edges,
                    peer_rates: &rates,
                },
                &CachedAuto(disposition),
                &mut TxnSurface {
                    vault: self.vault(),
                    txn,
                    run: &mut run,
                },
                now.saturating_mul(1000),
            )?;
            match admission {
                FanoutAdmission::Proceed { estimate } => {
                    run.estimate = estimate;
                    self.mint_fanout_in(txn, &validated, input, &mut run, now, rate_now)?;
                }
                FanoutAdmission::Paused {
                    estimate,
                    row,
                    surface_ref,
                } => {
                    if surface_ref != row.row_ref {
                        return Err(Error::InvariantViolation("fan-out surface identity").into());
                    }
                    run.estimate = estimate;
                    run.pause = Some(*row);
                }
            }
            save_run(self.vault(), txn, &run)?;
            run.receipt()
        })
    }

    /// Sets vault-owned approval knobs, never a caller-provided widening selector.
    pub fn set_consult_fanout_policy(
        &self,
        owner: &AuthenticatedOwner,
        policy: &ConsultFanOutPolicy,
    ) -> MemoryResult<()> {
        self.reauthenticate_fanout_owner(owner)?;
        if policy
            .peer_rate
            .as_ref()
            .is_some_and(|rate| rate.window_secs == 0 || rate.spike_at == 0)
        {
            return Err(MemoryError::bad_request(
                "fan-out rate window and threshold must be nonzero",
            ));
        }
        self.vault()
            .memory(owner.actor(), crate::EdgeActorClass::Human)
            .with_verified_actor_write_txn(|txn| {
                self.reauthenticate_fanout_owner(owner)?;
                self.vault()
                    .store
                    .vault_meta
                    .put(txn, POLICY_KEY, &encode(policy)?)?;
                Ok(())
            })
    }

    /// Rebuilds this actor's AGENTS counts from the durable metering rows.
    /// Includes silent runs and parked denials; this projection grants no authority.
    pub fn fan_out_agents_section(
        &self,
        children: &[ChildAgentPresence],
        peers: &[PeerPresence],
    ) -> MemoryResult<AgentsSection> {
        verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        let mut section = render_agents_section(children, peers);
        let txn = self
            .vault()
            .store
            .env
            .read_txn()
            .map_err(crate::error::Error::from)?;
        for run in runs_in(self.vault(), &txn)? {
            if run.plan.actor_ref == self.actor().to_hex() {
                section.rows.extend(run.receipt()?.meter.board_rows);
            }
        }
        Ok(section)
    }

    pub(super) fn reauthenticate_fanout_owner(
        &self,
        owner: &AuthenticatedOwner,
    ) -> MemoryResult<()> {
        self.vault().authenticate_owner(
            owner.actor(),
            owner.principal_ref(),
            true,
            owner.decision_id(),
        )?;
        verify_actor_binding(self.vault(), owner.actor(), crate::EdgeActorClass::Human)
    }

    pub(super) fn require_fanout_ceiling(&self, txn: &heed::RoTxn<'_>) -> MemoryResult<()> {
        if task_actor_ceiling(self.vault(), txn, self.actor(), self.actor_class())?
            != PolicyApprovalCeiling::Auto
        {
            return Err(consult_refusal(
                MEMORY_CODE_FORBIDDEN,
                "fan-out requires an auto-ceiling actor",
                "Create the consults individually so each surfaces its own proposal.",
            ));
        }
        Ok(())
    }

    pub(super) fn validate_fanout(
        &self,
        input: &ConsultFanOutSpec,
        correlation: EntityId,
        now: u64,
    ) -> MemoryResult<Vec<ValidatedTaskCreate>> {
        if input.assignees.is_empty() {
            return Err(MemoryError::bad_request(
                "a fan-out addresses at least one peer actor",
            ));
        }
        let mut peers = input.assignees.clone();
        peers.sort_unstable();
        if peers.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(MemoryError::bad_request(
                "fan-out assignees must be distinct peer actors",
            ));
        }
        peers
            .into_iter()
            .map(|actor_ref| {
                validate_task_create(
                    self.vault(),
                    &TaskCreateSpec::new(Value::Nil, input.label.clone(), None, Some(now))
                        .with_kind(TaskKind::Consult)
                        .with_consult(ConsultPayload::question(
                            input.question_ref,
                            input.context_refs.clone(),
                            correlation,
                        ))
                        .with_assignee(TaskAssignee::Peer { actor_ref })
                        .with_ttl(TaskTtl::at(input.deadline_at)),
                    now,
                )
            })
            .collect()
    }

    pub(super) fn mint_fanout_in(
        &self,
        txn: &mut heed::RwTxn<'_>,
        entries: &[ValidatedTaskCreate],
        input: &ConsultFanOutSpec,
        run: &mut StoredFanout,
        now: u64,
        rate_now: u64,
    ) -> MemoryResult<()> {
        self.require_fanout_ceiling(txn)?;
        // The generic create quota meters requests, not the number of peers
        // in an admitted request. Charging N slots made the default 10-slot
        // quota an accidental fan-out cap below the 25-peer approval threshold.
        if !consume_create_rate_slot(
            self.vault(),
            txn,
            self.actor(),
            rate_now,
            TaskCreateRateLimit::default(),
        )? {
            return Err(consult_refusal(
                MEMORY_CODE_INVALID_STATE,
                "fan-out exceeds the actor's create quota",
                "Retry the whole fan-out in the next window.",
            ));
        }
        let provenance = facade_provenance(TasksVerb::Create.as_str());
        for entry in entries {
            run.task_refs.push(
                self.mint_task_in_txn(
                    txn,
                    entry,
                    input.label.clone(),
                    self.actor(),
                    &provenance,
                    now,
                )?
                .to_hex(),
            );
        }
        run.dispatched_at = Some(rate_now);
        Ok(())
    }

    fn fanout_history(
        &self,
        txn: &heed::RoTxn<'_>,
        run: &StoredFanout,
        policy: &ConsultFanOutPolicy,
        now: u64,
    ) -> Result<(Vec<FanoutPlanEdge>, Vec<PeerRateSnapshot>)> {
        let mut edges = Vec::new();
        let mut counts = std::collections::BTreeMap::<String, u32>::new();
        // Consults created individually or replayed from peers also close
        // cycles. Stream the existing TASK index; do not reconstruct a second
        // task graph from only this facade's historical runs.
        for entry in self
            .vault()
            .store
            .type_index
            .prefix_iter(txn, &[crate::registry::ENTITY_TYPE_TASK])?
        {
            let (key, _) = entry?;
            let task = crate::vault::entity_id_from_type_index_key(&key)?;
            if let Some(body) = task_verb_body_in(self.vault(), txn, task)?
                && body.task_kind() == TaskKind::Consult
                && let Some(TaskAssignee::Peer { actor_ref }) = body.assignee
                && body.terminal().is_none()
                && body.settled_ladder_disposition().is_none()
                && body.ttl.is_some_and(|ttl| ttl.deadline_at > now)
            {
                edges.push(FanoutPlanEdge {
                    from_peer_ref: body.owner_ref,
                    to_peer_ref: actor_ref.to_hex(),
                    count: 1,
                });
            }
        }
        if let Some(rate) = &policy.peer_rate {
            // Engine-stamped dispatch times, never the caller's task clock.
            for prior in runs_in(self.vault(), txn)? {
                if prior
                    .dispatched_at
                    .is_none_or(|at| at.saturating_add(rate.window_secs) <= now)
                {
                    continue;
                }
                for peer in prior.input.assignees {
                    let count = counts.entry(peer).or_default();
                    *count = count
                        .checked_add(1)
                        .ok_or(Error::ArithmeticOverflow("fan-out rate count"))?;
                }
            }
        }
        let rates = policy.peer_rate.as_ref().map_or_else(Vec::new, |rate| {
            run.input
                .assignees
                .iter()
                .map(|peer| PeerRateSnapshot {
                    peer_ref: peer.clone(),
                    window_secs: rate.window_secs,
                    observed_count: counts.get(peer).copied().unwrap_or(0),
                    spike_at: rate.spike_at,
                })
                .collect()
        });
        Ok((edges, rates))
    }
}
