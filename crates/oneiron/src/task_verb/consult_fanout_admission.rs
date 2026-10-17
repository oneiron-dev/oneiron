//! Meter, state and admit consult fan-outs before any TASK exists.
//!
//! Every fan-out states its counts, expected spend and cap before minting
//! (OF-393). The approval mode gates every fan-out at any width: `manual`
//! pauses, `auto` mints on the decider's allow and otherwise pauses for the
//! escalated role, `full-access` mints. The threshold only marks the
//! exceptional-width check, which never holds: it rides the pause row of a
//! held run and the statement of a minted one.

use super::consult_fanout_store::{
    FrozenInput, StoredFanout, TxnSurface, policy_in, runs_in, save_run,
};
use super::create_validation::{ValidatedTaskCreate, consult_refusal, validate_task_create};
use super::rate_limit::task_actor_ceiling;
use super::wire_decode::task_verb_body_in;
use super::{
    ConsultFanOutPolicy, ConsultFanOutReceipt, ConsultFanOutScope, ConsultFanOutSpec,
    ConsultPayload, TaskAssignee, TaskCreateSpec, TaskKind, TaskTtl,
};
use crate::agent_dispatch::{
    AGENT_DISPATCH_ATTEMPT_TYPE, AgentDispatcher, FanoutCaller, FanoutStatement, FanoutWork,
    WidthCheckClass, agent_dispatch_actor, decode_agent_dispatch_input,
};
use crate::consent::AuthenticatedOwner;
use crate::edit_distance::escalation::{EscalationTrigger, standing_policy_for};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::fanout_auto::{
    FanoutAskContext, FanoutAskTrigger, FanoutDecisions, LearningFanoutAutoDecider,
};
use crate::gate::fanout_policy::{FanoutControls, FanoutScopedRow, valid_rates};
use crate::gate::{
    POLICY_CONSULT_FANOUT_APPROVAL_THRESHOLD_KEY, POLICY_CONSULT_FANOUT_CONTROLS_KEY,
    POLICY_CONSULT_FANOUT_SCOPE_ROWS_KEY, PolicyApprovalCeiling,
};
use crate::memory::{
    MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INVALID_STATE, Memory, MemoryError, MemoryResult,
    facade_provenance, verify_actor_binding,
};
use crate::outbound_chokepoint::{
    FanoutAdmission, FanoutAutoDecider, FanoutAutoDisposition, FanoutEstimate, FanoutHistory,
    FanoutPlan, FanoutPlanEdge, PeerRateSnapshot, admit_fanout_with_history, fanout_estimate,
    fanout_history_pathology,
};
use crate::own_rate::{OwnRate, OwnRateKind, count_in_txn};
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_POLICY_MANIFEST;
use crate::task_verb::sdk::AgentVerb;
use rmpv::Value;

/// An AUTO answer taken outside the writer, replayed inside it.
pub(super) struct CachedAuto(pub(super) FanoutAutoDisposition);
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

    /// Admit a counted consult plan under a named preset. Repeated peer IDs
    /// represent separate consult TASKs; the estimate groups them by peer.
    pub fn fan_out_counted_consults(
        &self,
        input: &ConsultFanOutSpec,
        preset: &str,
    ) -> MemoryResult<ConsultFanOutReceipt> {
        self.fan_out_counted_consults_with_classifier(input, preset, None)
    }

    /// Admit a counted preset plan with the host's AUTO decisions.
    /// Absent decisions or an abstaining ladder still pause rather than allowing work.
    pub fn fan_out_counted_consults_with_classifier(
        &self,
        input: &ConsultFanOutSpec,
        preset: &str,
        decisions: Option<&FanoutDecisions<'_>>,
    ) -> MemoryResult<ConsultFanOutReceipt> {
        if preset.is_empty() || preset.trim() != preset {
            return Err(MemoryError::bad_request("fan-out preset must be canonical"));
        }
        self.fan_out_consults_impl(
            input,
            decisions,
            true,
            Some(preset),
            ConsultFanOutScope::default(),
            None,
        )
    }

    /// A counted preset fan-out by an agent the host runs: the statement
    /// states the hard cap `caller`'s own work runs under. The host binds
    /// `caller` from the agent's authenticated dispatch; a parent attempt that
    /// is not this actor's own agent dispatch is refused.
    pub fn fan_out_counted_consults_for_caller(
        &self,
        input: &ConsultFanOutSpec,
        preset: &str,
        decisions: Option<&FanoutDecisions<'_>>,
        caller: &FanoutCaller,
    ) -> MemoryResult<ConsultFanOutReceipt> {
        if preset.is_empty() || preset.trim() != preset {
            return Err(MemoryError::bad_request("fan-out preset must be canonical"));
        }
        self.verify_fanout_caller(caller)?;
        self.fan_out_consults_impl(
            input,
            decisions,
            true,
            Some(preset),
            ConsultFanOutScope::default(),
            Some(caller),
        )
    }

    /// Submit counted peer consults under a frozen policy scope. Each supplied
    /// level names its parent, and every policy lookup uses the same snapshot
    /// and authenticated manifest resolution as the vault-wide door.
    pub fn fan_out_counted_consults_in_scope(
        &self,
        input: &ConsultFanOutSpec,
        preset: &str,
        scope: &ConsultFanOutScope,
        owner: &AuthenticatedOwner,
        decisions: Option<&FanoutDecisions<'_>>,
    ) -> MemoryResult<ConsultFanOutReceipt> {
        // A non-vault scope can carry a holder override. The caller cannot
        // select such a scope as an unauthenticated widening selector.
        self.reauthenticate_fanout_owner(owner)?;
        if preset.is_empty() || preset.trim() != preset || !scope.is_valid() {
            return Err(MemoryError::bad_request(
                "fan-out preset or policy scope must be canonical",
            ));
        }
        self.fan_out_consults_impl(input, decisions, true, Some(preset), scope.clone(), None)
    }

    /// Meter and state a counted plan before admission. This does not write a
    /// TASK, ask the decision ladder, or persist a pause or a question.
    pub fn estimate_counted_consults(
        &self,
        input: &ConsultFanOutSpec,
        preset: &str,
    ) -> MemoryResult<super::ConsultFanOutEstimate> {
        verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        if preset.is_empty() || preset.trim() != preset {
            return Err(MemoryError::bad_request("fan-out preset must be canonical"));
        }
        let now = input.now.unwrap_or_else(|| self.vault().now_recorded_at());
        let correlation = self.vault().new_entity_id()?;
        self.validate_fanout(input, correlation, now, true)?;
        let txn = self.vault().store.env.read_txn().map_err(Error::from)?;
        let scope = ConsultFanOutScope::default();
        let policy = policy_in(self.vault(), &txn, &scope)?.policy;
        let plan = FrozenInput::new(input, now, Some(preset), scope).plan(
            self.actor(),
            correlation,
            &policy,
        )?;
        let estimate = fanout_estimate(&plan)?;
        let statement = self.consult_statement(&txn, input, None, now)?;
        Ok(super::ConsultFanOutEstimate {
            total_count: estimate.total_count,
            per_peer: estimate.per_peer,
            statement,
        })
    }

    /// The host's AUTO decisions. Absent decisions or an uncertain answer surface a pause.
    pub fn fan_out_consults_with_classifier(
        &self,
        input: &ConsultFanOutSpec,
        decisions: Option<&FanoutDecisions<'_>>,
    ) -> MemoryResult<ConsultFanOutReceipt> {
        self.fan_out_consults_impl(
            input,
            decisions,
            false,
            None,
            ConsultFanOutScope::default(),
            None,
        )
    }

    /// `caller` is host-bound context; every public door without it states
    /// no cap.
    fn fan_out_consults_impl(
        &self,
        input: &ConsultFanOutSpec,
        decisions: Option<&FanoutDecisions<'_>>,
        allow_repeated_peers: bool,
        preset: Option<&str>,
        policy_scope: ConsultFanOutScope,
        caller: Option<&FanoutCaller>,
    ) -> MemoryResult<ConsultFanOutReceipt> {
        verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        let now = input.now.unwrap_or_else(|| self.vault().now_recorded_at());
        let correlation = self.vault().new_entity_id()?;
        let validated = self.validate_fanout(input, correlation, now, allow_repeated_peers)?;
        // The plan is frozen and stated in one snapshot, before any TASK.
        let (governed, statement) = {
            let txn = self
                .vault()
                .store
                .env
                .read_txn()
                .map_err(crate::error::Error::from)?;
            (
                policy_in(self.vault(), &txn, &policy_scope)?,
                self.consult_statement(&txn, input, caller, now)?,
            )
        };
        let policy = governed.policy.clone();
        let frozen = FrozenInput::new(input, now, preset, policy_scope);
        let plan = frozen.plan(self.actor(), correlation, &policy)?;
        let estimate = fanout_estimate(&plan)?;
        let mut run = StoredFanout {
            correlation: correlation.to_hex(),
            input: frozen,
            plan,
            estimate,
            statement,
            pause: None,
            check_row: None,
            dispatched_at: None,
            task_refs: Vec::new(),
            denied: false,
            choice_receipt_ref: None,
            shipped_policy_rows: governed.shipped_rows.clone(),
        };
        let scope = run.scope();
        let rate_now = self.vault().now_recorded_at();
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
        // Decision IO never holds the writer. A concurrent standing-policy or
        // knob change invalidates the cached answer before minting.
        let standing = standing_policy_for(self.vault(), &scope, EscalationTrigger::Budget)?;
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
            decisions,
        )?;
        // AUTO rules on every auto fan-out, whatever its width.
        let disposition = if !has_pathology && policy.mode == super::ConsultFanOutMode::Auto {
            auto.decide(&run.plan, &run.estimate)
                .unwrap_or(FanoutAutoDisposition::SurfaceHuman)
        } else {
            FanoutAutoDisposition::SurfaceHuman
        };
        // An accepted standing row answers alone when it exists, so an Allow
        // beside one stood on it.
        let clearance = standing
            .as_ref()
            .filter(|_| disposition == FanoutAutoDisposition::Allow)
            .map(|row| row.row_ref.to_hex());
        self.with_verified_actor_write_txn(|txn| {
            self.require_fanout_ceiling(txn)?;
            if policy_in(self.vault(), txn, &run.input.policy_scope)? != governed
                || standing_policy_for(self.vault(), &scope, EscalationTrigger::Budget)? != standing
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
                    clearance: clearance.clone(),
                },
                now.saturating_mul(1000),
            )?;
            match admission {
                // Above the threshold the sink has already recorded the
                // classified width check; the run mints either way.
                FanoutAdmission::Proceed { estimate } => {
                    run.estimate = estimate;
                    self.mint_fanout_in(txn, &validated, input, &mut run, now)?;
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
                    // A held run asks its width check on its own pause row.
                    let threshold = u64::from(policy.approval_threshold);
                    if run.statement.crosses(threshold) {
                        run.statement.raise_width_check(
                            threshold,
                            WidthCheckClass::Asked {
                                row_ref: row.row_ref.clone(),
                            },
                        );
                    }
                    let mut row = *row;
                    row.statement = Some(run.statement.clone());
                    run.pause = Some(row);
                }
            }
            save_run(self.vault(), txn, &run)?;
            run.receipt()
        })
    }

    /// Owner-authenticated vault row: threshold, mode, detector and request
    /// quota all live in the same manifest transaction.
    pub fn set_consult_fanout_policy(
        &self,
        owner: &AuthenticatedOwner,
        policy: &ConsultFanOutPolicy,
    ) -> MemoryResult<()> {
        let actor = self.reauthenticate_fanout_owner(owner)?;
        if !valid_rates(policy.create_rate, policy.peer_rate.as_ref()) {
            return Err(MemoryError::bad_request(
                "fan-out policy rate and quota must be nonzero",
            ));
        }
        self.vault()
            .memory(actor, crate::EdgeActorClass::Human)
            .with_verified_actor_write_txn(|txn| {
                self.reauthenticate_fanout_owner(owner)?;
                rewrite_fanout_manifest(self.vault(), owner, txn, |entries| {
                    replace_manifest_row(
                        entries,
                        POLICY_CONSULT_FANOUT_APPROVAL_THRESHOLD_KEY,
                        Value::from(u64::from(policy.approval_threshold)),
                    )?;
                    let controls = FanoutControls {
                        mode: policy.mode,
                        peer_rate: policy.peer_rate.clone(),
                        create_rate: policy.create_rate,
                    };
                    replace_manifest_row(
                        entries,
                        POLICY_CONSULT_FANOUT_CONTROLS_KEY,
                        manifest_value(&controls)?,
                    )
                })
            })
    }

    /// A scoped holder may author one upward override, bounded by the vault
    /// row. Other scoped rows narrow their parent as the precedence row says.
    pub fn set_consult_fanout_scope_policy(
        &self,
        owner: &AuthenticatedOwner,
        scope: &ConsultFanOutScope,
        policy: &ConsultFanOutPolicy,
        holder_override: bool,
    ) -> MemoryResult<()> {
        let actor = self.reauthenticate_fanout_owner(owner)?;
        if !scope.is_valid()
            || scope.level() == 0
            || !valid_rates(policy.create_rate, policy.peer_rate.as_ref())
        {
            return Err(MemoryError::bad_request(
                "scoped fan-out policy shape invalid",
            ));
        }
        let row_ref = format!(
            "fanout.scope.{}.{}.{}.{}",
            scope.level(),
            scope.project_ref.as_deref().unwrap_or("_"),
            scope.subproject_ref.as_deref().unwrap_or("_"),
            scope.thread_ref.as_deref().unwrap_or("_")
        );
        let row = FanoutScopedRow {
            row_ref: row_ref.clone(),
            scope: scope.clone(),
            policy: policy.clone(),
            holder_ref: holder_override.then(|| actor.to_hex()),
        };
        self.vault()
            .memory(actor, crate::EdgeActorClass::Human)
            .with_verified_actor_write_txn(|txn| {
                self.reauthenticate_fanout_owner(owner)?;
                rewrite_fanout_manifest(self.vault(), owner, txn, |entries| {
                    let position = manifest_row_or_insert(
                        entries,
                        POLICY_CONSULT_FANOUT_SCOPE_ROWS_KEY,
                        Value::Array(Vec::new()),
                    )?;
                    let Value::Array(ref mut rows) = entries[position].1 else {
                        return Err(MemoryError::bad_request("fan-out scope rows malformed"));
                    };
                    rows.retain(|value| {
                        value.as_map().is_none_or(|fields| {
                            !fields.iter().any(|(key, val)| {
                                key.as_str() == Some("row_ref") && val.as_str() == Some(&row_ref)
                            })
                        })
                    });
                    rows.push(manifest_value(&row)?);
                    Ok(())
                })
            })
    }

    /// Effective manifest row at the vault level.
    pub fn get_consult_fanout_policy(&self) -> MemoryResult<ConsultFanOutPolicy> {
        self.get_consult_fanout_policy_for(&ConsultFanOutScope::default())
    }

    /// Effective manifest policy for a validated nested request scope.
    pub fn get_consult_fanout_policy_for(
        &self,
        scope: &ConsultFanOutScope,
    ) -> MemoryResult<ConsultFanOutPolicy> {
        verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        let txn = self.vault().store.env.read_txn().map_err(Error::from)?;
        Ok(policy_in(self.vault(), &txn, scope)?.policy)
    }

    /// This actor's consult fan-out meter rows, rebuilt from the durable
    /// metering rows. Includes silent runs and parked denials; this
    /// projection grants no authority.
    pub fn fan_out_meter_rows(&self) -> MemoryResult<Vec<super::FanoutMeterRow>> {
        verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        let txn = self
            .vault()
            .store
            .env
            .read_txn()
            .map_err(crate::error::Error::from)?;
        let mut rows = Vec::new();
        for run in runs_in(self.vault(), &txn)? {
            if run.plan.actor_ref == self.actor().to_hex() {
                rows.extend(run.receipt()?.meter.board_rows);
            }
        }
        Ok(rows)
    }

    /// The statement of one consult fan-out: every consult a peer delivery,
    /// repeats included, under the caller's cap or none.
    fn consult_statement(
        &self,
        txn: &heed::RoTxn<'_>,
        input: &ConsultFanOutSpec,
        caller: Option<&FanoutCaller>,
        now: u64,
    ) -> MemoryResult<FanoutStatement> {
        let work: Vec<_> = input
            .assignees
            .iter()
            .map(|peer| FanoutWork::PeerConsult { peer: *peer })
            .collect();
        let root = FanoutCaller::default();
        Ok(AgentDispatcher::new(self.vault()).plan_fanout_in_txn(
            txn,
            caller.unwrap_or(&root),
            &work,
            now,
        )?)
    }

    /// A caller's parent attempt must be this actor's own agent dispatch, so
    /// no guest-supplied id can state another agent's cap.
    fn verify_fanout_caller(&self, caller: &FanoutCaller) -> MemoryResult<()> {
        let Some(parent) = caller.parent_attempt else {
            return Ok(());
        };
        let status = crate::dreamer_runner::DreamerRunnerStore::new(self.vault()).status(parent)?;
        let own = match status {
            Some(status) if status.payload.attempt_type == AGENT_DISPATCH_ATTEMPT_TYPE => {
                agent_dispatch_actor(&decode_agent_dispatch_input(&status.payload.input)?)?
                    == crate::WriteActor::new(self.actor(), self.actor_class())
            }
            _ => false,
        };
        if !own {
            return Err(consult_refusal(
                MEMORY_CODE_FORBIDDEN,
                "fan-out caller attempt is not this actor's own dispatch",
                "Bind the caller from the running agent's own attempt.",
            ));
        }
        Ok(())
    }

    pub(super) fn reauthenticate_fanout_owner(
        &self,
        owner: &AuthenticatedOwner,
    ) -> MemoryResult<EntityId> {
        let actor = owner.revalidate(self.vault())?;
        verify_actor_binding(self.vault(), actor, crate::EdgeActorClass::Human)?;
        Ok(actor)
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
        allow_repeated_peers: bool,
    ) -> MemoryResult<Vec<ValidatedTaskCreate>> {
        if input.assignees.is_empty() {
            return Err(MemoryError::bad_request(
                "a fan-out addresses at least one peer actor",
            ));
        }
        let mut peers = input.assignees.clone();
        peers.sort_unstable();
        if !allow_repeated_peers && peers.windows(2).any(|pair| pair[0] == pair[1]) {
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
    ) -> MemoryResult<()> {
        self.require_fanout_ceiling(txn)?;
        // Counted and stamped at the engine's clock as it mints, not as the
        // admission began: a decision or an approval can hold a request
        // across a window boundary (review r2, Astra F1).
        let dispatched_at = self.vault().now_recorded_at();
        // A fan-out request is counted, never refused for rate (OF-520). The
        // vault's create_rate row is the bound: the first request past it in
        // a window leaves one typed check, and every request lands. One count
        // per request, not per peer in it, in one window against one bound
        // whatever scope the request runs in: a scoped row of another duration
        // or bound would reset the count or ask again (review r1, Sol F1, F2).
        let rate = policy_in(self.vault(), txn, &ConsultFanOutScope::default())?
            .policy
            .create_rate;
        count_in_txn(
            &self.vault().store,
            txn,
            OwnRateKind::ConsultFanout,
            self.actor(),
            dispatched_at,
            OwnRate {
                threshold: rate.limit as u64,
                window_seconds: rate.window_seconds,
            },
        )?;
        let provenance = facade_provenance(AgentVerb::TasksCreate.as_str());
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
        run.dispatched_at = Some(dispatched_at);
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
        for entry in EntityStoreRead::port_entity_ids_by_type(
            &self.vault().store,
            txn,
            crate::registry::ENTITY_TYPE_TASK,
            None,
        )? {
            let task = entry?;
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
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
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

fn manifest_row_position(entries: &[(Value, Value)], key: &str) -> MemoryResult<usize> {
    let positions: Vec<_> = entries
        .iter()
        .enumerate()
        .filter_map(|(index, (name, _))| (name.as_str() == Some(key)).then_some(index))
        .collect();
    let [position] = positions.as_slice() else {
        return Err(MemoryError::bad_request(
            "fan-out manifest row missing or duplicated",
        ));
    };
    Ok(*position)
}

/// A vault seeded before a fan-out row existed reads the shipped row; the
/// owner's first write maps it by adding the row. A duplicate still refuses.
fn manifest_row_or_insert(
    entries: &mut Vec<(Value, Value)>,
    key: &str,
    value: Value,
) -> MemoryResult<usize> {
    if entries.iter().any(|(name, _)| name.as_str() == Some(key)) {
        return manifest_row_position(entries, key);
    }
    entries.push((Value::from(key), value));
    Ok(entries.len() - 1)
}

fn replace_manifest_row(
    entries: &mut Vec<(Value, Value)>,
    key: &str,
    value: Value,
) -> MemoryResult<()> {
    let position = manifest_row_or_insert(entries, key, Value::Nil)?;
    entries[position].1 = value;
    Ok(())
}

fn rewrite_fanout_manifest(
    vault: &crate::Vault,
    owner: &AuthenticatedOwner,
    txn: &mut heed::RwTxn<'_>,
    edit: impl FnOnce(&mut Vec<(Value, Value)>) -> MemoryResult<()>,
) -> MemoryResult<()> {
    let id = crate::gate::default_policy_manifest_id()?;
    let row = vault
        .store
        .port_entity_record(txn, &id)?
        .ok_or_else(|| MemoryError::bad_request("default policy manifest missing"))?;
    if row.entity_type != ENTITY_TYPE_POLICY_MANIFEST {
        return Err(MemoryError::bad_request("default policy manifest mistyped"));
    }
    let mut cursor = std::io::Cursor::new(row.body.as_slice());
    let mut manifest = rmpv::decode::read_value(&mut cursor)
        .map_err(|_| MemoryError::bad_request("default policy manifest malformed"))?;
    if cursor.position() != row.body.len() as u64 {
        return Err(MemoryError::bad_request(
            "default policy manifest trailing data",
        ));
    }
    let Value::Map(ref mut entries) = manifest else {
        return Err(MemoryError::bad_request(
            "default policy manifest malformed",
        ));
    };
    edit(entries)?;
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &manifest)
        .map_err(|_| MemoryError::bad_request("cannot encode policy manifest"))?;
    vault.write_owner_policy_manifest_in_txn(owner, txn, id, bytes, vault.now_recorded_at())?;
    Ok(())
}

fn manifest_value(value: &impl serde::Serialize) -> MemoryResult<Value> {
    let bytes = rmp_serde::to_vec_named(value)
        .map_err(|_| MemoryError::bad_request("fan-out manifest row encode"))?;
    rmpv::decode::read_value(&mut bytes.as_slice())
        .map_err(|_| MemoryError::bad_request("fan-out manifest row decode"))
}
