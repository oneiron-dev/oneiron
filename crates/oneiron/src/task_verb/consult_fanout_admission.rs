//! Meter and admit consult fan-outs before any TASK exists.

use super::consult_fanout_store::{
    FrozenInput, StoredFanout, TxnSurface, policy_in, runs_in, save_run,
};
use super::create_validation::{ValidatedTaskCreate, consult_refusal, validate_task_create};
use super::rate_limit::{consume_create_rate_slot, task_actor_ceiling};
use super::wire_decode::task_verb_body_in;
use super::{
    ConsultFanOutPolicy, ConsultFanOutReceipt, ConsultFanOutScope, ConsultFanOutSpec,
    ConsultPayload, TaskAssignee, TaskCreateSpec, TaskKind, TaskTtl,
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
use crate::gate::fanout_policy::{FanoutControls, FanoutScopedRow, valid_rates};
use crate::gate::{
    POLICY_CONSULT_FANOUT_APPROVAL_THRESHOLD_KEY, POLICY_CONSULT_FANOUT_CONTROLS_KEY,
    POLICY_CONSULT_FANOUT_SCOPE_ROWS_KEY, PolicyApprovalCeiling,
};
use crate::memory::{
    MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INVALID_STATE, Memory, MemoryError, MemoryPolicyDenial,
    MemoryPolicyExceptionProposal, MemoryResult, facade_provenance, verify_actor_binding,
};
use crate::outbound_chokepoint::{
    FanoutAdmission, FanoutAutoDecider, FanoutAutoDisposition, FanoutEstimate, FanoutHistory,
    FanoutPlan, FanoutPlanEdge, PeerRateSnapshot, admit_fanout_with_history, fanout_estimate,
    fanout_history_pathology,
};
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_POLICY_MANIFEST;
use crate::task_verb::sdk::AgentVerb;
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

    /// Admit a counted consult plan under a named preset. Repeated peer IDs
    /// represent separate consult TASKs; the estimate groups them by peer.
    pub fn fan_out_counted_consults(
        &self,
        input: &ConsultFanOutSpec,
        preset: &str,
    ) -> MemoryResult<ConsultFanOutReceipt> {
        self.fan_out_counted_consults_with_classifier(input, preset, None)
    }

    /// Admit a counted preset plan with the host's existing AUTO classifier.
    /// An absent or failing classifier still pauses rather than allowing work.
    pub fn fan_out_counted_consults_with_classifier(
        &self,
        input: &ConsultFanOutSpec,
        preset: &str,
        classifier: Option<&dyn FanoutAskClassifier>,
    ) -> MemoryResult<ConsultFanOutReceipt> {
        if preset.is_empty() || preset.trim() != preset {
            return Err(MemoryError::bad_request("fan-out preset must be canonical"));
        }
        self.fan_out_consults_impl(
            input,
            classifier,
            true,
            Some(preset),
            ConsultFanOutScope::default(),
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
        classifier: Option<&dyn FanoutAskClassifier>,
    ) -> MemoryResult<ConsultFanOutReceipt> {
        // A non-vault scope can carry a holder override. The caller cannot
        // select such a scope as an unauthenticated widening selector.
        self.reauthenticate_fanout_owner(owner)?;
        if preset.is_empty() || preset.trim() != preset || !scope.is_valid() {
            return Err(MemoryError::bad_request(
                "fan-out preset or policy scope must be canonical",
            ));
        }
        self.fan_out_consults_impl(input, classifier, true, Some(preset), scope.clone())
    }

    /// Meter a counted plan before admission. This does not write a TASK,
    /// run a classifier, or persist a pause.
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
        Ok(super::ConsultFanOutEstimate {
            total_count: estimate.total_count,
            per_peer: estimate.per_peer,
        })
    }

    /// Host-injected AUTO classifier. Unavailable or uncertain classifiers surface a pause.
    pub fn fan_out_consults_with_classifier(
        &self,
        input: &ConsultFanOutSpec,
        classifier: Option<&dyn FanoutAskClassifier>,
    ) -> MemoryResult<ConsultFanOutReceipt> {
        self.fan_out_consults_impl(
            input,
            classifier,
            false,
            None,
            ConsultFanOutScope::default(),
        )
    }

    fn fan_out_consults_impl(
        &self,
        input: &ConsultFanOutSpec,
        classifier: Option<&dyn FanoutAskClassifier>,
        allow_repeated_peers: bool,
        preset: Option<&str>,
        policy_scope: ConsultFanOutScope,
    ) -> MemoryResult<ConsultFanOutReceipt> {
        verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        let now = input.now.unwrap_or_else(|| self.vault().now_recorded_at());
        let correlation = self.vault().new_entity_id()?;
        let validated = self.validate_fanout(input, correlation, now, allow_repeated_peers)?;
        let policy = {
            let txn = self
                .vault()
                .store
                .env
                .read_txn()
                .map_err(crate::error::Error::from)?;
            policy_in(self.vault(), &txn, &policy_scope)?.policy
        };
        let frozen = FrozenInput::new(input, now, preset, policy_scope);
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
        // Classifier IO never holds the writer. A concurrent standing-policy or
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
            if policy_in(self.vault(), txn, &run.input.policy_scope)?.policy != policy
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

    /// Owner-authenticated vault row: threshold, mode, detector and request
    /// quota all live in the same manifest transaction.
    pub fn set_consult_fanout_policy(
        &self,
        owner: &AuthenticatedOwner,
        policy: &ConsultFanOutPolicy,
    ) -> MemoryResult<()> {
        self.reauthenticate_fanout_owner(owner)?;
        if !valid_rates(policy.create_rate, policy.peer_rate.as_ref()) {
            return Err(MemoryError::bad_request(
                "fan-out policy rate and quota must be nonzero",
            ));
        }
        self.vault()
            .memory(owner.actor(), crate::EdgeActorClass::Human)
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
        self.reauthenticate_fanout_owner(owner)?;
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
            holder_ref: holder_override.then(|| owner.actor().to_hex()),
        };
        self.vault()
            .memory(owner.actor(), crate::EdgeActorClass::Human)
            .with_verified_actor_write_txn(|txn| {
                self.reauthenticate_fanout_owner(owner)?;
                rewrite_fanout_manifest(self.vault(), owner, txn, |entries| {
                    let position =
                        manifest_row_position(entries, POLICY_CONSULT_FANOUT_SCOPE_ROWS_KEY)?;
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
        rate_now: u64,
    ) -> MemoryResult<()> {
        self.require_fanout_ceiling(txn)?;
        // The generic create quota meters requests, not the number of peers
        // in an admitted request. Charging N slots made the default 10-slot
        // quota an accidental fan-out cap below the 25-peer approval threshold.
        let governed = policy_in(self.vault(), txn, &run.input.policy_scope)?;
        if !consume_create_rate_slot(
            self.vault(),
            txn,
            self.actor(),
            rate_now,
            governed.policy.create_rate,
        )? {
            let trace = governed.quota_trace;
            let mut refusal = consult_refusal(
                MEMORY_CODE_INVALID_STATE,
                &format!(
                    "fan-out create quota refused at level={} row={} role={}",
                    trace.level, trace.row_ref, trace.role
                ),
                &format!(
                    "ask_for_exception:fanout.create_rate:level={}:row={}:role={}",
                    trace.level, trace.row_ref, trace.role
                ),
            );
            refusal.policy_denial = Some(Box::new(MemoryPolicyDenial {
                level: trace.level.to_owned(),
                row_ref: trace.row_ref.clone(),
                role: trace.role.to_owned(),
                exception_proposal: MemoryPolicyExceptionProposal {
                    action: "ask_for_exception:fanout.create_rate".to_owned(),
                    row_ref: trace.row_ref,
                    required_role: "holder".to_owned(),
                },
            }));
            return Err(refusal);
        }
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

fn replace_manifest_row(
    entries: &mut [(Value, Value)],
    key: &str,
    value: Value,
) -> MemoryResult<()> {
    let position = manifest_row_position(entries, key)?;
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
