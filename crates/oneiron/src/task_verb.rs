//! Typed, actor-bound verbs over the Context Board TASKS section.

use std::collections::BTreeMap;
use std::sync::atomic::Ordering;

use rmpv::Value;

use crate::agent_dispatch::{
    AGENT_DISPATCH_ATTEMPT_TYPE, agent_dispatch_actor, decode_agent_dispatch_input,
};
use crate::attempt_queue::{
    AttemptId, AttemptInterventionEffect, AttemptInterventionKind, AttemptQueue, AttemptState,
    EnqueueAttempt, EnqueueOutcome, InterveneAttempt,
};
use crate::batch::{
    ApplyOpsGateMode, BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader,
    apply_ops_with_gate_mode,
};
use crate::claim::{ClaimApprovalStatus, ClaimSource, ClaimSubject};
use crate::context_board::{
    JobPresence, TaskBoardStatus, TaskIntentPresence, TasksSection, ack_task_in_txn,
    cancel_task_in_txn, expand_task, fold_up_status, render_tasks_section, task_is_acked,
    task_is_cancelled,
};
use crate::dreamer_runner::{DREAMER_RUNNER_ATTEMPT_KIND, decode_dreamer_attempt_payload};
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::facade::{
    BRIDGE_OUTBOUND_ATTEMPT_KIND, FacadeError, FacadeResult, MemoryFacade, facade_provenance,
    verify_actor_binding,
};
use crate::gate::{
    ExternalEffectGateInput, ExternalEffectPolicyRisk, GateActor, GateOutcome,
    GateProvenanceHandles, PolicyApprovalCeiling, check_external_effect_policy,
    dispatched_agent_effective_ceiling, resolve_policy_manifest,
};
use crate::habit::TaskRole;
use crate::registry::ENTITY_TYPE_TASK;
use crate::run_tree::{RunTreeAdapter, RunTreeNode, RunTreeStatus};
use crate::temporal::TimeRange;
use crate::write_envelope::{ClaimCandidate, WriteActor, WriteEnvelope, WriteProvenance};
use crate::{Vault, unix_seconds_now};

const TASK_VERB_BODY_SCHEMA_VERSION: u8 = 1;
const TASK_VERB_BODY_SUBKIND: &str = "typed";
const TASK_REALIZE_ATTEMPT_KIND: &str = "tasks.realize";
const TASK_CREATE_RATE_KEY_PREFIX: &[u8] = b"tasks.create.rate.v1\0";
const TASK_CREATE_OWNER_KEY_PREFIX: &[u8] = b"tasks.create.owner.v1\0";
const TASK_CREATE_PROPOSAL_PREDICATE: &str = "tasks.create";
const TASK_CANCEL_PROPOSAL_PREDICATE: &str = "tasks.cancel";
const TASK_CANCEL_GATE_CHANNEL: &str = "tasks";
const TASK_GATE_RECEIPT_SCAN_LIMIT: usize = 512;

/// Exact agent-visible TASKS verb family in protocol sort order.
pub const TASKS_VERBS: [&str; 5] = [
    "tasks.ack",
    "tasks.cancel",
    "tasks.check",
    "tasks.create",
    "tasks.expand",
];

/// The five typed verbs available over the TASKS section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TasksVerb {
    Ack,
    Cancel,
    Check,
    Create,
    Expand,
}

impl TasksVerb {
    /// All typed TASKS verbs in protocol sort order.
    pub const ALL: [Self; 5] = [
        Self::Ack,
        Self::Cancel,
        Self::Check,
        Self::Create,
        Self::Expand,
    ];

    /// Stable protocol identifier for this typed verb.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ack => "tasks.ack",
            Self::Cancel => "tasks.cancel",
            Self::Check => "tasks.check",
            Self::Create => "tasks.create",
            Self::Expand => "tasks.expand",
        }
    }
}

/// One TASK intent and the node-local realizing-attempt input chosen by the engine.
#[derive(Debug, Clone, PartialEq)]
pub struct TaskCreateSpec {
    pub spec: Value,
    pub label: Option<String>,
    pub owner_ref: Option<EntityId>,
    pub now: Option<u64>,
}

/// Per-actor create quota within one node-local time window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaskCreateRateLimit {
    pub limit: usize,
    pub window_seconds: u64,
}

impl Default for TaskCreateRateLimit {
    fn default() -> Self {
        Self {
            limit: 10,
            window_seconds: 60,
        }
    }
}

/// Result of one `tasks.create` invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskCreateReceipt {
    pub task_ref: Option<EntityId>,
    pub proposal_ref: Option<EntityId>,
    pub approval: ClaimApprovalStatus,
    pub effected: bool,
}

/// Vocabulary over the existing two-state approval ceiling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskCancelMode {
    Auto,
    FullAccess,
    Manual,
}

impl TaskCancelMode {
    /// All ladder vocabulary tokens in protocol sort order.
    pub const ALL: [Self; 3] = [Self::Auto, Self::FullAccess, Self::Manual];

    /// Stable vocabulary token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::FullAccess => "full-access",
            Self::Manual => "manual",
        }
    }

    const fn ceiling(self) -> PolicyApprovalCeiling {
        match self {
            Self::Auto | Self::FullAccess => PolicyApprovalCeiling::Auto,
            Self::Manual => PolicyApprovalCeiling::Proposed,
        }
    }
}

/// Default ladder vocabulary for own-task and own-spawn cancellation.
pub const DEFAULT_TASK_CANCEL_MODE: TaskCancelMode = TaskCancelMode::Auto;

/// A TASK entity or agent-dispatch spawn addressed by `tasks.cancel`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskCancelTarget {
    Task(EntityId),
    Spawn(AttemptId),
}

/// Result of one `tasks.cancel` invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskCancelReceipt {
    pub approval: ClaimApprovalStatus,
    pub effected: bool,
    pub proposal_ref: Option<EntityId>,
    pub gate_decision_ref: Option<String>,
    pub status: Option<RunTreeStatus>,
}

/// Result of persisting one render-tier task acknowledgement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskAckReceipt {
    pub task_ref: EntityId,
    pub acked: bool,
}

#[derive(Debug, Clone, PartialEq)]
struct TaskVerbBody {
    role: u8,
    schema_version: u8,
    subkind: String,
    owner_ref: String,
    label: Option<String>,
    spec: Value,
    provenance: Value,
    created_at: u64,
}

#[derive(Debug)]
pub(crate) struct CancelTargetState {
    owned: bool,
    task_ref: Option<EntityId>,
    attempts: Vec<(AttemptId, AttemptState)>,
    proposal_subject: EntityId,
    target_ref: String,
}

impl MemoryFacade<'_> {
    /// Mints one TASK plus one linked realizing attempt when the actor's live
    /// definition/manifest ceiling permits Auto; otherwise parks one proposal.
    pub fn tasks_create(&self, spec: &TaskCreateSpec) -> FacadeResult<TaskCreateReceipt> {
        self.tasks_create_with_engine_rate_limit(spec, TaskCreateRateLimit::default())
    }

    /// Compatibility entry point whose quota arguments cannot override the
    /// engine-owned default.
    #[cfg(not(test))]
    pub fn tasks_create_with_rate_limit(
        &self,
        spec: &TaskCreateSpec,
        _rate_limit: TaskCreateRateLimit,
    ) -> FacadeResult<TaskCreateReceipt> {
        self.tasks_create(spec)
    }

    /// Crate-test seam for exercising exact quota boundaries.
    #[cfg(test)]
    pub(crate) fn tasks_create_with_rate_limit(
        &self,
        spec: &TaskCreateSpec,
        rate_limit: TaskCreateRateLimit,
    ) -> FacadeResult<TaskCreateReceipt> {
        self.tasks_create_with_engine_rate_limit(spec, rate_limit)
    }

    fn tasks_create_with_engine_rate_limit(
        &self,
        spec: &TaskCreateSpec,
        rate_limit: TaskCreateRateLimit,
    ) -> FacadeResult<TaskCreateReceipt> {
        let verb = task_verb_contract(TasksVerb::Create);
        verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        let now = spec.now.unwrap_or_else(unix_seconds_now);
        let rate_now = unix_seconds_now();
        let provenance = facade_provenance(verb);
        let direct = self.with_verified_actor_write_txn(|wtxn| {
            let ceiling =
                task_actor_ceiling(self.vault(), &*wtxn, self.actor(), self.actor_class())?;
            if ceiling != PolicyApprovalCeiling::Auto
                || !consume_create_rate_slot(
                    self.vault(),
                    wtxn,
                    self.actor(),
                    rate_now,
                    rate_limit,
                )?
            {
                return Ok(None);
            }

            let task_ref = EntityId::now();
            let owner_ref = spec.owner_ref.unwrap_or_else(|| self.actor());
            let body = encode_task_verb_body(TaskVerbBody {
                role: TaskRole::Task.role_byte(),
                schema_version: TASK_VERB_BODY_SCHEMA_VERSION,
                subkind: TASK_VERB_BODY_SUBKIND.to_owned(),
                owner_ref: owner_ref.to_hex(),
                label: spec.label.clone(),
                spec: spec.spec.clone(),
                provenance: provenance.clone(),
                created_at: now,
            })?;
            let occurred = TimeRange {
                start: now,
                end: now,
            };
            self.vault()
                .batch_in()
                .put(&task_ref, ENTITY_TYPE_TASK, occurred, now, &body)
                .apply(wtxn)?;
            record_task_create_owner_in_txn(self.vault(), wtxn, task_ref, owner_ref)?;
            let queue = AttemptQueue::new(self.vault());
            let outcome = queue.enqueue_with_task_ref_in_txn(
                wtxn,
                EnqueueAttempt {
                    kind: TASK_REALIZE_ATTEMPT_KIND.to_owned(),
                    payload: encode_task_realization_input(&spec.spec)?,
                    dedupe_key: None,
                    run_id: None,
                    now,
                },
                Some(task_ref.to_hex()),
            )?;
            let EnqueueOutcome::Enqueued(_) = outcome else {
                return Err(FacadeError::from(Error::InvariantViolation(
                    "tasks.create.enqueue",
                )));
            };
            Ok(Some(task_ref))
        })?;

        if let Some(task_ref) = direct {
            return Ok(TaskCreateReceipt {
                task_ref: Some(task_ref),
                proposal_ref: None,
                approval: ClaimApprovalStatus::Auto,
                effected: true,
            });
        }

        let (proposal_ref, _gate_decision_ref) = self.persist_task_proposal(
            TASK_CREATE_PROPOSAL_PREDICATE,
            task_create_proposal_value(spec, now),
            self.actor(),
            now,
            provenance,
        )?;
        Ok(TaskCreateReceipt {
            task_ref: None,
            proposal_ref: Some(proposal_ref),
            approval: ClaimApprovalStatus::Proposed,
            effected: false,
        })
    }

    /// Renders the current TASKS section through the existing board renderer.
    pub fn tasks_check(&self) -> FacadeResult<TasksSection> {
        let _provenance = facade_provenance(task_verb_contract(TasksVerb::Check));
        verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        let (intents, bare_jobs) = task_presence(self.vault())?;
        Ok(render_tasks_section(&intents, &bare_jobs))
    }

    /// Expands one TASK intent through the existing Context Board projection.
    pub fn tasks_expand(&self, task_ref: EntityId) -> FacadeResult<Vec<String>> {
        let _provenance = facade_provenance(task_verb_contract(TasksVerb::Expand));
        verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        let (intents, _) = task_presence(self.vault())?;
        let task_hex = task_ref.to_hex();
        let Some(intent) = intents.into_iter().find(|intent| intent.id == task_hex) else {
            return Err(FacadeError::from(Error::EntityNotFound));
        };
        // An acked failure has left the TASKS surface (`render_tasks_section`
        // drops it); the typed read verbs must agree, so it is not expandable
        // by id either.
        if intent.is_acked_failure() {
            return Err(FacadeError::from(Error::EntityNotFound));
        }
        Ok(expand_task(&intent))
    }

    /// Persists the free render-tier acknowledgement bit for one TASK.
    pub fn tasks_ack(&self, task_ref: EntityId) -> FacadeResult<TaskAckReceipt> {
        let _provenance = facade_provenance(task_verb_contract(TasksVerb::Ack));
        verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        // Ack applies only to a currently-FAILED task: failed rows stay
        // surfaced until acked (08b §3). Acking a queued/running task would
        // pre-set the bit so the later failure is dropped from render and never
        // surfaced — so a non-failed ack is a no-op that leaves the bit unset.
        let (intents, _) = task_presence(self.vault())?;
        let task_hex = task_ref.to_hex();
        let Some(intent) = intents.into_iter().find(|intent| intent.id == task_hex) else {
            return Err(FacadeError::from(Error::EntityNotFound));
        };
        if intent.status != TaskBoardStatus::Failed {
            return Ok(TaskAckReceipt {
                task_ref,
                acked: intent.acked,
            });
        }
        self.with_verified_actor_write_txn(|wtxn| {
            ack_task_in_txn(self.vault(), wtxn, task_ref).map_err(FacadeError::from)
        })?;
        Ok(TaskAckReceipt {
            task_ref,
            acked: task_is_acked(self.vault(), task_ref)?,
        })
    }

    /// Cancels under the own-scoped `auto` default.
    pub fn tasks_cancel(&self, target: TaskCancelTarget) -> FacadeResult<TaskCancelReceipt> {
        self.tasks_cancel_with_mode(target, DEFAULT_TASK_CANCEL_MODE)
    }

    /// Cancels under one ladder vocabulary token. `auto` and `full-access`
    /// map to the existing Auto ceiling; `manual` maps to Proposed.
    pub fn tasks_cancel_with_mode(
        &self,
        target: TaskCancelTarget,
        mode: TaskCancelMode,
    ) -> FacadeResult<TaskCancelReceipt> {
        verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        let state = cancel_target_state(self.vault(), self.actor(), target)?;
        self.tasks_cancel_resolved(mode, state)
    }

    /// Crate-test seam: runs the cancel decision over a caller-supplied (and
    /// possibly deliberately stale) target snapshot, so the in-txn live-state
    /// re-read (P1-b) can be exercised without a mid-call injection point.
    #[cfg(test)]
    pub(crate) fn tasks_cancel_with_injected_state_for_test(
        &self,
        mode: TaskCancelMode,
        state: CancelTargetState,
    ) -> FacadeResult<TaskCancelReceipt> {
        verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        self.tasks_cancel_resolved(mode, state)
    }

    fn tasks_cancel_resolved(
        &self,
        mode: TaskCancelMode,
        state: CancelTargetState,
    ) -> FacadeResult<TaskCancelReceipt> {
        let verb = task_verb_contract(TasksVerb::Cancel);
        let now = unix_seconds_now();
        let provenance = facade_provenance(verb);
        if !state.owned || mode.ceiling() == PolicyApprovalCeiling::Proposed {
            let (proposal_ref, gate_decision_ref) = self.persist_task_proposal(
                TASK_CANCEL_PROPOSAL_PREDICATE,
                Value::Map(vec![
                    (Value::from("target_ref"), Value::from(state.target_ref)),
                    (Value::from("mode"), Value::from(mode.as_str())),
                ]),
                state.proposal_subject,
                now,
                provenance,
            )?;
            return Ok(TaskCancelReceipt {
                approval: ClaimApprovalStatus::Proposed,
                effected: false,
                proposal_ref: Some(proposal_ref),
                gate_decision_ref,
                status: None,
            });
        }

        let (gate_decision_ref, gate_outcome, effected, status) = self
            .with_verified_actor_write_txn(|wtxn| {
                let policy = resolve_policy_manifest(&self.vault().store, &*wtxn)?;
                let effect = ExternalEffectGateInput {
                    actor: GateActor {
                        actor_class: self.actor_class().gate_actor_class().to_owned(),
                        actor_ref: Some(self.actor().to_hex()),
                    },
                    provenance: GateProvenanceHandles {
                        actor_entity_ref: Some(self.actor()),
                        ..GateProvenanceHandles::default()
                    },
                    verb: verb.to_owned(),
                    channel: TASK_CANCEL_GATE_CHANNEL.to_owned(),
                    channel_identity_ref: None,
                    counterparty: None,
                    brief_ref: Some(state.target_ref.clone()),
                    send_ref: None,
                    standing_grant_ref: None,
                    scoped_mcp_call: None,
                    counterparty_first_touch: None,
                    counterparty_opted_out: false,
                    counterparty_opt_out_receipt_reason: None,
                    has_opted_in: true,
                    has_permission: true,
                    policy_risk: ExternalEffectPolicyRisk::Normal,
                };
                let (decision_id, decision, _charge) = check_external_effect_policy(
                    &self.vault().store,
                    wtxn,
                    &effect,
                    &policy,
                    false,
                )?;
                let decision_ref = format!("gate:{}", decision_id.to_hex());
                if decision.outcome() != GateOutcome::Allow {
                    return Ok((decision_ref, decision.outcome(), false, None));
                }

                // P1-b (TOCTOU): decide on transaction-current attempt state,
                // not the pre-txn snapshot. A `Leased`→`Queued` requeue (lease
                // cleanup / timeout) between the snapshot and this write txn
                // must be acted on as its live state; otherwise the now-Queued
                // attempt survives a "successful" cancel and stays claimable.
                let queue = AttemptQueue::new(self.vault());
                // Deferred membership TOCTOU: when multi-attempt-per-task
                // ships, this in-txn re-read must re-enumerate the realizing
                // SET, not just re-read the snapshotted attempt STATES —
                // snapshot-then-restate-state misses an attempt enqueued
                // between snapshot and write-txn.
                let mut live_attempts: Vec<(AttemptId, AttemptState)> =
                    Vec::with_capacity(state.attempts.len());
                for (attempt_id, snapshot_state) in &state.attempts {
                    match queue.get_in_write_txn(&*wtxn, *attempt_id)? {
                        Some(record) => live_attempts.push((*attempt_id, record.state)),
                        // Spawn realizations have no TASK backlink to recover
                        // membership from. Preserve an already-terminal spawn
                        // snapshot when the in-txn lookup cannot surface its
                        // row; terminal attempt states cannot transition again.
                        None if state.task_ref.is_none()
                            && matches!(
                                snapshot_state,
                                AttemptState::Completed
                                    | AttemptState::Failed
                                    | AttemptState::Cancelled
                            ) =>
                        {
                            live_attempts.push((*attempt_id, *snapshot_state));
                        }
                        None => {}
                    }
                }

                // P1-a (leased-cancel honesty): a leased realization cannot be
                // stopped in this txn (`intervene` refuses a leased attempt) and
                // its local/outbound work keeps running. Report the honest
                // partial — do NOT hide the task and do NOT claim effect while a
                // live lease remains; the task stays VISIBLE (it folds to
                // Running under its live lease) until the lease releases. A
                // Queued+Leased mix is uneffected too: nothing is intervened and
                // nothing is hidden, so the receipt never conceals live work.
                if live_attempts
                    .iter()
                    .any(|(_, attempt_state)| *attempt_state == AttemptState::Leased)
                {
                    return Ok((
                        decision_ref,
                        decision.outcome(),
                        false,
                        Some(RunTreeStatus::Running),
                    ));
                }

                let terminal_status = terminal_attempt_status(&live_attempts);
                if !live_attempts.iter().any(|(_, attempt_state)| {
                    matches!(attempt_state, AttemptState::Queued | AttemptState::Paused)
                }) {
                    return Ok((decision_ref, decision.outcome(), false, terminal_status));
                }

                let mut cancelled_count = 0usize;
                for (attempt_id, attempt_state) in &live_attempts {
                    if !matches!(attempt_state, AttemptState::Queued | AttemptState::Paused) {
                        continue;
                    }
                    let outcome = queue.intervene_in_txn(
                        wtxn,
                        InterveneAttempt {
                            id: *attempt_id,
                            kind: AttemptInterventionKind::Cancel,
                            actor: self.actor().to_hex(),
                            note: None,
                            now,
                        },
                    )?;
                    match outcome.effect {
                        AttemptInterventionEffect::Cancelled => cancelled_count += 1,
                        AttemptInterventionEffect::AlreadyCancelled => {}
                        _ => {
                            return Err(FacadeError::from(Error::InvariantViolation(
                                "tasks.cancel.effect",
                            )));
                        }
                    }
                }
                if cancelled_count == 0 {
                    return Ok((decision_ref, decision.outcome(), false, terminal_status));
                }
                // A Completed/Failed sibling remains real terminal work. Keep
                // its TASK intent visible so the unchanged job stays folded
                // exactly once, and surface that aggregate terminal status
                // instead of claiming the whole target was cancelled.
                let preserved_terminal_status = terminal_status.filter(|status| {
                    matches!(status, RunTreeStatus::Completed | RunTreeStatus::Failed)
                });
                if preserved_terminal_status.is_none()
                    && let Some(task_ref) = state.task_ref
                {
                    cancel_task_in_txn(self.vault(), wtxn, task_ref)?;
                }
                Ok((
                    decision_ref,
                    decision.outcome(),
                    true,
                    preserved_terminal_status.or(Some(RunTreeStatus::Cancelled)),
                ))
            })?;

        if gate_outcome != GateOutcome::Allow {
            let (proposal_ref, _proposal_gate_decision_ref) = self.persist_task_proposal(
                TASK_CANCEL_PROPOSAL_PREDICATE,
                Value::Map(vec![
                    (Value::from("target_ref"), Value::from(state.target_ref)),
                    (Value::from("mode"), Value::from(mode.as_str())),
                ]),
                state.proposal_subject,
                now,
                provenance,
            )?;
            return Ok(TaskCancelReceipt {
                approval: ClaimApprovalStatus::Proposed,
                effected: false,
                proposal_ref: Some(proposal_ref),
                gate_decision_ref: Some(gate_decision_ref),
                status: None,
            });
        }

        // Gate allowed. `effected` is honest: true only when at least one live
        // Queued/Paused realization was cancelled. A terminal sibling keeps the
        // task visible and owns the combined status; all-cancellable work is
        // hidden. A live lease or an all-terminal target remains uneffected.
        Ok(TaskCancelReceipt {
            approval: ClaimApprovalStatus::Auto,
            effected,
            proposal_ref: None,
            gate_decision_ref: Some(gate_decision_ref),
            status,
        })
    }

    fn persist_task_proposal(
        &self,
        predicate: &str,
        value: Value,
        subject: EntityId,
        now: u64,
        provenance: Value,
    ) -> FacadeResult<(EntityId, Option<String>)> {
        let proposal_ref = EntityId::now();
        let candidate = ClaimCandidate::new(
            predicate.to_owned(),
            ClaimSubject::Entity(subject),
            value,
            1.0,
        );
        let envelope = WriteEnvelope::new(
            WriteActor::new(self.actor(), self.actor_class()),
            ClaimSource::ToolOutput,
            WriteProvenance::new(provenance)?,
            ClaimApprovalStatus::Proposed,
        );
        let occurred = TimeRange {
            start: now,
            end: now,
        };
        self.with_verified_actor_write_txn(|wtxn| {
            apply_ops_with_gate_mode(
                &self.vault().store,
                &self.vault().config,
                &self.vault().analyzer,
                wtxn,
                vec![BatchOp::ClaimCandidate {
                    id: proposal_ref,
                    candidate: Box::new(candidate),
                    envelope,
                    occurred,
                    learned_at: now,
                    internal_lexical_query_hint: false,
                }],
                self.vault().text_index_trusted.load(Ordering::Acquire),
                ApplyOpsGateMode::new(true, true),
            )
            .map_err(FacadeError::from)
        })?;
        let gate_decision_ref = self
            .vault()
            .gate_decisions(TASK_GATE_RECEIPT_SCAN_LIMIT)?
            .into_iter()
            .filter(|record| record.claim_id.as_ref() == Some(proposal_ref.as_bytes()))
            .max_by_key(|record| record.decision_id.to_hex())
            .map(|record| format!("gate:{}", record.decision_id.to_hex()));
        Ok((proposal_ref, gate_decision_ref))
    }
}

fn task_verb_contract(verb: TasksVerb) -> &'static str {
    verb.as_str()
}

fn task_actor_ceiling(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: EntityId,
    actor_class: EdgeActorClass,
) -> FacadeResult<PolicyApprovalCeiling> {
    let policy = resolve_policy_manifest(&vault.store, txn)?;
    let policy_projection = policy.actor_ceiling(
        actor_class.gate_actor_class(),
        Some(actor.to_hex().as_str()),
    );
    let definition = crate::gate::agent_definition_ceiling_for_actor(
        &vault.store,
        txn,
        WriteActor::new(actor, actor_class),
    );
    Ok(definition.map_or(policy_projection, |definition| {
        dispatched_agent_effective_ceiling(definition, policy_projection)
    }))
}

fn consume_create_rate_slot(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: EntityId,
    now: u64,
    rate_limit: TaskCreateRateLimit,
) -> Result<bool> {
    let window_seconds = rate_limit.window_seconds.max(1);
    let window = now / window_seconds;
    // One node-local key per (actor, window_seconds), overwritten each window:
    // value = {window, count}. A stored window other than the current one
    // resets the count, so elapsed windows overwrite the same key instead of
    // leaving a per-window residue that grows unbounded over the vault's life.
    let key = task_create_rate_key(actor, window_seconds);
    let count = match vault.store.vault_meta.get(&*wtxn, key.as_slice())? {
        Some(raw) => {
            let stored: [u8; 16] = raw
                .as_ref()
                .try_into()
                .map_err(|_| Error::CorruptedIndex("tasks.create.rate"))?;
            let stored_window = u64::from_le_bytes(stored[..8].try_into().expect("rate window"));
            if stored_window == window {
                u64::from_le_bytes(stored[8..].try_into().expect("rate count"))
            } else {
                0
            }
        }
        None => 0,
    };
    if count >= rate_limit.limit as u64 {
        return Ok(false);
    }
    let mut value = [0u8; 16];
    value[..8].copy_from_slice(&window.to_le_bytes());
    value[8..].copy_from_slice(&count.saturating_add(1).to_le_bytes());
    vault.store.vault_meta.put(wtxn, key.as_slice(), &value)?;
    Ok(true)
}

fn task_create_rate_key(actor: EntityId, window_seconds: u64) -> Vec<u8> {
    let mut key = Vec::with_capacity(
        TASK_CREATE_RATE_KEY_PREFIX.len() + actor.as_bytes().len() + size_of::<u64>(),
    );
    key.extend_from_slice(TASK_CREATE_RATE_KEY_PREFIX);
    key.extend_from_slice(actor.as_bytes());
    key.extend_from_slice(&window_seconds.to_be_bytes());
    key
}

fn record_task_create_owner_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    task_ref: EntityId,
    owner_ref: EntityId,
) -> Result<()> {
    vault.store.vault_meta.put(
        wtxn,
        task_create_owner_key(task_ref).as_slice(),
        owner_ref.as_bytes(),
    )?;
    Ok(())
}

fn task_create_owner(vault: &Vault, task_ref: EntityId) -> Result<Option<EntityId>> {
    let rtxn = vault.store.env.read_txn()?;
    let Some(raw) = vault
        .store
        .vault_meta
        .get(&rtxn, task_create_owner_key(task_ref).as_slice())?
    else {
        return Ok(None);
    };
    let bytes: [u8; 16] = raw
        .as_ref()
        .try_into()
        .map_err(|_| Error::CorruptedIndex("tasks.create.owner"))?;
    EntityId::from_bytes(bytes).map(Some)
}

fn task_create_owner_key(task_ref: EntityId) -> Vec<u8> {
    let mut key =
        Vec::with_capacity(TASK_CREATE_OWNER_KEY_PREFIX.len() + task_ref.as_bytes().len());
    key.extend_from_slice(TASK_CREATE_OWNER_KEY_PREFIX);
    key.extend_from_slice(task_ref.as_bytes());
    key
}

fn encode_task_verb_body(body: TaskVerbBody) -> Result<Vec<u8>> {
    let value = Value::Map(vec![
        (Value::from("role"), Value::from(body.role)),
        (
            Value::from("schema_version"),
            Value::from(body.schema_version),
        ),
        (Value::from("subkind"), Value::from(body.subkind)),
        (Value::from("owner_ref"), Value::from(body.owner_ref)),
        (
            Value::from("label"),
            body.label.map_or(Value::Nil, Value::from),
        ),
        (Value::from("spec"), body.spec),
        (Value::from("provenance"), body.provenance),
        (Value::from("created_at"), Value::from(body.created_at)),
    ]);
    let mut encoded = Vec::new();
    rmpv::encode::write_value(&mut encoded, &value)
        .map_err(|_| Error::InvalidTaskBody("tasks.create.body"))?;
    Ok(encoded)
}

fn encode_task_realization_input(spec: &Value) -> Result<Vec<u8>> {
    let mut payload = Vec::new();
    rmpv::encode::write_value(&mut payload, spec)
        .map_err(|_| Error::InvalidTaskBody("tasks.create.spec"))?;
    Ok(payload)
}

fn task_verb_body(vault: &Vault, task_ref: EntityId) -> Result<Option<TaskVerbBody>> {
    let Some(raw) = vault.get_raw(&task_ref)? else {
        return Ok(None);
    };
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        return Err(Error::CorruptedIndex("tasks.create.header"));
    };
    if header.entity_type != ENTITY_TYPE_TASK {
        return Ok(None);
    }
    let body = &raw[ENTITY_METADATA_HEADER_LEN..];
    if !task_body_has_typed_subkind(body)? {
        return Ok(None);
    }
    let body = decode_task_verb_body(body)?;
    if body.schema_version != TASK_VERB_BODY_SCHEMA_VERSION
        || body.role != TaskRole::Task.role_byte()
    {
        return Err(Error::InvalidTaskBody("tasks.create.version"));
    }
    Ok(Some(body))
}

fn task_entity_role(vault: &Vault, task_ref: EntityId) -> Result<Option<TaskRole>> {
    let Some(raw) = vault.get_raw(&task_ref)? else {
        return Ok(None);
    };
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        return Err(Error::CorruptedIndex("tasks.role.header"));
    };
    if header.entity_type != ENTITY_TYPE_TASK {
        return Ok(None);
    }
    crate::habit::task_role_from_body_bytes(&raw[ENTITY_METADATA_HEADER_LEN..]).map(Some)
}

fn decode_task_verb_body(body: &[u8]) -> Result<TaskVerbBody> {
    let mut cursor = body;
    let value = rmpv::decode::read_value(&mut cursor)
        .map_err(|_| Error::InvalidTaskBody("tasks.create.body"))?;
    if !cursor.is_empty() {
        return Err(Error::InvalidTaskBody("tasks.create.body"));
    }
    let entries = value
        .as_map()
        .ok_or(Error::InvalidTaskBody("tasks.create.body"))?;
    let byte = |key| {
        task_body_field(entries, key)?
            .as_u64()
            .and_then(|value| u8::try_from(value).ok())
            .ok_or(Error::InvalidTaskBody("tasks.create.body"))
    };
    let string = |key| {
        task_body_field(entries, key)?
            .as_str()
            .map(str::to_owned)
            .ok_or(Error::InvalidTaskBody("tasks.create.body"))
    };
    let label = match task_body_field(entries, "label")? {
        Value::Nil => None,
        value => Some(
            value
                .as_str()
                .map(str::to_owned)
                .ok_or(Error::InvalidTaskBody("tasks.create.body"))?,
        ),
    };
    let created_at = task_body_field(entries, "created_at")?
        .as_u64()
        .ok_or(Error::InvalidTaskBody("tasks.create.body"))?;
    Ok(TaskVerbBody {
        role: byte("role")?,
        schema_version: byte("schema_version")?,
        subkind: string("subkind")?,
        owner_ref: string("owner_ref")?,
        label,
        spec: task_body_field(entries, "spec")?.clone(),
        provenance: task_body_field(entries, "provenance")?.clone(),
        created_at,
    })
}

fn task_body_field<'a>(entries: &'a [(Value, Value)], name: &str) -> Result<&'a Value> {
    let mut values = entries
        .iter()
        .filter(|(key, _)| key.as_str() == Some(name))
        .map(|(_, value)| value);
    let value = values
        .next()
        .ok_or(Error::InvalidTaskBody("tasks.create.body"))?;
    if values.next().is_some() {
        return Err(Error::InvalidTaskBody("tasks.create.body"));
    }
    Ok(value)
}

fn task_body_has_typed_subkind(body: &[u8]) -> Result<bool> {
    let mut cursor = body;
    let value = rmpv::decode::read_value(&mut cursor)
        .map_err(|_| Error::InvalidTaskBody("tasks.create.body"))?;
    if !cursor.is_empty() {
        return Err(Error::InvalidTaskBody("tasks.create.body"));
    }
    let Some(entries) = value.as_map() else {
        return Ok(false);
    };
    Ok(entries
        .iter()
        .filter(|(key, _)| key.as_str() == Some("subkind"))
        .count()
        == 1
        && entries
            .iter()
            .filter(|(key, value)| {
                key.as_str() == Some("subkind") && value.as_str() == Some(TASK_VERB_BODY_SUBKIND)
            })
            .count()
            == 1)
}

fn task_create_proposal_value(spec: &TaskCreateSpec, now: u64) -> Value {
    Value::Map(vec![
        (Value::from("spec"), spec.spec.clone()),
        (
            Value::from("label"),
            spec.label.clone().map_or(Value::Nil, Value::from),
        ),
        (
            Value::from("owner_ref"),
            spec.owner_ref
                .map_or(Value::Nil, |owner| Value::from(owner.to_hex())),
        ),
        (Value::from("created_at"), Value::from(now)),
    ])
}

fn task_presence(vault: &Vault) -> Result<(Vec<TaskIntentPresence>, Vec<JobPresence>)> {
    let records = AttemptQueue::new(vault).list()?;
    let task_refs_by_attempt: BTreeMap<String, Option<String>> = records
        .iter()
        .map(|record| (attempt_hex(record.id), record.task_ref.clone()))
        .collect();
    let tree = RunTreeAdapter::new(vault).read()?;
    let mut nodes = Vec::new();
    collect_run_tree_nodes(&tree.roots, &mut nodes);
    let mut realizing_jobs: BTreeMap<String, Vec<JobPresence>> = BTreeMap::new();
    let mut bare_jobs = Vec::new();
    for node in nodes {
        let Some(job) = JobPresence::from_run_tree_node(node) else {
            continue;
        };
        match task_refs_by_attempt.get(&node.attempt_id) {
            Some(Some(task_ref)) => realizing_jobs
                .entry(task_ref.clone())
                .or_default()
                .push(job),
            _ if node.worker_kind == BRIDGE_OUTBOUND_ATTEMPT_KIND => {}
            _ => bare_jobs.push(job),
        }
    }

    let mut intents = Vec::new();
    for task_ref in vault.entities_by_type(ENTITY_TYPE_TASK)? {
        if task_is_cancelled(vault, task_ref)? {
            continue;
        }
        let task_hex = task_ref.to_hex();
        let jobs = realizing_jobs.get(&task_hex).cloned().unwrap_or_default();
        let acked = task_is_acked(vault, task_ref)?;
        // P2 F8 (board poisoning): one malformed TASK body must not abort the
        // whole board. A body that decodes badly — e.g. a role byte carrying
        // `subkind:"typed"` but missing the typed fields — is skipped/degraded,
        // never propagated as a hard error that takes down `tasks.check`.
        match task_intent_presence(vault, task_ref, &task_hex, jobs, acked) {
            Ok(Some(intent)) => {
                realizing_jobs.remove(&task_hex);
                intents.push(intent);
            }
            Ok(None) => {}
            Err(_) => continue,
        }
    }

    // P2 F7 (dangling backlink): every live realizing job must render exactly
    // once. A backlink naming no surviving intent (deleted / malformed /
    // case-mismatched owner) is re-emitted as a bare job instead of vanishing.
    bare_jobs.extend(realizing_jobs.into_values().flatten());

    Ok((intents, bare_jobs))
}

/// Projects one surviving (non-cancelled) TASK entity into its board intent
/// row, or `None` when the entity is not a board-visible TASK. Returns an error
/// only for that single entity; `task_presence` degrades one bad entity into a
/// skip so the whole board survives (P2 F8).
fn task_intent_presence(
    vault: &Vault,
    task_ref: EntityId,
    task_hex: &str,
    jobs: Vec<JobPresence>,
    acked: bool,
) -> Result<Option<TaskIntentPresence>> {
    if let Some(task) = task_verb_body(vault, task_ref)? {
        let status = fold_up_status(&jobs).unwrap_or(TaskBoardStatus::Queued);
        return Ok(Some(TaskIntentPresence {
            id: task_hex.to_owned(),
            status,
            label: task.label,
            acked,
            realizing_jobs: jobs,
        }));
    }
    if let Some(task) = vault.connector_send_task(&task_ref)? {
        let status = fold_up_status(&jobs).unwrap_or(TaskBoardStatus::Scheduled);
        return Ok(Some(TaskIntentPresence::from_connector_send_task_with_ack(
            &task, status, jobs, acked,
        )));
    }
    // P2 F6 (role fold): only the `Task` role folds into the TASKS section.
    // Goal / Milestone / Habit / HabitCheckin roles are not tasks and must not
    // render as TASKS rows (nor enter the cancel fallback below).
    if matches!(task_entity_role(vault, task_ref)?, Some(TaskRole::Task)) {
        let status = fold_up_status(&jobs).unwrap_or(TaskBoardStatus::Queued);
        return Ok(Some(TaskIntentPresence {
            id: task_hex.to_owned(),
            status,
            label: None,
            acked,
            realizing_jobs: jobs,
        }));
    }
    Ok(None)
}

fn collect_run_tree_nodes<'a>(nodes: &'a [RunTreeNode], out: &mut Vec<&'a RunTreeNode>) {
    for node in nodes {
        out.push(node);
        collect_run_tree_nodes(&node.children, out);
    }
}

fn cancel_target_state(
    vault: &Vault,
    actor: EntityId,
    target: TaskCancelTarget,
) -> FacadeResult<CancelTargetState> {
    match target {
        TaskCancelTarget::Task(task_ref) => {
            let task_hex = task_ref.to_hex();
            let owned = if task_verb_body(vault, task_ref)?.is_some() {
                // The typed body is mutable storage and its `owner_ref` is not
                // authority. Only the owner record stamped atomically by the
                // verified `tasks.create` path proves direct-cancel ownership;
                // typed bodies from any other write door fail closed.
                task_create_owner(vault, task_ref)? == Some(actor)
            } else if let Some(task) = vault.connector_send_task(&task_ref)? {
                task.actor_ref == actor
            } else if matches!(task_entity_role(vault, task_ref)?, Some(TaskRole::Task)) {
                // P1-c (role-only ownership): a role-only TASK carries no stored
                // owner/author provenance (ONE-1695 role bodies are `{role}`
                // only, and no header / side-index / ledger records the author
                // of a raw TASK put). Ownership therefore cannot be established,
                // so fail CLOSED to the foreign ladder (propose-only) rather
                // than vacuously trusting the caller — no principal may directly
                // cancel another's role-only task. Visibility (fix-r1 F6) is
                // unaffected: role-only Tasks still render in `tasks.check` and
                // remain cancellable via a proposal. (F6 also narrows this
                // fallback to `Task`; Goal/Milestone/Habit/HabitCheckin ids are
                // not TASKS and fall through to `EntityNotFound`.)
                false
            } else {
                return Err(FacadeError::from(Error::EntityNotFound));
            };
            let attempts = AttemptQueue::new(vault)
                .list()?
                .into_iter()
                .filter(|attempt| attempt.task_ref.as_deref() == Some(task_hex.as_str()))
                .map(|attempt| (attempt.id, attempt.state))
                .collect();
            Ok(CancelTargetState {
                owned,
                task_ref: Some(task_ref),
                attempts,
                proposal_subject: task_ref,
                target_ref: task_hex,
            })
        }
        TaskCancelTarget::Spawn(attempt_ref) => {
            let queue = AttemptQueue::new(vault);
            let child = queue
                .get(attempt_ref)?
                .ok_or_else(|| FacadeError::from(Error::EntityNotFound))?;
            let child_payload = decode_dreamer_attempt_payload(&child.payload)?;
            let owned = if child.kind == DREAMER_RUNNER_ATTEMPT_KIND
                && child_payload.attempt_type == AGENT_DISPATCH_ATTEMPT_TYPE
            {
                child_payload
                    .parent_attempt
                    .and_then(|parent_ref| queue.get(parent_ref).ok().flatten())
                    .and_then(|parent| decode_dreamer_attempt_payload(&parent.payload).ok())
                    .filter(|parent| parent.attempt_type == AGENT_DISPATCH_ATTEMPT_TYPE)
                    .and_then(|parent| decode_agent_dispatch_input(&parent.input).ok())
                    .is_some_and(|parent| agent_dispatch_actor(&parent).entity_ref() == actor)
            } else {
                false
            };
            Ok(CancelTargetState {
                owned,
                task_ref: None,
                attempts: vec![(attempt_ref, child.state)],
                proposal_subject: actor,
                target_ref: attempt_hex(attempt_ref),
            })
        }
    }
}

fn attempt_hex(attempt_id: AttemptId) -> String {
    let mut out = String::with_capacity(32);
    for byte in attempt_id.as_bytes() {
        use std::fmt::Write as _;
        write!(&mut out, "{byte:02x}").expect("fmt::Write for String is infallible");
    }
    out
}

fn terminal_attempt_status(attempts: &[(AttemptId, AttemptState)]) -> Option<RunTreeStatus> {
    if attempts
        .iter()
        .any(|(_, state)| *state == AttemptState::Failed)
    {
        Some(RunTreeStatus::Failed)
    } else if attempts
        .iter()
        .any(|(_, state)| *state == AttemptState::Completed)
    {
        Some(RunTreeStatus::Completed)
    } else if attempts
        .iter()
        .any(|(_, state)| *state == AttemptState::Cancelled)
    {
        Some(RunTreeStatus::Cancelled)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_def::SystemAgentPreset;
    use crate::agent_dispatch::{
        AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher, DispatchAgent,
    };
    use crate::attempt_queue::{ClaimAttempt, ClaimOutcome, CompleteAttempt, FailAttempt};
    use crate::config::VaultConfig;
    use crate::facade::OutboundDraftInput;
    use crate::genui::{GrantMintIntent, GrantMintIntentScope};
    use crate::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_TASK};

    fn open_vault() -> (tempfile::TempDir, Vault) {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
        (dir, vault)
    }

    fn put_person(vault: &Vault, id: EntityId) {
        vault
            .put_entity(
                &id,
                ENTITY_TYPE_PERSON,
                TimeRange { start: 1, end: 1 },
                1,
                b"actor",
            )
            .expect("put actor");
    }

    fn own_agent(vault: &Vault) -> EntityId {
        let actor = EntityId::from_bytes([0xE1; 16]).expect("actor id");
        put_person(vault, actor);
        actor
    }

    fn grant_cancel(vault: &Vault, actor: EntityId, seed: u8) {
        let grant_ref = EntityId::from_bytes([seed; 16]).expect("grant id");
        vault
            .mint_standing_outbound_grant(
                &grant_ref,
                &GrantMintIntent {
                    principal_ref: actor.to_hex(),
                    origin_component_id: "tasks".to_owned(),
                    origin_action_id: "cancel".to_owned(),
                    origin_receipt_ref: None,
                    scope: GrantMintIntentScope::VerbClass {
                        verb_class: TasksVerb::Cancel.as_str().to_owned(),
                    },
                },
                1,
            )
            .expect("mint cancel grant");
    }

    fn spec(now: u64) -> TaskCreateSpec {
        TaskCreateSpec {
            spec: Value::from("unit-task"),
            label: None,
            owner_ref: None,
            now: Some(now),
        }
    }

    fn assert_queued_terminal_mix_cancel(
        terminal_state: AttemptState,
        expected_receipt_status: RunTreeStatus,
        expected_board_status: TaskBoardStatus,
    ) {
        assert!(matches!(
            terminal_state,
            AttemptState::Completed | AttemptState::Failed
        ));
        let (_dir, vault) = open_vault();
        let own = own_agent(&vault);
        grant_cancel(&vault, own, 0xDA);
        let facade = vault.memory_facade(own, EdgeActorClass::Agent);
        let created = facade.tasks_create(&spec(120)).expect("create task");
        let task_ref = created.task_ref.expect("task ref");
        let task_hex = task_ref.to_hex();
        let queue = AttemptQueue::new(&vault);
        let terminal = match queue
            .claim_kind(
                TASK_REALIZE_ATTEMPT_KIND,
                ClaimAttempt {
                    lease_owner: "terminal-mix-worker".to_owned(),
                    now: 120,
                },
            )
            .expect("claim terminal realization")
        {
            ClaimOutcome::Claimed(claimed) => claimed,
            ClaimOutcome::Empty => panic!("terminal realization must be claimable"),
        };
        let queued = match queue
            .enqueue_with_task_ref(
                EnqueueAttempt {
                    kind: TASK_REALIZE_ATTEMPT_KIND.to_owned(),
                    payload: Vec::new(),
                    dedupe_key: None,
                    run_id: None,
                    now: 121,
                },
                Some(task_hex.clone()),
            )
            .expect("enqueue live sibling")
        {
            EnqueueOutcome::Enqueued(queued) => queued,
            EnqueueOutcome::Existing(_) => panic!("live sibling must be fresh"),
        };
        match terminal_state {
            AttemptState::Completed => {
                queue
                    .complete(CompleteAttempt {
                        id: terminal.id,
                        lease_owner: "terminal-mix-worker".to_owned(),
                        attempt_count: terminal.attempt_count,
                        now: 122,
                    })
                    .expect("complete terminal sibling");
            }
            AttemptState::Failed => {
                queue
                    .fail(FailAttempt {
                        id: terminal.id,
                        lease_owner: "terminal-mix-worker".to_owned(),
                        attempt_count: terminal.attempt_count,
                        reason: "terminal mix failure".to_owned(),
                        now: 122,
                    })
                    .expect("fail terminal sibling");
            }
            _ => unreachable!("helper accepts only completed or failed states"),
        }

        let cancel = facade
            .tasks_cancel(TaskCancelTarget::Task(task_ref))
            .expect("cancel live sibling");
        let records = queue.list().expect("list attempts after cancel");
        let terminal_after = queue
            .get(terminal.id)
            .expect("read terminal sibling")
            .expect("terminal sibling exists");
        let queued_after = queue
            .get(queued.id)
            .expect("read cancelled sibling")
            .expect("cancelled sibling exists");
        let section = facade.tasks_check().expect("check mixed task");
        let terminal_hex = attempt_hex(terminal.id);
        let queued_hex = attempt_hex(queued.id);

        assert_eq!(usize::from(cancel.effected), 1);
        assert_eq!(cancel.approval, ClaimApprovalStatus::Auto);
        assert_eq!(usize::from(cancel.proposal_ref.is_some()), 0);
        assert_eq!(cancel.status, Some(expected_receipt_status));
        assert_eq!(terminal_after.state, terminal_state);
        assert_eq!(queued_after.state, AttemptState::Cancelled);
        assert_eq!(
            usize::from(task_is_cancelled(&vault, task_ref).expect("cancel state")),
            0
        );
        assert_eq!(
            records
                .iter()
                .filter(|record| {
                    record.task_ref.as_deref() == Some(task_hex.as_str())
                        && record.state == terminal_state
                })
                .count(),
            1
        );
        assert_eq!(
            records
                .iter()
                .filter(|record| {
                    record.task_ref.as_deref() == Some(task_hex.as_str())
                        && record.state == AttemptState::Cancelled
                })
                .count(),
            1
        );
        assert_eq!(
            records
                .iter()
                .filter(|record| record.task_ref.as_deref() == Some(task_hex.as_str()))
                .count(),
            2
        );
        assert_eq!(
            section.rows.iter().filter(|row| row.id == task_hex).count(),
            1
        );
        let task_row = section
            .rows
            .iter()
            .find(|row| row.id == task_hex)
            .expect("mixed task row");
        assert_eq!(task_row.status, expected_board_status);
        assert_eq!(task_row.folded_job_count, 1);
        assert_eq!(
            section
                .rows
                .iter()
                .filter(|row| row.id == terminal_hex)
                .count(),
            0
        );
        assert_eq!(
            section
                .rows
                .iter()
                .filter(|row| row.id == queued_hex)
                .count(),
            0
        );
        assert_eq!(section.rows.len(), 1);
    }

    #[test]
    fn verb_family_is_exactly_five_without_queue_verbs() {
        let verbs = TasksVerb::ALL.map(TasksVerb::as_str);
        assert_eq!(verbs.len(), 5);
        assert_eq!(verbs, TASKS_VERBS);
        assert_eq!(
            verbs
                .iter()
                .filter(|verb| verb.contains("queue") || verb.contains("lease"))
                .count(),
            0
        );
    }

    #[test]
    fn own_create_effects_and_foreign_create_proposes() {
        let (_dir, vault) = open_vault();
        let own = own_agent(&vault);
        let foreign = EntityId::from_bytes([0xE2; 16]).expect("foreign id");
        put_person(&vault, foreign);
        let rate = TaskCreateRateLimit {
            limit: 10,
            window_seconds: 60,
        };

        let own_result = vault
            .memory_facade(own, EdgeActorClass::Agent)
            .tasks_create_with_rate_limit(&spec(120), rate)
            .expect("own create");
        let foreign_result = vault
            .memory_facade(foreign, EdgeActorClass::Agent)
            .tasks_create_with_rate_limit(&spec(120), rate)
            .expect("foreign create");

        assert_eq!(usize::from(own_result.effected), 1);
        assert_eq!(own_result.approval, ClaimApprovalStatus::Auto);
        assert_eq!(usize::from(own_result.proposal_ref.is_some()), 0);
        assert_eq!(usize::from(foreign_result.effected), 0);
        assert_eq!(foreign_result.approval, ClaimApprovalStatus::Proposed);
        assert_eq!(usize::from(foreign_result.proposal_ref.is_some()), 1);
        assert_eq!(
            vault
                .entities_by_type(ENTITY_TYPE_TASK)
                .expect("task entities")
                .len(),
            1
        );
    }

    #[test]
    fn rate_limit_effects_n_and_proposes_every_overflow() {
        let (_dir, vault) = open_vault();
        let own = own_agent(&vault);
        let facade = vault.memory_facade(own, EdgeActorClass::Agent);
        let limit = 3;
        let attempted = 5;
        // The rate window is keyed on the ENGINE clock (`unix_seconds_now()`,
        // not caller time — the codex-r1 anti-bypass fix). A single window here
        // keeps the overflow behavior deterministic: with a finite window these
        // creates could straddle a wall-clock boundary under load and reset the
        // count mid-loop. (Window advancement is covered separately by
        // `create_rate_slot_overwrites_one_key_across_windows`.)
        let rate = TaskCreateRateLimit {
            limit,
            window_seconds: u64::MAX,
        };
        let mut results = Vec::new();
        for _ in 0..attempted {
            results.push(
                facade
                    .tasks_create_with_rate_limit(&spec(120), rate)
                    .expect("create"),
            );
        }

        assert_eq!(usize::from(results[limit - 1].effected), 1);
        assert_eq!(results[limit - 1].approval, ClaimApprovalStatus::Auto);
        assert_eq!(usize::from(results[limit - 1].proposal_ref.is_some()), 0);
        assert_eq!(usize::from(results[limit].effected), 0);
        assert_eq!(results[limit].approval, ClaimApprovalStatus::Proposed);
        assert_eq!(usize::from(results[limit].proposal_ref.is_some()), 1);
        assert_eq!(
            results.iter().filter(|result| result.effected).count(),
            limit
        );
        assert_eq!(
            results
                .iter()
                .filter(|result| result.proposal_ref.is_some())
                .count(),
            attempted - limit
        );
    }

    #[test]
    fn create_rate_slot_overwrites_one_key_across_windows() {
        let (_dir, vault) = open_vault();
        let own = own_agent(&vault);
        let rate = TaskCreateRateLimit {
            limit: 2,
            window_seconds: 10,
        };
        {
            let mut wtxn = vault.store.env.write_txn().expect("write txn");
            // Window 0 (now 0..9): two slots, then the third is refused.
            assert!(consume_create_rate_slot(&vault, &mut wtxn, own, 0, rate).expect("w0 s1"));
            assert!(consume_create_rate_slot(&vault, &mut wtxn, own, 3, rate).expect("w0 s2"));
            assert!(!consume_create_rate_slot(&vault, &mut wtxn, own, 9, rate).expect("w0 over"));
            // Window 1 (now 10..): the count resets, a slot is available again.
            assert!(consume_create_rate_slot(&vault, &mut wtxn, own, 10, rate).expect("w1 s1"));
            // Window 2 (now 20..): still resets, still the same single key.
            assert!(consume_create_rate_slot(&vault, &mut wtxn, own, 20, rate).expect("w2 s1"));
            wtxn.commit().expect("commit");
        }
        // Elapsed windows overwrite the SAME key: exactly one rate key persists
        // for this (actor, window_seconds), not one row per elapsed window.
        let rtxn = vault.store.env.read_txn().expect("read txn");
        let keys = vault
            .store
            .vault_meta
            .prefix_iter(&rtxn, TASK_CREATE_RATE_KEY_PREFIX)
            .expect("rate prefix iter")
            .count();
        assert_eq!(keys, 1);
    }

    #[test]
    fn caller_time_variation_does_not_bypass_one_engine_rate_window() {
        let (_dir, vault) = open_vault();
        let own = own_agent(&vault);
        let facade = vault.memory_facade(own, EdgeActorClass::Agent);
        let limit = 3;
        let rate = TaskCreateRateLimit {
            limit,
            window_seconds: u64::MAX,
        };
        let caller_times = [0, 60, 120, 180];
        let results = caller_times.map(|now| {
            facade
                .tasks_create_with_rate_limit(&spec(now), rate)
                .expect("create")
        });

        assert_eq!(
            results.iter().filter(|result| result.effected).count(),
            limit
        );
        assert_eq!(
            results
                .iter()
                .filter(|result| result.approval == ClaimApprovalStatus::Proposed)
                .count(),
            1
        );
        assert_eq!(
            results
                .iter()
                .filter(|result| result.proposal_ref.is_some())
                .count(),
            1
        );
    }

    #[test]
    fn cancel_ladder_is_own_scoped_and_records_gate_decision() {
        let (_dir, vault) = open_vault();
        let own = own_agent(&vault);
        grant_cancel(&vault, own, 0xD1);
        let other = EntityId::from_bytes([0xE2; 16]).expect("other id");
        put_person(&vault, other);
        let facade = vault.memory_facade(own, EdgeActorClass::Agent);
        let own_create = facade.tasks_create(&spec(120)).expect("own task");
        let mut other_spec = spec(120);
        other_spec.owner_ref = Some(other);
        let other_create = facade.tasks_create(&other_spec).expect("other task");

        let decisions_before = vault.gate_decisions(512).expect("decisions before").len();
        let own_cancel = facade
            .tasks_cancel(TaskCancelTarget::Task(
                own_create.task_ref.expect("own task ref"),
            ))
            .expect("own cancel");
        let decisions_after_own = vault
            .gate_decisions(512)
            .expect("decisions after own")
            .len();
        let foreign_cancel = facade
            .tasks_cancel(TaskCancelTarget::Task(
                other_create.task_ref.expect("other task ref"),
            ))
            .expect("foreign cancel");

        assert_eq!(TaskCancelMode::ALL.map(TaskCancelMode::as_str).len(), 3);
        assert_eq!(
            TaskCancelMode::ALL.map(TaskCancelMode::as_str),
            ["auto", "full-access", "manual"]
        );
        assert_eq!(DEFAULT_TASK_CANCEL_MODE.as_str(), "auto");
        assert_eq!(TaskCancelMode::Auto.ceiling(), PolicyApprovalCeiling::Auto);
        assert_eq!(
            TaskCancelMode::FullAccess.ceiling(),
            PolicyApprovalCeiling::Auto
        );
        assert_eq!(
            TaskCancelMode::Manual.ceiling(),
            PolicyApprovalCeiling::Proposed
        );
        assert_eq!(decisions_after_own - decisions_before, 1);
        assert_eq!(usize::from(own_cancel.gate_decision_ref.is_some()), 1);
        assert_eq!(
            vault
                .gate_decisions(512)
                .expect("gate decisions")
                .iter()
                .filter(|decision| {
                    own_cancel.gate_decision_ref.as_deref()
                        == Some(format!("gate:{}", decision.decision_id.to_hex()).as_str())
                        && decision.outcome == GateOutcome::Allow.as_str()
                })
                .count(),
            1
        );
        assert_eq!(usize::from(own_cancel.effected), 1);
        assert_eq!(own_cancel.approval, ClaimApprovalStatus::Auto);
        assert_eq!(own_cancel.status, Some(RunTreeStatus::Cancelled));
        assert_eq!(usize::from(foreign_cancel.effected), 0);
        assert_eq!(foreign_cancel.approval, ClaimApprovalStatus::Proposed);
        assert_eq!(usize::from(foreign_cancel.proposal_ref.is_some()), 1);
        assert_eq!(usize::from(foreign_cancel.gate_decision_ref.is_some()), 1);

        let queue = AttemptQueue::new(&vault);
        let records = queue.list().expect("list attempts");
        let own_task_hex = own_create.task_ref.expect("own task ref").to_hex();
        let other_task_hex = other_create.task_ref.expect("other task ref").to_hex();
        let own_attempts: Vec<_> = records
            .iter()
            .filter(|attempt| attempt.task_ref.as_deref() == Some(own_task_hex.as_str()))
            .collect();
        let other_attempts: Vec<_> = records
            .iter()
            .filter(|attempt| attempt.task_ref.as_deref() == Some(other_task_hex.as_str()))
            .collect();
        assert_eq!(own_attempts.len(), 1);
        assert_eq!(other_attempts.len(), 1);
        let own_attempt = own_attempts[0];
        let other_attempt = other_attempts[0];
        assert_eq!(own_attempt.state, AttemptState::Cancelled);
        assert_eq!(other_attempt.state, AttemptState::Queued);
    }

    #[test]
    fn pending_cancel_proposes_without_intervening_realization() {
        let (_dir, vault) = open_vault();
        let own = own_agent(&vault);
        let facade = vault.memory_facade(own, EdgeActorClass::Agent);
        let created = facade.tasks_create(&spec(120)).expect("create task");
        let task_ref = created.task_ref.expect("task ref");

        let cancel = facade
            .tasks_cancel(TaskCancelTarget::Task(task_ref))
            .expect("propose cancel");
        let records = AttemptQueue::new(&vault).list().expect("list attempts");
        let task_hex = task_ref.to_hex();

        assert_eq!(usize::from(cancel.effected), 0);
        assert_eq!(cancel.approval, ClaimApprovalStatus::Proposed);
        assert_eq!(usize::from(cancel.proposal_ref.is_some()), 1);
        assert_eq!(
            vault
                .gate_decisions(512)
                .expect("gate decisions")
                .iter()
                .filter(|decision| {
                    cancel.gate_decision_ref.as_deref()
                        == Some(format!("gate:{}", decision.decision_id.to_hex()).as_str())
                        && decision.outcome == GateOutcome::Pending.as_str()
                })
                .count(),
            1
        );
        assert_eq!(
            records
                .iter()
                .filter(|record| {
                    record.task_ref.as_deref() == Some(task_hex.as_str())
                        && record.state == AttemptState::Queued
                })
                .count(),
            1
        );
        assert_eq!(
            usize::from(task_is_cancelled(&vault, task_ref).expect("cancel state")),
            0
        );
    }

    #[test]
    fn leased_realization_keeps_cancel_receipt_running() {
        let (_dir, vault) = open_vault();
        let own = own_agent(&vault);
        grant_cancel(&vault, own, 0xD2);
        let facade = vault.memory_facade(own, EdgeActorClass::Agent);
        let created = facade.tasks_create(&spec(120)).expect("create task");
        let task_ref = created.task_ref.expect("task ref");
        let queue = AttemptQueue::new(&vault);
        let claimed = match queue
            .claim_kind(
                TASK_REALIZE_ATTEMPT_KIND,
                ClaimAttempt {
                    lease_owner: "w1".to_owned(),
                    now: 120,
                },
            )
            .expect("claim realization")
        {
            ClaimOutcome::Claimed(claimed) => claimed,
            ClaimOutcome::Empty => panic!("realization must be claimable"),
        };

        let cancel = facade
            .tasks_cancel(TaskCancelTarget::Task(task_ref))
            .expect("cancel task");
        let post_cancel = queue
            .get(claimed.id)
            .expect("read realization")
            .expect("realization exists");
        let section = facade.tasks_check().expect("check tasks");

        // P1-a: a leased realization is NOT stoppable in-txn, so the cancel is
        // honest — it does not claim effect and does not hide the task.
        assert_eq!(usize::from(cancel.effected), 0);
        assert_eq!(cancel.status, Some(RunTreeStatus::Running));
        assert_eq!(
            usize::from(cancel.status == Some(RunTreeStatus::Cancelled)),
            0
        );
        assert_eq!(cancel.approval, ClaimApprovalStatus::Auto);
        assert_eq!(usize::from(cancel.proposal_ref.is_some()), 0);
        assert_eq!(post_cancel.state, AttemptState::Leased);
        // The task is NOT hidden while the lease keeps realizing (outbound
        // delivery included): the cancelled bit is not set.
        assert_eq!(
            usize::from(task_is_cancelled(&vault, task_ref).expect("cancel state")),
            0
        );
        // The board still shows the task exactly once — it folds to Running
        // under its live lease rather than vanishing.
        assert_eq!(
            section
                .rows
                .iter()
                .filter(|row| row.id == task_ref.to_hex())
                .count(),
            1
        );
    }

    #[test]
    fn terminal_task_cancel_is_uneffected_and_keeps_intent_folded() {
        let (_dir, vault) = open_vault();
        let own = own_agent(&vault);
        grant_cancel(&vault, own, 0xD3);
        let facade = vault.memory_facade(own, EdgeActorClass::Agent);
        let created = facade.tasks_create(&spec(120)).expect("create task");
        let task_ref = created.task_ref.expect("task ref");
        let task_hex = task_ref.to_hex();
        let queue = AttemptQueue::new(&vault);
        let claimed = match queue
            .claim_kind(
                TASK_REALIZE_ATTEMPT_KIND,
                ClaimAttempt {
                    lease_owner: "terminal-task-worker".to_owned(),
                    now: 120,
                },
            )
            .expect("claim realization")
        {
            ClaimOutcome::Claimed(claimed) => claimed,
            ClaimOutcome::Empty => panic!("realization must be claimable"),
        };
        queue
            .complete(CompleteAttempt {
                id: claimed.id,
                lease_owner: "terminal-task-worker".to_owned(),
                attempt_count: claimed.attempt_count,
                now: 121,
            })
            .expect("complete realization");

        let cancel = facade
            .tasks_cancel(TaskCancelTarget::Task(task_ref))
            .expect("cancel terminal task");
        let realization = queue
            .get(claimed.id)
            .expect("read realization")
            .expect("realization exists");
        let section = facade.tasks_check().expect("check tasks");
        let job_hex = attempt_hex(claimed.id);

        assert_eq!(usize::from(cancel.effected), 0);
        assert_eq!(cancel.status, Some(RunTreeStatus::Completed));
        assert_eq!(cancel.approval, ClaimApprovalStatus::Auto);
        assert_eq!(realization.state, AttemptState::Completed);
        assert_eq!(
            usize::from(task_is_cancelled(&vault, task_ref).expect("cancel state")),
            0
        );
        assert_eq!(
            section
                .rows
                .iter()
                .filter(|row| row.id == task_hex && row.status == TaskBoardStatus::Done)
                .count(),
            1
        );
        assert_eq!(
            section.rows.iter().filter(|row| row.id == job_hex).count(),
            0
        );
        assert_eq!(section.rows.len(), 1);
    }

    #[test]
    fn queued_completed_mix_cancel_preserves_terminal_fold_exactly_once() {
        assert_queued_terminal_mix_cancel(
            AttemptState::Completed,
            RunTreeStatus::Completed,
            TaskBoardStatus::Done,
        );
    }

    #[test]
    fn queued_failed_mix_cancel_preserves_terminal_fold_exactly_once() {
        assert_queued_terminal_mix_cancel(
            AttemptState::Failed,
            RunTreeStatus::Failed,
            TaskBoardStatus::Failed,
        );
    }

    // Deferred post-close (CB-04): traced root cause is NOT cancel-receipt
    // honesty. For an agent principal cancelling its OWN already-terminal
    // spawn, `check_external_effect_policy` resolves `Pending` (propose), not
    // `Allow`, so `tasks_cancel_resolved` returns at the gate branch with
    // `approval = Proposed, status = None` before the terminal-status path
    // runs. The receipt is therefore honest about the proposal; the terminal
    // `Some(Completed)`/`Auto` this test expects is unreachable until the
    // external-effect gate auto-allows an agent's self-cancel of its own
    // spawn. That is gate-authority-surface work (an owner decision on whether
    // agent spawn self-cancel is Auto), out of 1696 scope, and fail-closed
    // (propose ⊃ allow) so non-security. Re-enable once that authority lands.
    #[test]
    #[ignore = "CB-04 follow-up: agent spawn self-cancel proposes (gate Pending); Auto/Some(Completed) needs gate-authority change, deferred post-close, non-security"]
    fn terminal_spawn_cancel_is_uneffected_and_preserves_terminal_state() {
        let (_dir, vault) = open_vault();
        let own = EntityId::from_bytes([0xB3; 16]).expect("custom agent id");
        vault
            .fork_system_agent(
                &own,
                SystemAgentPreset::Keeper,
                "spawn-owner",
                TimeRange { start: 1, end: 1 },
                1,
            )
            .expect("fork custom agent");
        grant_cancel(&vault, own, 0xD4);
        let dispatcher = AgentDispatcher::new(&vault);
        let parent = match dispatcher
            .dispatch(DispatchAgent {
                target: AgentDispatchTarget::Custom(own),
                parent_attempt: None,
                dedupe_key: None,
                run_id: None,
                now: 120,
            })
            .expect("dispatch parent")
        {
            AgentDispatchOutcome::Dispatched(status) => status,
            AgentDispatchOutcome::Existing(_) => panic!("parent dispatch must be fresh"),
        };
        let child = match dispatcher
            .dispatch_default_base(Some(parent.attempt.id), None, None, 121)
            .expect("dispatch child")
        {
            AgentDispatchOutcome::Dispatched(status) => status,
            AgentDispatchOutcome::Existing(_) => panic!("child dispatch must be fresh"),
        };
        let queue = AttemptQueue::new(&vault);
        for (expected, lease_owner, now) in [
            (parent.attempt.id, "terminal-parent-worker", 122),
            (child.attempt.id, "terminal-child-worker", 123),
        ] {
            let claimed = match queue
                .claim_kind(
                    DREAMER_RUNNER_ATTEMPT_KIND,
                    ClaimAttempt {
                        lease_owner: lease_owner.to_owned(),
                        now,
                    },
                )
                .expect("claim dispatch")
            {
                ClaimOutcome::Claimed(claimed) => claimed,
                ClaimOutcome::Empty => panic!("dispatch must be claimable"),
            };
            assert_eq!(usize::from(claimed.id == expected), 1);
            queue
                .complete(CompleteAttempt {
                    id: claimed.id,
                    lease_owner: lease_owner.to_owned(),
                    attempt_count: claimed.attempt_count,
                    now,
                })
                .expect("complete dispatch");
        }

        let facade = vault.memory_facade(own, EdgeActorClass::Agent);
        let cancel = facade
            .tasks_cancel(TaskCancelTarget::Spawn(child.attempt.id))
            .expect("cancel terminal spawn");
        let terminal = queue
            .get(child.attempt.id)
            .expect("read child")
            .expect("child exists");

        assert_eq!(usize::from(cancel.effected), 0);
        assert_eq!(cancel.status, Some(RunTreeStatus::Completed));
        assert_eq!(cancel.approval, ClaimApprovalStatus::Auto);
        assert_eq!(terminal.state, AttemptState::Completed);
        assert_eq!(
            vault
                .gate_decisions(512)
                .expect("gate decisions")
                .iter()
                .filter(|decision| {
                    cancel.gate_decision_ref.as_deref()
                        == Some(format!("gate:{}", decision.decision_id.to_hex()).as_str())
                        && decision.outcome == GateOutcome::Allow.as_str()
                })
                .count(),
            1
        );
    }

    #[test]
    fn connector_send_cancel_cancels_queued_realization() {
        let (_dir, vault) = open_vault();
        let own = own_agent(&vault);
        let send_grant_ref = EntityId::from_bytes([0xD3; 16]).expect("send grant id");
        vault
            .mint_standing_outbound_grant(
                &send_grant_ref,
                &GrantMintIntent {
                    principal_ref: own.to_hex(),
                    origin_component_id: "tasks".to_owned(),
                    origin_action_id: "create".to_owned(),
                    origin_receipt_ref: None,
                    scope: GrantMintIntentScope::VerbClass {
                        verb_class: "send".to_owned(),
                    },
                },
                1,
            )
            .expect("mint send grant");
        grant_cancel(&vault, own, 0xD4);
        let facade = vault.memory_facade(own, EdgeActorClass::Agent);
        facade
            .schedule_outbound(&OutboundDraftInput {
                verb: "send".to_owned(),
                channel: "email".to_owned(),
                target: "x".to_owned(),
                on_behalf_of: None,
                content_ref: None,
                idempotency_key: Some("k1".to_owned()),
                dedupe_key: None,
                trigger: "agent_immediate".to_owned(),
                trigger_ref: "s1".to_owned(),
                job_ref: None,
                occurred_at: Some(120),
            })
            .expect("schedule send");
        let tasks = vault.connector_send_tasks().expect("connector tasks");
        assert_eq!(tasks.len(), 1);
        let task_ref = tasks[0].task_ref;

        let cancel = facade
            .tasks_cancel(TaskCancelTarget::Task(task_ref))
            .expect("cancel send");
        let attempts = AttemptQueue::new(&vault).list().expect("list attempts");
        let task_hex = task_ref.to_hex();

        assert_eq!(usize::from(cancel.effected), 1);
        assert_eq!(cancel.status, Some(RunTreeStatus::Cancelled));
        assert_eq!(
            attempts
                .iter()
                .filter(|attempt| {
                    attempt.task_ref.as_deref() == Some(task_hex.as_str())
                        && attempt.state == AttemptState::Cancelled
                })
                .count(),
            1
        );
        assert_eq!(
            attempts
                .iter()
                .filter(|attempt| {
                    attempt.task_ref.as_deref() == Some(task_hex.as_str())
                        && attempt.state == AttemptState::Queued
                })
                .count(),
            0
        );
    }

    #[test]
    fn role_only_task_is_present_and_cancel_fails_closed() {
        let (_dir, vault) = open_vault();
        let own = own_agent(&vault);
        grant_cancel(&vault, own, 0xD5);
        let task_ref = EntityId::from_bytes([0xB1; 16]).expect("task id");
        vault
            .put_entity(
                &task_ref,
                ENTITY_TYPE_TASK,
                TimeRange {
                    start: 120,
                    end: 120,
                },
                120,
                &crate::habit::task_body_for_test(TaskRole::Task),
            )
            .expect("put task");
        let outcome = AttemptQueue::new(&vault)
            .enqueue_with_task_ref(
                EnqueueAttempt {
                    kind: TASK_REALIZE_ATTEMPT_KIND.to_owned(),
                    payload: Vec::new(),
                    dedupe_key: None,
                    run_id: None,
                    now: 120,
                },
                Some(task_ref.to_hex()),
            )
            .expect("enqueue realization");
        let EnqueueOutcome::Enqueued(attempt) = outcome else {
            panic!("realization must enqueue");
        };
        let facade = vault.memory_facade(own, EdgeActorClass::Agent);

        let section = facade.tasks_check().expect("check tasks");
        assert_eq!(section.rows.len(), 1);
        assert_eq!(
            section
                .rows
                .iter()
                .filter(|row| row.id == task_ref.to_hex())
                .count(),
            1
        );

        let cancel = facade
            .tasks_cancel(TaskCancelTarget::Task(task_ref))
            .expect("cancel task");
        let realization = AttemptQueue::new(&vault)
            .get(attempt.id)
            .expect("read realization")
            .expect("realization exists");

        // P1-c: a role-only TASK carries no stored owner provenance, so cancel
        // fails closed to the foreign ladder — a proposal, never a direct
        // effect. The realizing attempt is untouched (still Queued), and the
        // task stays visible (asserted above: fix-r1 F6 is preserved).
        assert_eq!(usize::from(cancel.effected), 0);
        assert_eq!(cancel.approval, ClaimApprovalStatus::Proposed);
        assert_eq!(usize::from(cancel.proposal_ref.is_some()), 1);
        assert_eq!(realization.state, AttemptState::Queued);
    }

    #[test]
    fn ack_persists_and_removes_failed_task_from_render() {
        let (_dir, vault) = open_vault();
        let own = own_agent(&vault);
        let facade = vault.memory_facade(own, EdgeActorClass::Agent);
        let created = facade.tasks_create(&spec(120)).expect("create task");
        let task_ref = created.task_ref.expect("task ref");
        let queue = AttemptQueue::new(&vault);
        let claimed = match queue
            .claim_kind(
                TASK_REALIZE_ATTEMPT_KIND,
                ClaimAttempt {
                    lease_owner: "worker".to_owned(),
                    now: 120,
                },
            )
            .expect("claim")
        {
            ClaimOutcome::Claimed(claimed) => claimed,
            ClaimOutcome::Empty => panic!("created task must be claimable"),
        };
        queue
            .fail(FailAttempt {
                id: claimed.id,
                lease_owner: "worker".to_owned(),
                attempt_count: claimed.attempt_count,
                reason: "failed".to_owned(),
                now: 121,
            })
            .expect("fail task");

        let before = facade.tasks_check().expect("check before ack");
        assert_eq!(before.rows.len(), 1);
        assert_eq!(before.rows[0].status, TaskBoardStatus::Failed);
        assert!(!task_is_acked(&vault, task_ref).expect("read unacked state"));
        // An unacked failure is still expandable by id.
        assert!(facade.tasks_expand(task_ref).is_ok());
        let ack = facade.tasks_ack(task_ref).expect("ack task");
        assert!(ack.acked);
        assert!(task_is_acked(&vault, task_ref).expect("read ack"));
        // Once acked, the failure has left the surface — expand agrees with check.
        assert_eq!(
            facade
                .tasks_expand(task_ref)
                .expect_err("acked failure is not expandable")
                .code,
            crate::facade::FACADE_CODE_NOT_FOUND
        );
        let after = facade.tasks_check().expect("check after ack");
        assert_eq!(after.rows.len(), 0);
    }

    #[test]
    fn ack_before_failure_is_a_noop_and_failure_still_surfaces() {
        let (_dir, vault) = open_vault();
        let own = own_agent(&vault);
        let facade = vault.memory_facade(own, EdgeActorClass::Agent);
        let created = facade.tasks_create(&spec(120)).expect("create task");
        let task_ref = created.task_ref.expect("task ref");

        // The task is Queued (not failed): acking it is a no-op — the bit stays
        // unset so a later failure is not pre-suppressed.
        let premature = facade.tasks_ack(task_ref).expect("ack queued task");
        assert!(!premature.acked);
        assert!(!task_is_acked(&vault, task_ref).expect("no ack bit set"));

        // The realization now fails.
        let queue = AttemptQueue::new(&vault);
        let claimed = match queue
            .claim_kind(
                TASK_REALIZE_ATTEMPT_KIND,
                ClaimAttempt {
                    lease_owner: "worker".to_owned(),
                    now: 120,
                },
            )
            .expect("claim")
        {
            ClaimOutcome::Claimed(claimed) => claimed,
            ClaimOutcome::Empty => panic!("created task must be claimable"),
        };
        queue
            .fail(FailAttempt {
                id: claimed.id,
                lease_owner: "worker".to_owned(),
                attempt_count: claimed.attempt_count,
                reason: "failed".to_owned(),
                now: 121,
            })
            .expect("fail task");

        // The failure STILL surfaces — the premature ack did not suppress it.
        let after_fail = facade.tasks_check().expect("check after fail");
        assert_eq!(after_fail.rows.len(), 1);
        assert_eq!(after_fail.rows[0].status, TaskBoardStatus::Failed);

        // A real ack (now that it is failed) removes it from the surface.
        let acked = facade.tasks_ack(task_ref).expect("ack failed task");
        assert!(acked.acked);
        assert_eq!(facade.tasks_check().expect("check after ack").rows.len(), 0);
    }

    #[test]
    fn malformed_dreamer_row_does_not_poison_the_board() {
        let (_dir, vault) = open_vault();
        let own = own_agent(&vault);
        let facade = vault.memory_facade(own, EdgeActorClass::Agent);
        // A healthy TASK.
        let created = facade.tasks_create(&spec(120)).expect("create task");
        let task_ref = created.task_ref.expect("task ref");
        // A malformed dreamer-kind row enqueued through the public queue API (as
        // a downstream product could): 0xC1 is the reserved, never-valid
        // MessagePack marker, so the payload envelope never decodes.
        let queue = AttemptQueue::new(&vault);
        let EnqueueOutcome::Enqueued(_) = queue
            .enqueue(EnqueueAttempt {
                kind: DREAMER_RUNNER_ATTEMPT_KIND.to_owned(),
                payload: vec![0xC1],
                dedupe_key: None,
                run_id: None,
                now: 121,
            })
            .expect("enqueue malformed dreamer row")
        else {
            panic!("malformed row must enqueue");
        };
        // The board still reads for the unrelated healthy TASK — one bad row
        // degrades to a bare job in the run tree instead of poisoning the whole
        // read (previously the tree read errored and failed tasks.check/expand).
        let section = facade
            .tasks_check()
            .expect("board reads despite the malformed row");
        assert_eq!(
            section
                .rows
                .iter()
                .filter(|row| row.id == task_ref.to_hex())
                .count(),
            1
        );
        // The typed read verb for the healthy TASK also works.
        assert!(facade.tasks_expand(task_ref).is_ok());
    }

    /// P1-a: a Queued+Leased mix cannot be fully cancelled in-txn (the lease
    /// can't be stopped), so the cancel is honest — uneffected, nothing hidden,
    /// nothing intervened — and the task stays visible under its live lease.
    #[test]
    fn queued_leased_mix_cancel_is_honest_and_not_hidden() {
        let (_dir, vault) = open_vault();
        let own = own_agent(&vault);
        grant_cancel(&vault, own, 0xD6);
        let facade = vault.memory_facade(own, EdgeActorClass::Agent);
        let created = facade.tasks_create(&spec(120)).expect("create task");
        let task_ref = created.task_ref.expect("task ref");
        let task_hex = task_ref.to_hex();
        let queue = AttemptQueue::new(&vault);
        // Second realizing attempt so the task has a Queued + Leased mix.
        assert!(matches!(
            queue
                .enqueue_with_task_ref(
                    EnqueueAttempt {
                        kind: TASK_REALIZE_ATTEMPT_KIND.to_owned(),
                        payload: Vec::new(),
                        dedupe_key: None,
                        run_id: None,
                        now: 120,
                    },
                    Some(task_hex.clone()),
                )
                .expect("enqueue second realization"),
            EnqueueOutcome::Enqueued(_)
        ));
        // Lease exactly one realization; the other stays Queued.
        match queue
            .claim_kind(
                TASK_REALIZE_ATTEMPT_KIND,
                ClaimAttempt {
                    lease_owner: "w1".to_owned(),
                    now: 120,
                },
            )
            .expect("claim one realization")
        {
            ClaimOutcome::Claimed(_) => {}
            ClaimOutcome::Empty => panic!("a realization must be claimable"),
        }

        let cancel = facade
            .tasks_cancel(TaskCancelTarget::Task(task_ref))
            .expect("cancel task");
        let records = queue.list().expect("list attempts");
        let section = facade.tasks_check().expect("check tasks");

        assert_eq!(usize::from(cancel.effected), 0);
        assert_eq!(cancel.status, Some(RunTreeStatus::Running));
        assert_eq!(
            usize::from(task_is_cancelled(&vault, task_ref).expect("cancel state")),
            0
        );
        // Neither attempt was touched: exactly one Leased, exactly one Queued.
        assert_eq!(
            records
                .iter()
                .filter(|r| r.task_ref.as_deref() == Some(task_hex.as_str())
                    && r.state == AttemptState::Leased)
                .count(),
            1
        );
        assert_eq!(
            records
                .iter()
                .filter(|r| r.task_ref.as_deref() == Some(task_hex.as_str())
                    && r.state == AttemptState::Queued)
                .count(),
            1
        );
        // The board still shows the task exactly once.
        assert_eq!(
            section.rows.iter().filter(|row| row.id == task_hex).count(),
            1
        );
    }

    /// P1-b (TOCTOU): the cancel acts on the transaction-current attempt state,
    /// not a pre-txn snapshot. A stale `Leased` snapshot whose live state is now
    /// `Queued` must still be cancelled in-txn.
    #[test]
    fn cancel_uses_in_txn_live_state_not_stale_leased_snapshot() {
        let (_dir, vault) = open_vault();
        let own = own_agent(&vault);
        grant_cancel(&vault, own, 0xDB);
        let facade = vault.memory_facade(own, EdgeActorClass::Agent);
        let created = facade.tasks_create(&spec(120)).expect("create task");
        let task_ref = created.task_ref.expect("task ref");
        let task_hex = task_ref.to_hex();
        let queue = AttemptQueue::new(&vault);
        let records = queue.list().expect("list attempts");
        let attempt = records
            .iter()
            .find(|r| r.task_ref.as_deref() == Some(task_hex.as_str()))
            .expect("realizing attempt");
        // Live state is Queued (as if a lease-cleanup requeue already happened).
        assert_eq!(attempt.state, AttemptState::Queued);

        // A deliberately STALE snapshot claims the attempt is still Leased.
        let stale = CancelTargetState {
            owned: true,
            task_ref: Some(task_ref),
            attempts: vec![(attempt.id, AttemptState::Leased)],
            proposal_subject: task_ref,
            target_ref: task_hex.clone(),
        };
        let cancel = facade
            .tasks_cancel_with_injected_state_for_test(TaskCancelMode::Auto, stale)
            .expect("cancel with stale snapshot");
        let after = queue.list().expect("list after");

        // The in-txn re-read acts on the LIVE (Queued) state and cancels it,
        // despite the stale Leased snapshot. Trusting the snapshot would skip
        // intervention and leave the attempt claimable.
        assert_eq!(usize::from(cancel.effected), 1);
        assert_eq!(cancel.status, Some(RunTreeStatus::Cancelled));
        assert_eq!(
            after
                .iter()
                .filter(|r| r.task_ref.as_deref() == Some(task_hex.as_str())
                    && r.state == AttemptState::Cancelled)
                .count(),
            1
        );
        assert_eq!(
            after
                .iter()
                .filter(|r| r.task_ref.as_deref() == Some(task_hex.as_str())
                    && r.state == AttemptState::Queued)
                .count(),
            0
        );
    }

    /// P1-c: a stored, `tasks.cancel`-granted actor cannot DIRECTLY cancel a
    /// role-only task it cannot prove it owns — it surfaces a proposal. Role-only
    /// ownership is not derivable from storage, so the fallback fails closed.
    #[test]
    fn role_only_task_cancel_by_foreign_granted_actor_proposes() {
        let (_dir, vault) = open_vault();
        let agent_b = own_agent(&vault);
        grant_cancel(&vault, agent_b, 0xD8);
        // Role-only TASK nominally belonging to some agent A; no stored
        // provenance links it to any actor.
        let task_ref = EntityId::from_bytes([0xB2; 16]).expect("task id");
        vault
            .put_entity(
                &task_ref,
                ENTITY_TYPE_TASK,
                TimeRange {
                    start: 120,
                    end: 120,
                },
                120,
                &crate::habit::task_body_for_test(TaskRole::Task),
            )
            .expect("put role-only task");
        let outcome = AttemptQueue::new(&vault)
            .enqueue_with_task_ref(
                EnqueueAttempt {
                    kind: TASK_REALIZE_ATTEMPT_KIND.to_owned(),
                    payload: Vec::new(),
                    dedupe_key: None,
                    run_id: None,
                    now: 120,
                },
                Some(task_ref.to_hex()),
            )
            .expect("enqueue realization");
        let EnqueueOutcome::Enqueued(attempt) = outcome else {
            panic!("realization must enqueue");
        };
        let facade = vault.memory_facade(agent_b, EdgeActorClass::Agent);

        let cancel = facade
            .tasks_cancel(TaskCancelTarget::Task(task_ref))
            .expect("cancel role-only task");
        let realization = AttemptQueue::new(&vault)
            .get(attempt.id)
            .expect("read realization")
            .expect("realization exists");
        let section = facade.tasks_check().expect("check tasks");

        assert_eq!(usize::from(cancel.effected), 0);
        assert_eq!(cancel.approval, ClaimApprovalStatus::Proposed);
        assert_eq!(usize::from(cancel.proposal_ref.is_some()), 1);
        // The realizing attempt is untouched and the task stays visible.
        assert_eq!(realization.state, AttemptState::Queued);
        assert_eq!(
            usize::from(task_is_cancelled(&vault, task_ref).expect("cancel state")),
            0
        );
        assert_eq!(
            section
                .rows
                .iter()
                .filter(|row| row.id == task_ref.to_hex())
                .count(),
            1
        );
    }

    /// FIX A: a valid typed body can claim any `owner_ref`, so that field is
    /// never cancellation authority. The create-time owner record remains the
    /// sole proof even if trusted low-level storage rewrites the body.
    #[test]
    fn typed_task_cancel_ignores_forged_body_owner() {
        let (_dir, vault) = open_vault();
        let attacker = own_agent(&vault);
        let owner = EntityId::from_bytes([0xE2; 16]).expect("owner id");
        put_person(&vault, owner);
        grant_cancel(&vault, attacker, 0xD9);
        let created = vault
            .memory_facade(owner, EdgeActorClass::Human)
            .tasks_create(&spec(120))
            .expect("owner creates task");
        let task_ref = created.task_ref.expect("task ref");
        let mut forged_body = task_verb_body(&vault, task_ref)
            .expect("decode created body")
            .expect("created task is typed");
        forged_body.owner_ref = attacker.to_hex();
        let forged_body = encode_task_verb_body(forged_body).expect("encode forged body");
        vault
            .put_entity(
                &task_ref,
                ENTITY_TYPE_TASK,
                TimeRange {
                    start: 121,
                    end: 121,
                },
                121,
                &forged_body,
            )
            .expect("rewrite body below facade");
        let forged = task_verb_body(&vault, task_ref)
            .expect("decode forged body")
            .expect("typed task");
        let cancel = vault
            .memory_facade(attacker, EdgeActorClass::Agent)
            .tasks_cancel(TaskCancelTarget::Task(task_ref))
            .expect("cancel forged-owner task");
        let task_hex = task_ref.to_hex();
        let attempts = AttemptQueue::new(&vault).list().expect("list attempts");

        assert_eq!(usize::from(forged.owner_ref == attacker.to_hex()), 1);
        assert_eq!(
            task_create_owner(&vault, task_ref).expect("read proven owner"),
            Some(owner)
        );
        assert_eq!(usize::from(cancel.effected), 0);
        assert_eq!(cancel.approval, ClaimApprovalStatus::Proposed);
        assert_eq!(usize::from(cancel.proposal_ref.is_some()), 1);
        assert_eq!(
            attempts
                .iter()
                .filter(|attempt| {
                    attempt.task_ref.as_deref() == Some(task_hex.as_str())
                        && attempt.state == AttemptState::Queued
                })
                .count(),
            1
        );
        assert_eq!(
            attempts
                .iter()
                .filter(|attempt| {
                    attempt.task_ref.as_deref() == Some(task_hex.as_str())
                        && attempt.state == AttemptState::Cancelled
                })
                .count(),
            0
        );
        assert_eq!(
            usize::from(task_is_cancelled(&vault, task_ref).expect("cancel state")),
            0
        );
    }

    /// P2 F6: only the `Task` role folds into TASKS. A `Habit`-role entity is
    /// not a task and must not render as a TASKS row.
    #[test]
    fn only_task_role_folds_into_tasks_section() {
        let (_dir, vault) = open_vault();
        let own = own_agent(&vault);
        let task_role = EntityId::from_bytes([0xB3; 16]).expect("task role id");
        let habit_role = EntityId::from_bytes([0xB4; 16]).expect("habit role id");
        vault
            .put_entity(
                &task_role,
                ENTITY_TYPE_TASK,
                TimeRange {
                    start: 120,
                    end: 120,
                },
                120,
                &crate::habit::task_body_for_test(TaskRole::Task),
            )
            .expect("put task-role");
        vault
            .put_entity(
                &habit_role,
                ENTITY_TYPE_TASK,
                TimeRange {
                    start: 120,
                    end: 120,
                },
                120,
                &crate::habit::task_body_for_test(TaskRole::Habit),
            )
            .expect("put habit-role");
        let facade = vault.memory_facade(own, EdgeActorClass::Agent);

        let section = facade.tasks_check().expect("check tasks");

        assert_eq!(
            section
                .rows
                .iter()
                .filter(|row| row.id == task_role.to_hex())
                .count(),
            1
        );
        assert_eq!(
            section
                .rows
                .iter()
                .filter(|row| row.id == habit_role.to_hex())
                .count(),
            0
        );
        assert_eq!(section.rows.len(), 1);
    }

    /// P2 F7: a realizing job whose backlink names no surviving intent is
    /// re-emitted as a bare job — rendered exactly once, never dropped.
    #[test]
    fn dangling_backlink_job_still_renders_once() {
        let (_dir, vault) = open_vault();
        let own = own_agent(&vault);
        let missing_task_hex = EntityId::from_bytes([0xC1; 16])
            .expect("missing id")
            .to_hex();
        let outcome = AttemptQueue::new(&vault)
            .enqueue_with_task_ref(
                EnqueueAttempt {
                    kind: TASK_REALIZE_ATTEMPT_KIND.to_owned(),
                    payload: Vec::new(),
                    dedupe_key: None,
                    run_id: None,
                    now: 120,
                },
                Some(missing_task_hex),
            )
            .expect("enqueue dangling attempt");
        let EnqueueOutcome::Enqueued(attempt) = outcome else {
            panic!("attempt must enqueue");
        };
        let facade = vault.memory_facade(own, EdgeActorClass::Agent);

        let section = facade.tasks_check().expect("check tasks");
        let job_id = attempt_hex(attempt.id);

        assert_eq!(
            section.rows.iter().filter(|row| row.id == job_id).count(),
            1
        );
        assert_eq!(section.rows.len(), 1);
    }

    /// FIX C: projection failure/non-membership cannot consume a live job.
    /// Both jobs degrade to bare rows exactly once when their backlink entity
    /// cannot produce a TASKS intent.
    #[test]
    fn unprojectable_task_backlinks_render_jobs_exactly_once() {
        let (_dir, vault) = open_vault();
        let own = own_agent(&vault);
        let malformed = EntityId::from_bytes([0xC2; 16]).expect("malformed id");
        let non_task_role = EntityId::from_bytes([0xC3; 16]).expect("non-task role id");
        let malformed_body = {
            let value = Value::Map(vec![
                (Value::from("role"), Value::from(TaskRole::Task.role_byte())),
                (Value::from("subkind"), Value::from(TASK_VERB_BODY_SUBKIND)),
            ]);
            let mut bytes = Vec::new();
            rmpv::encode::write_value(&mut bytes, &value).expect("encode malformed body");
            bytes
        };
        vault
            .put_entity(
                &malformed,
                ENTITY_TYPE_TASK,
                TimeRange {
                    start: 120,
                    end: 120,
                },
                120,
                &malformed_body,
            )
            .expect("put malformed task");
        vault
            .put_entity(
                &non_task_role,
                ENTITY_TYPE_TASK,
                TimeRange {
                    start: 120,
                    end: 120,
                },
                120,
                &crate::habit::task_body_for_test(TaskRole::Habit),
            )
            .expect("put non-task role");
        let queue = AttemptQueue::new(&vault);
        let attempts: Vec<_> = [malformed, non_task_role]
            .into_iter()
            .map(|task_ref| {
                match queue
                    .enqueue_with_task_ref(
                        EnqueueAttempt {
                            kind: TASK_REALIZE_ATTEMPT_KIND.to_owned(),
                            payload: Vec::new(),
                            dedupe_key: None,
                            run_id: None,
                            now: 120,
                        },
                        Some(task_ref.to_hex()),
                    )
                    .expect("enqueue realization")
                {
                    EnqueueOutcome::Enqueued(attempt) => attempt,
                    EnqueueOutcome::Existing(_) => panic!("realization must be fresh"),
                }
            })
            .collect();

        let section = vault
            .memory_facade(own, EdgeActorClass::Agent)
            .tasks_check()
            .expect("check tasks");
        let malformed_job = attempt_hex(attempts[0].id);
        let non_task_job = attempt_hex(attempts[1].id);

        assert_eq!(
            section
                .rows
                .iter()
                .filter(|row| row.id == malformed_job)
                .count(),
            1
        );
        assert_eq!(
            section
                .rows
                .iter()
                .filter(|row| row.id == non_task_job)
                .count(),
            1
        );
        assert_eq!(
            section
                .rows
                .iter()
                .filter(|row| row.id == malformed.to_hex())
                .count(),
            0
        );
        assert_eq!(
            section
                .rows
                .iter()
                .filter(|row| row.id == non_task_role.to_hex())
                .count(),
            0
        );
        assert_eq!(section.rows.len(), 2);
    }

    /// P2 F8: one malformed TASK body (typed subkind but missing the typed
    /// fields) must not abort the whole board — it is skipped, and every other
    /// task still renders.
    #[test]
    fn malformed_task_body_does_not_poison_the_board() {
        let (_dir, vault) = open_vault();
        let own = own_agent(&vault);
        let facade = vault.memory_facade(own, EdgeActorClass::Agent);
        let created = facade.tasks_create(&spec(120)).expect("create task");
        let valid_task = created.task_ref.expect("task ref");
        let poison = EntityId::from_bytes([0xC2; 16]).expect("poison id");
        let poison_body = {
            let value = Value::Map(vec![
                (Value::from("role"), Value::from(TaskRole::Task.role_byte())),
                (Value::from("subkind"), Value::from(TASK_VERB_BODY_SUBKIND)),
            ]);
            let mut bytes = Vec::new();
            rmpv::encode::write_value(&mut bytes, &value).expect("encode poison body");
            bytes
        };
        vault
            .put_entity(
                &poison,
                ENTITY_TYPE_TASK,
                TimeRange {
                    start: 120,
                    end: 120,
                },
                120,
                &poison_body,
            )
            .expect("put poison task");

        let section = facade.tasks_check().expect("check tasks survives poison");

        assert_eq!(
            section
                .rows
                .iter()
                .filter(|row| row.id == valid_task.to_hex())
                .count(),
            1
        );
        assert_eq!(
            section
                .rows
                .iter()
                .filter(|row| row.id == poison.to_hex())
                .count(),
            0
        );
        assert_eq!(section.rows.len(), 1);
    }
}
