use rmpv::Value;

use crate::agent_dispatch::{
    AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher, DispatchAgent,
};
use crate::attempt_queue::{AttemptId, AttemptQueue, EnqueueAttempt, EnqueueOutcome};
use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus};
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::facade::{FacadeResult, MemoryFacade, facade_provenance, verify_actor_binding};
use crate::gate::PolicyApprovalCeiling;
use crate::habit::TaskRole;
use crate::human_task::{register_human_followup_in_txn, resolve_native_human_route};
use crate::registry::ENTITY_TYPE_TASK;
use crate::temporal::TimeRange;
use crate::unix_seconds_now;

use super::consts::{
    TASK_CREATE_PROPOSAL_PREDICATE, TASK_REALIZE_ATTEMPT_KIND, TASK_VERB_BODY_SCHEMA_VERSION,
    TASK_VERB_BODY_SUBKIND,
};
use super::consult_result::TaskVerbBody;
use super::create_spec::{TaskCreateRateLimit, TaskCreateSpec};
use super::create_validation::{
    ValidatedTaskCreate, human_route_refusal, task_create_proposal_value, task_route_dedupe_key,
    validate_task_create,
};
use super::rate_limit::{
    consume_create_rate_slot, record_task_create_owner_in_txn, task_actor_ceiling,
    task_verb_contract,
};
use super::route_receipts::{TaskCreateReceipt, TaskRouteOutcome};
use super::terminal_state::TaskExecutionState;
use super::verb_kind::{TaskAssignee, TasksVerb};
use super::wire_encode::{canonical_bytes, encode_task_realization_input, encode_task_verb_body};

/// Canonical bytes of one create-proposal payload with its `created_at`
/// stamp neutralized — the dedupe identity of the ASK, independent of when it
/// was made.
fn create_proposal_identity(value: &Value) -> Vec<u8> {
    let Value::Map(entries) = value else {
        return canonical_bytes(value);
    };
    let neutralized = entries
        .iter()
        .map(|(key, value)| {
            if key.as_str() == Some("created_at") {
                (key.clone(), Value::from(0_u64))
            } else {
                (key.clone(), value.clone())
            }
        })
        .collect();
    canonical_bytes(&Value::Map(neutralized))
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
        // The typed shape is settled BEFORE any write transaction opens: an
        // invalid consult never reaches the TASK write, so a rejected request
        // leaves no partial entity and burns no rate slot.
        let validated = validate_task_create(self.vault(), spec, now)?;
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

            let owner_ref = spec.owner_ref.unwrap_or_else(|| self.actor());
            let task_ref = self.mint_task_in_txn(
                wtxn,
                &validated,
                spec.label.clone(),
                owner_ref,
                &provenance,
                now,
            )?;
            // The TASK and its realizing work commit together, so a route
            // failure rolls the intent back rather than leaving an invisible
            // half-created task behind.
            let route = self.route_created_task_in_txn(wtxn, task_ref, &validated, now)?;
            Ok(Some((task_ref, route)))
        })?;

        if let Some((task_ref, route)) = direct {
            return Ok(TaskCreateReceipt {
                task_ref: Some(task_ref),
                proposal_ref: None,
                approval: ClaimApprovalStatus::Auto,
                effected: true,
                route: Some(route),
            });
        }

        // Quota overflow falls through to a proposal rather than a refusal
        // (ONE-1696 §4, own-agent lane), so a caller retrying past quota is
        // asking the SAME question again. It parks on the row already waiting
        // for the owner instead of minting one row per attempt.
        let proposal_ref = match self.open_create_proposal_for_spec(spec, now)? {
            Some(existing) => existing,
            None => {
                self.persist_task_proposal(
                    TASK_CREATE_PROPOSAL_PREDICATE,
                    task_create_proposal_value(spec, now),
                    self.actor(),
                    now,
                    provenance,
                )?
                .0
            }
        };
        Ok(TaskCreateReceipt {
            task_ref: None,
            proposal_ref: Some(proposal_ref),
            approval: ClaimApprovalStatus::Proposed,
            effected: false,
            route: None,
        })
    }

    /// The OPEN `tasks.create` proposal this actor already parked for an
    /// identical ask, if any.
    ///
    /// Identity is the proposal payload with its `created_at` stamp
    /// neutralized: a retry is the same ask, only later. Only an ACTIVE,
    /// still-`Proposed` row counts — once the owner settles or withdraws one,
    /// the next create parks a fresh proposal.
    fn open_create_proposal_for_spec(
        &self,
        spec: &TaskCreateSpec,
        now: u64,
    ) -> FacadeResult<Option<EntityId>> {
        let wanted = create_proposal_identity(&task_create_proposal_value(spec, now));
        let rtxn = self.vault().store.env.read_txn().map_err(Error::from)?;
        for id in self
            .vault()
            .claims_for_subject_in_txn(&rtxn, &self.actor())?
        {
            let Some(body) = self.vault().get_claim_in_txn(&rtxn, &id)? else {
                continue;
            };
            if body.predicate != TASK_CREATE_PROPOSAL_PREDICATE
                || body.lifecycle != ClaimLifecycleStatus::Active
                || body.approval != ClaimApprovalStatus::Proposed
            {
                continue;
            }
            if create_proposal_identity(&body.value) == wanted {
                return Ok(Some(id));
            }
        }
        Ok(None)
    }

    /// Mints one TASK entity plus its create-time owner record.
    ///
    /// The realizing attempt is deliberately NOT part of this: a consult mints
    /// the CRDT-synced entity and nothing else, because a node-local lease can
    /// never reach a peer on another machine.
    pub(super) fn mint_task_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        validated: &ValidatedTaskCreate,
        label: Option<String>,
        owner_ref: EntityId,
        provenance: &Value,
        now: u64,
    ) -> FacadeResult<EntityId> {
        let task_ref = EntityId::now();
        let body = encode_task_verb_body(TaskVerbBody {
            role: TaskRole::Task.role_byte(),
            schema_version: TASK_VERB_BODY_SCHEMA_VERSION,
            subkind: TASK_VERB_BODY_SUBKIND.to_owned(),
            kind: Some(validated.kind),
            owner_ref: owner_ref.to_hex(),
            assignee: validated.assignee,
            label,
            spec: validated.spec.clone(),
            consult: validated.consult.clone(),
            ttl: validated.ttl,
            state: Some(TaskExecutionState::Queued),
            provenance: provenance.clone(),
            created_at: now,
        });
        self.put_task_body_in_txn(wtxn, task_ref, &body, now)?;
        record_task_create_owner_in_txn(self.vault(), wtxn, task_ref, owner_ref)?;
        Ok(task_ref)
    }

    pub(super) fn put_task_body_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        task_ref: EntityId,
        body: &[u8],
        now: u64,
    ) -> FacadeResult<()> {
        let occurred = TimeRange {
            start: now,
            end: now,
        };
        self.vault()
            .batch_in()
            .put(&task_ref, ENTITY_TYPE_TASK, occurred, now, body)
            .apply(wtxn)?;
        Ok(())
    }

    /// The engine — never the agent — decides the realizing job, and
    /// `TASK.assignee` is the only thing it decides from: never the label, the
    /// spec prose, the caller's harness, or the model vendor.
    ///
    /// The match is exhaustive so a new assignee variant cannot silently
    /// default into Dreamer realization.
    pub(super) fn route_created_task_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        task_ref: EntityId,
        validated: &ValidatedTaskCreate,
        now: u64,
    ) -> FacadeResult<TaskRouteOutcome> {
        match validated.assignee {
            // Absent assignee is the schema-v1 representation of the Dreamer
            // lane and routes identically — old rows are never rewritten.
            None | Some(TaskAssignee::Dreamer) => {
                let attempt_ref =
                    self.enqueue_task_realization_in_txn(wtxn, task_ref, &validated.spec, now)?;
                Ok(TaskRouteOutcome::DreamerAttempt { attempt_ref })
            }
            Some(TaskAssignee::AgentDef { agent_def_ref }) => {
                let outcome = AgentDispatcher::new(self.vault()).dispatch_for_task_in_txn(
                    wtxn,
                    task_ref,
                    DispatchAgent {
                        target: AgentDispatchTarget::Custom(agent_def_ref),
                        parent_attempt: None,
                        dedupe_key: Some(task_route_dedupe_key(task_ref)),
                        run_id: None,
                        now,
                    },
                )?;
                // Dispatched and deduped-existing are ONE idempotent outcome: a
                // retried route returns the attempt already realizing the task.
                let (AgentDispatchOutcome::Dispatched(status)
                | AgentDispatchOutcome::Existing(status)) = outcome;
                Ok(TaskRouteOutcome::AgentDispatch {
                    attempt_ref: status.attempt.id,
                    agent_def_ref,
                })
            }
            // The synced TASK is the transport. A local attempt could never
            // reach an executor on another machine, so none is minted.
            Some(TaskAssignee::Peer { actor_ref }) => {
                Ok(TaskRouteOutcome::PeerSyncedOnly { actor_ref })
            }
            // A person is not a worker. The TASK row and its follow-up cursor
            // commit together and NOTHING else is minted: no `tasks.realize`
            // attempt, no task-linked queue row, no dispatcher call. Follow-up
            // is Dreamer maintenance over the synced TASK fact, never a hidden
            // executor realizing the task on the person's behalf.
            Some(TaskAssignee::Human { actor_ref }) => {
                let route = resolve_native_human_route(self.vault(), actor_ref)
                    .map_err(human_route_refusal)?;
                register_human_followup_in_txn(
                    self.vault(),
                    wtxn,
                    task_ref,
                    route.person_ref,
                    now,
                )?;
                Ok(TaskRouteOutcome::HumanFollowup {
                    actor_ref: route.person_ref,
                })
            }
        }
    }

    /// Enqueues the one existing `tasks.realize` attempt for the Dreamer lane,
    /// keyed on the TASK so a retry can never mint a second realization.
    fn enqueue_task_realization_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        task_ref: EntityId,
        spec: &Value,
        now: u64,
    ) -> FacadeResult<AttemptId> {
        let outcome = AttemptQueue::new(self.vault()).enqueue_with_task_ref_in_txn(
            wtxn,
            EnqueueAttempt {
                kind: TASK_REALIZE_ATTEMPT_KIND.to_owned(),
                payload: encode_task_realization_input(spec)?,
                dedupe_key: Some(task_route_dedupe_key(task_ref)),
                run_id: None,
                now,
            },
            Some(task_ref.to_hex()),
        )?;
        let (EnqueueOutcome::Enqueued(record) | EnqueueOutcome::Existing(record)) = outcome;
        Ok(record.id)
    }
}
