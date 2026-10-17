//! The one task-domain door (OF-220): post, accept, report and status for
//! MCP tool-first, the HTTP facade and code mode alike.
//!
//! Grant and Scope are the one path for permissions and decide() the one
//! path for typed decisions (ARCH-0076); tasks get one domain door, and each
//! transport only builds a [`TaskCall`]. Every arm runs the same pipeline:
//! decode and validate the typed input and refuse before any write; prove
//! the actor; ask any surface question outside the write transaction, its
//! evidence re-checked at commit; commit the domain op in one write
//! transaction; return the durable handle.
//!
//! The door invents no check. It verifies the actor binding as every facade
//! does, proves the actor's TASK role through L02's rule over the immutable
//! authority facts ([`Memory::highway_task_actor_in`]), and runs the
//! per-leaf write gate `tasks_create` already runs. Payer, membership and
//! admission are neither read nor written here.

use std::collections::BTreeMap;

use rmpv::Value;

use crate::Vault;
use crate::attempt_queue::{AttemptId, AttemptRecord};
use crate::authority::{TaskActorProof, TaskActorVerb, actor_binding_is_active};
use crate::entity_id::EntityId;
use crate::error::{ClaimError, Error};
use crate::memory::{
    MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INVALID_STATE, Memory, MemoryError, MemoryResult,
    verify_actor_binding,
};
use crate::task_authority::{BindingGeneration, TaskStanding};
use crate::write_envelope::WriteActor;

use super::brief::StoredBrief;
use super::consult_result::TaskVerbBody;
use super::create_validation::consult_refusal;
use super::decision_port::TaskDecisions;
use super::highway_types::{
    AttemptHandle, TaskAccept, TaskCall, TaskCallReceipt, TaskLifecycleRecord, TaskPhase, TaskPost,
    TaskReport, TaskStatusQuery, TaskVia,
};
use super::terminal_state::TaskExecutionState;
use super::wire_encode::encode_task_verb_body;

/// Longest intent or report key a call may name.
const MAX_HIGHWAY_KEY_LEN: usize = 256;
/// Domain of the lease owner's binding digest.
const LEASE_OWNER_DOMAIN: &[u8] = b"oneiron.tasks.lease_owner.v1";

impl Memory<'_> {
    /// The one task-domain door. The actor is this surface's, verified per
    /// call exactly as every facade verifies it; `via` carries a host's
    /// lease, which the actor alone cannot prove.
    pub fn tasks_highway(&self, via: TaskVia, call: TaskCall) -> MemoryResult<TaskCallReceipt> {
        self.tasks_highway_with_decisions(via, call, None)
    }

    /// [`Self::tasks_highway`] under a host's decision path. With `None`,
    /// every surface question asks up, so a person is asked.
    pub fn tasks_highway_with_decisions(
        &self,
        via: TaskVia,
        call: TaskCall,
        decisions: Option<&TaskDecisions<'_>>,
    ) -> MemoryResult<TaskCallReceipt> {
        verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        match call {
            TaskCall::Post(post) => self.highway_post(&via, post, decisions),
            TaskCall::Accept(accept) => self.highway_accept(&via, accept),
            TaskCall::Report(report) => self.highway_report(&via, report, decisions),
            TaskCall::Status(query) => self.highway_status(query),
        }
    }

    /// Wire post: a TASK with a typed brief and an explicit assignee.
    pub fn tasks_post(&self, post: TaskPost) -> MemoryResult<TaskCallReceipt> {
        self.tasks_highway(TaskVia::Wire, TaskCall::Post(post))
    }

    /// Wire accept of a TASK addressed to this actor.
    pub fn tasks_accept(&self, accept: TaskAccept) -> MemoryResult<TaskCallReceipt> {
        self.tasks_highway(TaskVia::Wire, TaskCall::Accept(accept))
    }

    /// Wire report against a fenced attempt handle.
    pub fn tasks_report(&self, report: TaskReport) -> MemoryResult<TaskCallReceipt> {
        self.tasks_highway(TaskVia::Wire, TaskCall::Report(report))
    }

    /// Status, or a poll when `after` names the last observation.
    pub fn tasks_status(&self, query: TaskStatusQuery) -> MemoryResult<TaskCallReceipt> {
        self.tasks_highway(TaskVia::Wire, TaskCall::Status(query))
    }

    /// Proves this surface's actor may run `verb` on `task`, in the caller's
    /// snapshot, through L02's rule (OF-220), and answers the TASK's
    /// standing. The proof is the actor's live binding of its own class;
    /// else the slip its request presented, whose refusal stands; else, for
    /// the in-process host's own caller, its store truth; else a binding,
    /// which it then lacks. A TASK the actor is no party to is not found; a
    /// party the verb does not admit is told why, with `suggestion`.
    pub(super) fn highway_task_actor_in(
        &self,
        txn: &heed::RoTxn<'_>,
        task: EntityId,
        verb: TaskActorVerb<'_>,
        suggestion: &str,
    ) -> MemoryResult<TaskStanding> {
        let refusal = |error: Error| match error {
            Error::EntityNotFound => not_found(),
            Error::Claim(ClaimError::ActorLacksClaimAuthority { reason }) => {
                forbidden(reason, suggestion)
            }
            other => MemoryError::from(other),
        };
        let actor = WriteActor::new(self.actor(), self.actor_class());
        let fold = self
            .vault()
            .authority_view_readonly_in_txn(txn)
            .map_err(refusal)?;
        let bound =
            actor_binding_is_active(&fold, &self.actor(), self.actor_class().gate_actor_class());
        let writer = if bound {
            self.vault()
                .observed_write_actor_in_txn(txn, actor)
                .map_err(refusal)?
        } else {
            actor
        };
        let proof = if bound {
            TaskActorProof::Bound(&writer)
        } else if let Some(slip) = self.presented_credential() {
            TaskActorProof::Slip {
                actor: self.actor(),
                slip,
            }
        } else if self.native_invocation() {
            TaskActorProof::Native(&writer)
        } else {
            TaskActorProof::Bound(&writer)
        };
        self.vault()
            .prove_task_actor_by_in_txn(txn, task, proof, verb)
            .map_err(refusal)
    }

    /// Rewrites one TASK body inside the caller's transaction through the
    /// shared TASK-body writer.
    pub(super) fn rewrite_task_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        task_ref: EntityId,
        body: TaskVerbBody,
        now: u64,
    ) -> MemoryResult<()> {
        let encoded = encode_task_verb_body(body);
        self.put_task_body_in_txn(wtxn, task_ref, &encoded, now)
    }

    /// The skeleton of the lifecycle receipt one mutating call owes.
    pub(super) fn lifecycle_record(
        &self,
        via: &TaskVia,
        call: &str,
        outcome: &str,
        task_ref: Option<EntityId>,
        attempt: Option<AttemptId>,
        now: u64,
    ) -> TaskLifecycleRecord {
        TaskLifecycleRecord {
            call: call.to_owned(),
            outcome: outcome.to_owned(),
            occurred_at: now,
            actor: self.actor(),
            on_behalf_of: match via {
                TaskVia::Wire => None,
                TaskVia::Host(binding) => Some(attempt_hex(binding.parent())),
            },
            job_ref: attempt.map(attempt_hex),
            trigger_ref: task_ref.map(|task| task.to_hex()),
            fields: BTreeMap::new(),
        }
    }
}

/// Validates one idempotency key and qualifies it by the host's parent
/// attempt, the way spawn qualifies its intent key: a code-mode caller
/// cannot substitute its parent.
pub(super) fn qualified_key(via: &TaskVia, key: &str, what: &str) -> MemoryResult<String> {
    if key.trim().is_empty() {
        return Err(MemoryError::bad_request(format!(
            "{what} must not be blank"
        )));
    }
    if key.len() > MAX_HIGHWAY_KEY_LEN {
        return Err(MemoryError::bad_request(format!(
            "{what} must be at most {MAX_HIGHWAY_KEY_LEN} bytes"
        )));
    }
    Ok(match via {
        TaskVia::Wire => key.to_owned(),
        TaskVia::Host(binding) => format!("{}/{key}", attempt_hex(binding.parent())),
    })
}

pub(super) fn attempt_hex(id: AttemptId) -> String {
    crate::entity_id::bytes_to_hex_lower(id.as_bytes())
}

/// The engine-derived lease owner: the actor and a digest of the bindings it
/// holds now. The caller never supplies it, and a rebind changes it, so
/// every later report from the old binding is stale.
pub(super) fn lease_owner_for(actor: EntityId, generation: Option<&BindingGeneration>) -> String {
    let digest = match generation {
        Some(generation) => {
            let mut hasher = blake3::Hasher::new();
            hasher.update(LEASE_OWNER_DOMAIN);
            for binding in generation.bindings() {
                hasher.update(binding);
            }
            let hex = hasher.finalize().to_hex();
            hex.as_str()[..32].to_owned()
        }
        None => "unbound".to_owned(),
    };
    format!("{}@{digest}", actor.to_hex())
}

/// The digest of a binding generation, for receipts.
pub(super) fn generation_digest(generation: Option<&BindingGeneration>) -> String {
    match generation {
        Some(generation) => {
            let mut hasher = blake3::Hasher::new();
            hasher.update(LEASE_OWNER_DOMAIN);
            for binding in generation.bindings() {
                hasher.update(binding);
            }
            hasher.finalize().to_hex().as_str().to_owned()
        }
        None => "unbound".to_owned(),
    }
}

/// The handle of one leased try on this node.
pub(super) fn attempt_handle(
    task_ref: EntityId,
    record: &AttemptRecord,
    node_ref: Option<EntityId>,
) -> AttemptHandle {
    AttemptHandle {
        task_ref,
        attempt_ref: record.id,
        attempt_count: record.attempt_count,
        node_ref,
    }
}

/// This install's machine, the node a node-local attempt row lives on.
pub(super) fn local_node_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> MemoryResult<Option<EntityId>> {
    Ok(crate::identity::read_machine_id_in_txn(vault, txn)?)
}

/// Where one TASK body's work stands.
pub(super) fn phase_of(body: &TaskVerbBody) -> TaskPhase {
    match &body.state {
        None | Some(TaskExecutionState::Queued) => TaskPhase::Queued,
        Some(TaskExecutionState::Working { started_at }) => TaskPhase::Working {
            started_at: *started_at,
        },
        Some(TaskExecutionState::Blocked { since, on }) => TaskPhase::Blocked {
            since: *since,
            on: on.clone(),
        },
        Some(TaskExecutionState::Interrupted { .. }) => TaskPhase::Interrupted,
        Some(TaskExecutionState::Terminal(record)) => TaskPhase::Terminal {
            disposition: record.disposition,
        },
    }
}

/// The brief stamp fields every lifecycle receipt carries.
pub(super) fn stamp_fields(fields: &mut BTreeMap<String, String>, brief: Option<&StoredBrief>) {
    if let Some(brief) = brief {
        let stamp = brief.stamp();
        fields.insert(
            "type_ref".to_owned(),
            format!(
                "{}@{}",
                stamp.type_ref.node_id.to_hex(),
                stamp.type_ref.tree_version
            ),
        );
        fields.insert("brief_rev".to_owned(), stamp.rev.to_string());
        fields.insert(
            "brief_digest".to_owned(),
            crate::entity_id::bytes_to_hex_lower(&stamp.digest),
        );
    }
}

/// The not-found shape: a task this actor may not see has no other answer,
/// so existence does not leak.
pub(super) fn not_found() -> MemoryError {
    MemoryError::from(Error::EntityNotFound)
}

pub(super) fn forbidden(message: &str, suggestion: &str) -> MemoryError {
    consult_refusal(MEMORY_CODE_FORBIDDEN, message, suggestion)
}

pub(super) fn invalid_state(message: &str, suggestion: &str) -> MemoryError {
    consult_refusal(MEMORY_CODE_INVALID_STATE, message, suggestion)
}

/// The request digest a post's provenance records, if it records one.
pub(super) fn provenance_digest(provenance: &Value) -> Option<[u8; 32]> {
    let Value::Map(entries) = provenance else {
        return None;
    };
    entries
        .iter()
        .find_map(|(key, value)| match (key.as_str(), value) {
            (Some("request_digest"), Value::Binary(bytes)) => bytes.as_slice().try_into().ok(),
            _ => None,
        })
}

/// The provenance a posted TASK carries: the facade's, plus the intent key
/// and the request digest a replay is checked against.
pub(super) fn post_provenance(key: &str, digest: &[u8; 32], proposal: Option<EntityId>) -> Value {
    let mut entries = vec![
        (Value::from("surface"), Value::from("facade")),
        (Value::from("verb"), Value::from("tasks.create")),
        (Value::from("intent_key"), Value::from(key)),
        (
            Value::from("request_digest"),
            Value::Binary(digest.to_vec()),
        ),
    ];
    if let Some(proposal) = proposal {
        entries.push((Value::from("proposal_ref"), Value::from(proposal.to_hex())));
    }
    Value::Map(entries)
}
