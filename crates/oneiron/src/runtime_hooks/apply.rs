//! Applying saved intents (ARCH-0080 §4 Crash-safe outcomes, §6 authority).
//! Each runs once, as the hook's author with source Generated, through the
//! existing door, after current authority is checked again.

use rmpv::Value;

use crate::memory::HostWriteOrigin;
use crate::registry::{ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_PERSON};
use crate::skill_hub::pack_catalog::PackHookBinding;
use crate::task_verb::{TaskAssignee, TaskCreateSpec};
use crate::{
    ClaimApprovalStatus, ClaimInput, ClaimSource, DreamerConsolidationScope, DreamerRunnerStore,
    EdgeActorClass, EnqueueDreamerAttemptOutcome, EnqueueDreamerConsolidationAttempt, EntityId,
    Error, Memory, MemoryError, Result, Vault, WriteActor, WriteEnvelope, WriteProvenance,
};

use super::lineage;
use super::outcome::{EnqueuedDreamer, EnqueuedTask, HookOutcome, ProposedClaim};
use super::runner::HookPassReport;
use super::store::{HookIntent, HookIntentState, INTENTS, RunKey};

/// Intents the startup drain reads.
const MAX_DRAIN: usize = 10_000;
/// The predicates an edge or note proposal lands under: there is no gated
/// edge or note proposal door for a Generated write.
const EDGE_PROPOSAL_PREDICATE: &str = "hook.proposed_edge";
const NOTE_PROPOSAL_PREDICATE: &str = "hook.proposed_note";

/// What an applied intent landed.
struct Landed {
    /// The row a later fact on it inherits lineage from.
    row: Option<[u8; 16]>,
    /// The door's ref, for the intent record.
    reference: String,
}

/// Applies every Pending intent, once, at runner start.
pub(super) fn drain_pending(vault: &Vault, report: &mut HookPassReport) -> Result<()> {
    let pending: Vec<(RunKey, HookIntent)> = {
        let rtxn = vault.store.env.read_txn()?;
        let rows: Vec<(RunKey, HookIntent)> = INTENTS
            .iter_from(&vault.store, &rtxn, &[])?
            .filter(|row| {
                row.as_ref()
                    .map_or(true, |(_, intent)| intent.state == HookIntentState::Pending)
            })
            .take(MAX_DRAIN)
            .collect::<Result<_>>()?;
        rows
    };
    if pending.is_empty() {
        return Ok(());
    }
    let bindings = vault.pack_hook_bindings()?;
    let enabled = vault.hooks_enabled()?;
    for (key, intent) in pending {
        apply_intent(vault, &bindings, enabled, &key, intent, report)?;
    }
    Ok(())
}

/// Applies the intent one run just saved, if it is still Pending.
pub(super) fn drain_one(
    vault: &Vault,
    bindings: &[(EntityId, PackHookBinding)],
    key: &RunKey,
    report: &mut HookPassReport,
) -> Result<()> {
    let intent = {
        let rtxn = vault.store.env.read_txn()?;
        INTENTS.get(&vault.store, &rtxn, key)?
    };
    match intent {
        Some(intent) if intent.state == HookIntentState::Pending => {
            apply_intent(vault, bindings, true, key, intent, report)
        }
        _ => Ok(()),
    }
}

fn apply_intent(
    vault: &Vault,
    bindings: &[(EntityId, PackHookBinding)],
    enabled: bool,
    key: &RunKey,
    intent: HookIntent,
    report: &mut HookPassReport,
) -> Result<()> {
    let live = bindings.iter().any(|(id, binding)| {
        *id == intent.binding && binding.enabled && binding.owner == intent.author
    });
    let refusal = if !enabled {
        Some("hooks are off")
    } else if !live {
        Some("the binding is no longer live and enabled")
    } else {
        None
    };
    if let Some(reason) = refusal {
        report.intents_refused += 1;
        return settle(vault, key, Err(reason.to_owned()));
    }
    let outcome: HookOutcome = serde_json::from_str(&intent.outcome_json)
        .map_err(|_| Error::CorruptedIndex("hook intent outcome"))?;
    let memory = vault
        .memory(intent.author, EdgeActorClass::Human)
        .with_host_origin(HostWriteOrigin::new(hook_envelope(
            intent.author,
            intent.binding,
            key,
        )?));
    // A note about nothing in particular is proposed about its own binding.
    let binding_ref = intent.binding.to_hex();
    let result = match &outcome {
        HookOutcome::Propose { claim, edge, note } => match (claim, edge, note) {
            (Some(claim), _, _) => propose_claim(&memory, key, claim),
            (_, Some(edge), _) => propose(
                &memory,
                key,
                EDGE_PROPOSAL_PREDICATE,
                &edge.from,
                serde_json::json!({"to": edge.to, "edge": edge.edge}),
            ),
            (_, _, Some(note)) => propose(
                &memory,
                key,
                NOTE_PROPOSAL_PREDICATE,
                note.about.first().unwrap_or(&binding_ref),
                serde_json::json!({"title": note.title, "body": note.body, "about": note.about}),
            ),
            _ => Err("propose names nothing".to_owned()),
        },
        HookOutcome::Enqueue {
            task: Some(task), ..
        } => enqueue_task(vault, &memory, key, &intent, task),
        HookOutcome::Enqueue {
            dreamer: Some(dreamer),
            ..
        } => return enqueue_dreamer(vault, &memory, key, &intent, dreamer, report),
        HookOutcome::Effect { outbound } => {
            let mut draft = (**outbound).clone();
            draft.idempotency_key = Some(super::store::receipt_id(key));
            memory
                .schedule_outbound(&draft)
                .map(|receipt| Landed {
                    row: None,
                    reference: receipt.intent_ref,
                })
                .map_err(refusal_text)
        }
        _ => Err("the outcome is not queued work".to_owned()),
    };
    match &result {
        Ok(_) => report.intents_applied += 1,
        Err(_) => report.intents_refused += 1,
    }
    settle(vault, key, result)
}

/// Marks an intent Applied or Refused, and writes the landed row's lineage.
fn settle(vault: &Vault, key: &RunKey, result: std::result::Result<Landed, String>) -> Result<()> {
    vault.with_write_txn_grouped(|txn| settle_in_txn(vault, txn, key, result))
}

fn settle_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    key: &RunKey,
    result: std::result::Result<Landed, String>,
) -> Result<()> {
    let Some(mut intent) = INTENTS.get(&vault.store, txn, key)? else {
        return Err(Error::CorruptedIndex("hook intent vanished"));
    };
    if intent.state != HookIntentState::Pending {
        return Ok(());
    }
    match result {
        Ok(landed) => {
            if let Some(row) = landed.row {
                lineage::put_in_txn(vault, txn, &row, &intent.lineage)?;
            }
            intent.state = HookIntentState::Applied;
            intent.landed = Some(landed.reference);
        }
        Err(reason) => {
            intent.state = HookIntentState::Refused;
            intent.reason = Some(reason);
        }
    }
    intent.settled_at = Some(vault.store.clock.now_recorded_at());
    INTENTS.put(&vault.store, txn, key, &intent)
}

/// The envelope a hook's writes carry: its author, source Generated, and the
/// binding and run as provenance.
fn hook_envelope(author: EntityId, binding: EntityId, key: &RunKey) -> Result<WriteEnvelope> {
    Ok(WriteEnvelope::new(
        WriteActor::new(author, EdgeActorClass::Human),
        ClaimSource::Generated,
        WriteProvenance::new(Value::Map(vec![
            (Value::from("surface"), Value::from("runtime_hooks")),
            (
                Value::from("binding"),
                Value::Binary(binding.as_bytes().to_vec()),
            ),
            (Value::from("run_key"), Value::Binary(key.to_vec())),
        ]))?,
        ClaimApprovalStatus::Proposed,
    ))
}

/// The claim a Propose lands: one id per run, so a repeat writes the same row.
pub(super) fn proposal_id(key: &RunKey) -> Result<EntityId> {
    crate::codebase::entity_id_from_hash_material(b"oneiron.hook-proposal.v1", &[key.as_slice()])
}

fn propose_claim(
    memory: &Memory<'_>,
    key: &RunKey,
    claim: &ProposedClaim,
) -> std::result::Result<Landed, String> {
    let id = proposal_id(key).map_err(|error| error.to_string())?;
    let input = ClaimInput {
        predicate: claim.predicate.clone(),
        subject_ref: claim.subject.clone(),
        value: claim.value.clone(),
        confidence: claim.confidence,
        ..proposal_input(id)
    };
    land(memory, id, &input)
}

fn propose(
    memory: &Memory<'_>,
    key: &RunKey,
    predicate: &str,
    subject: &str,
    value: serde_json::Value,
) -> std::result::Result<Landed, String> {
    let id = proposal_id(key).map_err(|error| error.to_string())?;
    let input = ClaimInput {
        predicate: predicate.to_owned(),
        subject_ref: subject.to_owned(),
        value,
        ..proposal_input(id)
    };
    land(memory, id, &input)
}

fn proposal_input(id: EntityId) -> ClaimInput {
    ClaimInput {
        id: Some(id.to_hex()),
        predicate: String::new(),
        subject_ref: String::new(),
        value: serde_json::Value::Null,
        confidence: 1.0,
        source: ClaimSource::Generated.as_str().to_owned(),
        world_ref: None,
        relationship_ref: None,
        scope: None,
        valid_from: None,
        valid_to: None,
        occurred_at: None,
        learned_at: None,
        salience: None,
    }
}

fn land(
    memory: &Memory<'_>,
    id: EntityId,
    input: &ClaimInput,
) -> std::result::Result<Landed, String> {
    memory
        .claim_propose(input)
        .map(|receipt| Landed {
            row: Some(*id.as_bytes()),
            reference: receipt.receipt_ref,
        })
        .map_err(refusal_text)
}

/// Enqueue task: the tasks.create door. `TaskCreateSpec` has no due field, so
/// `due_at` rides in the spec.
fn enqueue_task(
    vault: &Vault,
    memory: &Memory<'_>,
    key: &RunKey,
    intent: &HookIntent,
    task: &EnqueuedTask,
) -> std::result::Result<Landed, String> {
    let mut spec_fields = vec![
        (Value::from("title"), Value::from(task.title.as_str())),
        (Value::from("body"), Value::from(task.body.as_str())),
        (Value::from("hook"), Value::from(intent.binding.to_hex())),
        (
            Value::from("run_key"),
            Value::from(super::store::receipt_id(key)),
        ),
    ];
    if let Some(due_at) = task.due_at {
        spec_fields.push((Value::from("due_at"), Value::from(due_at)));
    }
    let mut spec = TaskCreateSpec::new(
        Value::Map(spec_fields),
        Some(task.title.clone()),
        None,
        None,
    );
    if let Some(assignee) = task.assignee.as_deref() {
        spec = spec.with_assignee(assignee_for(vault, assignee)?);
    }
    let receipt = memory.tasks_create(&spec).map_err(refusal_text)?;
    let row = receipt.task_ref.or(receipt.proposal_ref);
    Ok(Landed {
        row: row.map(|id| *id.as_bytes()),
        reference: row.map_or_else(|| "task:parked".to_owned(), |id| id.to_hex()),
    })
}

fn assignee_for(vault: &Vault, assignee: &str) -> std::result::Result<TaskAssignee, String> {
    let id = EntityId::from_hex(assignee).map_err(|error| error.to_string())?;
    match vault
        .get_entity_type(&id)
        .map_err(|error| error.to_string())?
    {
        Some(ENTITY_TYPE_AGENT_DEF) => Ok(TaskAssignee::AgentDef { agent_def_ref: id }),
        Some(ENTITY_TYPE_PERSON) => Ok(TaskAssignee::Human { actor_ref: id }),
        _ => Err("a task assignee is an agent definition or a person".to_owned()),
    }
}

/// Enqueue dreamer: the consolidation queue, with the run key as its dedupe
/// key, in the same write that marks the intent Applied.
fn enqueue_dreamer(
    vault: &Vault,
    memory: &Memory<'_>,
    key: &RunKey,
    intent: &HookIntent,
    dreamer: &EnqueuedDreamer,
    report: &mut HookPassReport,
) -> Result<()> {
    let input = Value::Map(vec![
        (Value::from("reason"), Value::from(dreamer.reason.as_str())),
        (
            Value::from("about"),
            Value::Array(
                dreamer
                    .about
                    .iter()
                    .map(|id| Value::from(id.as_str()))
                    .collect(),
            ),
        ),
        (Value::from("hook"), Value::from(intent.binding.to_hex())),
    ]);
    let store = DreamerRunnerStore::new(vault);
    let applied = memory.with_verified_actor_write_txn(|txn| {
        let outcome = store
            .enqueue_consolidation_in_txn(
                txn,
                EnqueueDreamerConsolidationAttempt {
                    scope: DreamerConsolidationScope::Micro,
                    input,
                    parent_attempt: None,
                    dedupe_key: Some(super::store::receipt_id(key)),
                    run_id: None,
                    now: vault.store.clock.now_recorded_at(),
                },
            )
            .map_err(MemoryError::from)?;
        let (EnqueueDreamerAttemptOutcome::Enqueued(status)
        | EnqueueDreamerAttemptOutcome::Existing(status)) = outcome;
        let attempt = *status.attempt.id.as_bytes();
        let landed = Landed {
            row: Some(attempt),
            reference: crate::receipt::hex_lower(&attempt),
        };
        settle_in_txn(vault, txn, key, Ok(landed)).map_err(MemoryError::from)
    });
    match applied {
        Ok(()) => {
            report.intents_applied += 1;
            Ok(())
        }
        Err(error) => {
            report.intents_refused += 1;
            settle(vault, key, Err(refusal_text(error)))
        }
    }
}

fn refusal_text(error: MemoryError) -> String {
    format!("{}: {}", error.code, error.message)
}
