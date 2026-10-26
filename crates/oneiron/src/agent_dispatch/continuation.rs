//! The owner's prompt continuation of a failed agent run (FIX 3694, OF-568):
//! the successor attempt an approved `prompt_inject` enqueues, and the
//! record of that approval.
//!
//! The Coach drafts a prompt on an agent-health card; only the owner
//! applies it, through the card's apply door (`agent_health/apply.rs`),
//! which calls [`apply_prompt_inject_in_txn`] in its one write transaction.
//! The owner may edit the draft first: their own text is their approval.
//! The approval binds the failed attempt, the card, the Coach's ask, the
//! evidence it answered, the checkpoint the run continues from and the exact
//! approved bytes. In that transaction:
//!
//! - the failed attempt's TASK, when it realized one the failure settled,
//!   goes back to its runner lane (ruling 3);
//! - a new queued attempt, `retry_of` the failed one, takes its frozen
//!   payload byte for byte (ruling 1);
//! - the successor reserves a spend scope of its own under the failed
//!   attempt's parent scope, sized as the failed launch was, with its hard
//!   or soft policy; an unmetered launch stays unmetered (ruling 2);
//! - the engine executor's continuation row binds the successor to the
//!   checkpoint, the approval and the prompt;
//! - the application is kept, keyed by the failed attempt (ruling 5), with
//!   the digest of the Coach draft it approved or edited.
//!
//! The same approval applied again answers the successor it made, whatever
//! has become of it; another approval for that attempt refuses. Each
//! refusal reaches the owner as its code.

use serde::{Deserialize, Serialize};

use crate::attempt_queue::{AttemptId, AttemptQueue, AttemptRecord, AttemptState};
use crate::dreamer_runner::maintenance::agent_health::AgentHealthPromptInject;
use crate::dreamer_runner::{DREAMER_RUNNER_ATTEMPT_KIND, decode_dreamer_attempt_payload};
use crate::engine_executor::continuation::{
    ContinuationRefusal, ExecutorCheckpointRef, RunContinuation, checkpoint_ref,
    pre_fail_checkpoint, put_run_continuation_in_txn,
};
use crate::side_table::{self, Named, SideTable};
use crate::task_verb::{
    FailedTaskContinuation, TaskContinuationOutcome, continue_failed_task_in_txn,
};
use crate::{EntityId, Error, Result, Vault};

use super::spend_record::SCOPE;
use super::{
    AGENT_DISPATCH_ATTEMPT_TYPE, AgentDispatchInput, AgentDispatcher, ChildSpend, SpendRefused,
    SpendScope, SpendScopeId, SpendState, decode_agent_dispatch_input,
};

/// The domain of an approval's fingerprint, whose first 16 bytes are its id.
const APPROVAL_DOMAIN: &[u8] = b"oneiron:prompt-inject-approval:v1";

/// The failed launch's parent scope is gone, closed or cannot cover the
/// successor's reservation, or room-bound work has no payer's scope.
const CONTINUATION_UNFUNDED: &str = "continuation_unfunded";

/// The failed attempt's TASK is no longer the one its failure settled.
const CONTINUATION_TASK_MOVED: &str = "continuation_task_moved";

/// Applied prompt continuations. Key: the failed attempt's 16 bytes.
const APPLICATIONS: SideTable<[u8; 16], PromptInjectApplication, Named> =
    SideTable::new(&side_table::AGENT_DISPATCH_PROMPT_INJECT);

/// `/v1/owner/inbox/concern/apply-prompt-inject`'s input: the one prompt
/// continuation the owner approves.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConcernPromptInjectRequest {
    /// The card's `health:` handle, the row's `payload_ref`.
    pub card: String,
    /// The Coach ask the owner read: its `attempt`, as 32 hex.
    pub ask: String,
    /// The approved prompt: the Coach's proposal on that ask, or the
    /// owner's own edit of it.
    pub prompt: String,
    /// The checkpoint the run continues from, as 32 hex: the healer case's
    /// or the failure card's `pre_fail_checkpoint_ref`. Absent, the failed
    /// run's own pre-fail checkpoint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint: Option<String>,
}

/// The continuation an approval made.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConcernPromptInjectOutcome {
    /// The card's `health:` handle.
    pub card: String,
    /// The successor attempt, as 32 hex.
    pub successor: String,
    /// The approval's id, as 32 hex.
    pub approval: String,
    /// The checkpoint's id, as 32 hex.
    pub checkpoint: String,
    /// The same approval was applied before: this is the successor it made.
    pub replayed: bool,
}

/// One applied prompt continuation, kept by the failed attempt it
/// continues.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PromptInjectApplication {
    /// The card's `health:` handle.
    card: String,
    /// The Coach ask approved, as 32 hex.
    ask: String,
    /// The card's newest DIAGNOSTIC the ask answered.
    diagnostic: Option<EntityId>,
    /// BLAKE3 of the Coach draft's proposal the owner read: the evidence
    /// beside the approved prompt, which the continuation row keeps.
    proposal: [u8; 32],
    /// The approved prompt is the owner's edit, not the Coach's bytes.
    edited: bool,
    /// The owner who approved it.
    by: EntityId,
    at: u64,
    /// BLAKE3 over the approval's binding: the same approval is the same
    /// application.
    fingerprint: [u8; 32],
    /// The approval's id: the fingerprint's first 16 bytes.
    approval: EntityId,
    successor: AttemptId,
}

/// What an approval binds, as the apply door read it in its write
/// transaction.
#[derive(Debug, Clone, Copy)]
pub(crate) struct PromptInjectApproval<'a> {
    /// The card's canonical `health:` handle.
    pub(crate) card: &'a str,
    /// The standing Coach ask, as 32 hex.
    pub(crate) ask: &'a str,
    /// The ask's `prompt_inject` draft: the Coach's proposal.
    pub(crate) proposal: &'a str,
    /// The card's newest DIAGNOSTIC, which the ask answered.
    pub(crate) diagnostic: Option<EntityId>,
    /// The card's subject: the failed run's agent.
    pub(crate) subject: EntityId,
    /// The card's TASK, if any.
    pub(crate) task: Option<EntityId>,
    /// The card's attempt: the failed one.
    pub(crate) predecessor: AttemptId,
    /// Resolved before the transaction ([`continuation_checkpoint`]).
    pub(crate) checkpoint: ExecutorCheckpointRef,
    /// The approved bytes: the proposal, or the owner's edit of it.
    pub(crate) prompt: &'a str,
    /// The approving owner, revalidated in the transaction.
    pub(crate) by: EntityId,
    pub(crate) now: u64,
}

/// What an apply did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PromptInjectApplied {
    pub(crate) successor: AttemptId,
    pub(crate) approval: EntityId,
    /// The TASK this apply put back on its runner lane, for the wake owed
    /// after commit.
    pub(crate) task: Option<EntityId>,
    /// The same approval was applied before; nothing was written.
    pub(crate) replayed: bool,
}

/// The checkpoint an approval continues from, read before the apply's
/// write transaction: the one `checkpoint` names, as hex, or with none
/// named the failed run's pre-fail checkpoint. The step is the engine
/// executor's to choose, never this door's.
///
/// # Errors
///
/// `continuation_no_checkpoint` when the failed run has no checkpoint by
/// that id; a malformed id; storage errors.
pub(crate) fn continuation_checkpoint(
    vault: &Vault,
    predecessor: AttemptId,
    checkpoint: Option<&str>,
) -> Result<ExecutorCheckpointRef> {
    match checkpoint {
        Some(hex) => {
            let id = EntityId::from_hex(hex)
                .map_err(|_| refused("checkpoint is a 32-hex checkpoint id"))?;
            checkpoint_ref(vault, predecessor, id)?
                .ok_or_else(|| refused(ContinuationRefusal::NoCheckpoint.code()))
        }
        None => pre_fail_checkpoint(vault, EntityId::from_bytes(*predecessor.as_bytes())?),
    }
}

/// The applied prompt continuation of `predecessor`, as its agent-health
/// card shows it.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn prompt_inject_application(
    vault: &Vault,
    predecessor: AttemptId,
) -> Result<Option<AgentHealthPromptInject>> {
    let txn = vault.store.env.read_txn()?;
    Ok(APPLICATIONS
        .get(&vault.store, &txn, predecessor.as_bytes())?
        .map(|application| AgentHealthPromptInject {
            approval: application.approval.to_hex(),
            successor: crate::entity_id::bytes_to_hex_lower(application.successor.as_bytes()),
            ask: application.ask,
            by: application.by,
            at: application.at,
            edited: application.edited,
        }))
}

/// Applies `approval` in the apply door's write transaction: the TASK, the
/// successor, its spend, the continuation row and the application, in that
/// order, or nothing. The same approval applied before answers the
/// successor it made, writing nothing.
///
/// # Errors
///
/// `continuation_source_missing` for a predecessor that is gone or not
/// `Failed`; `continuation_occupied` when another approval continued it;
/// `continuation_task_moved`, `continuation_unfunded`, and the engine
/// executor's `continuation_no_checkpoint`, `continuation_effect_tail`,
/// `continuation_source_missing` and `continuation_occupied`, each as an
/// [`Error::InvalidConfig`] holding exactly its code; a refusal when the
/// failed attempt is not the card subject's agent run, or realizes another
/// TASK than the card's; the queue's refusals; storage errors.
pub(crate) fn apply_prompt_inject_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    approval: &PromptInjectApproval<'_>,
) -> Result<PromptInjectApplied> {
    let queue = AttemptQueue::new(vault);
    let failed = queue
        .get_in_txn(txn, approval.predecessor)?
        .filter(|record| record.state == AttemptState::Failed)
        .ok_or_else(|| refused(ContinuationRefusal::SourceMissing.code()))?;
    let input = frozen_dispatch(&failed)?;
    let agent = input.target.agent_definition_ref()?;
    if agent != approval.subject {
        return Err(refused("the card's attempt is not its subject's agent run"));
    }
    let task = failed
        .task_ref
        .as_deref()
        .map(EntityId::from_hex)
        .transpose()
        .map_err(|_| refused("the card's attempt names a malformed task"))?;
    if task != approval.task {
        return Err(refused("the card's attempt realizes another task"));
    }

    let (fingerprint, approval_id) = approval_identity(approval)?;
    let key = *approval.predecessor.as_bytes();
    if let Some(prior) = APPLICATIONS.get(&vault.store, txn, &key)? {
        if prior.fingerprint != fingerprint {
            return Err(refused(ContinuationRefusal::Occupied.code()));
        }
        return Ok(PromptInjectApplied {
            successor: prior.successor,
            approval: prior.approval,
            task: None,
            replayed: true,
        });
    }

    // Ruling 3: the same TASK continues, or the apply refuses.
    let reactivated = match task {
        None => None,
        Some(task) => {
            let continuation = FailedTaskContinuation {
                task,
                agent,
                predecessor: approval.predecessor,
                approval: approval_id,
                by: approval.by,
                now: approval.now,
            };
            match continue_failed_task_in_txn(vault, txn, &continuation)? {
                TaskContinuationOutcome::Reactivated => Some(task),
                TaskContinuationOutcome::Moved => return Err(refused(CONTINUATION_TASK_MOVED)),
            }
        }
    };

    // Ruling 1: a new try of the same attempt; ruling 2: its own spend.
    let successor = queue.successor_of_failed_in_txn(txn, approval.predecessor, approval.now)?;
    AgentDispatcher::new(vault).renew_continuation_spend_in_txn(
        txn,
        approval.predecessor,
        successor.id,
        &input,
        approval.now,
    )?;

    let continuation = RunContinuation {
        predecessor: approval.predecessor,
        checkpoint: approval.checkpoint,
        approval: approval_id,
        prompt: approval.prompt.to_owned(),
    };
    put_run_continuation_in_txn(vault, txn, successor.id, &continuation).map_err(|refusal| {
        match refusal {
            ContinuationRefusal::Storage(error) => error,
            refusal => refused(refusal.code()),
        }
    })?;

    let application = PromptInjectApplication {
        card: approval.card.to_owned(),
        ask: approval.ask.to_owned(),
        diagnostic: approval.diagnostic,
        proposal: *blake3::hash(approval.proposal.as_bytes()).as_bytes(),
        edited: approval.prompt != approval.proposal,
        by: approval.by,
        at: approval.now,
        fingerprint,
        approval: approval_id,
        successor: successor.id,
    };
    APPLICATIONS.put(&vault.store, txn, &key, &application)?;
    Ok(PromptInjectApplied {
        successor: successor.id,
        approval: approval_id,
        task: reactivated,
        replayed: false,
    })
}

impl AgentDispatcher<'_> {
    /// Reserves `successor`'s own spend scope, in the apply's transaction,
    /// as `predecessor`'s launch reserved its own (ruling 2). An unmetered
    /// launch stays unmetered. A metered one reserves under the failed
    /// scope's parent, never the closed scope itself: a carve of the pinned
    /// `budget` when the launch pinned one, else a hold of what the launch
    /// held, keeping its hard or soft policy. The failed try's worker lease
    /// is never carried over. Room-bound work proves its join again under
    /// the new scope.
    ///
    /// # Errors
    ///
    /// `continuation_unfunded` when the failed scope has no parent, its
    /// parent is gone or closed with no open ancestor, the reservation is
    /// refused, or the join no longer holds; storage errors.
    fn renew_continuation_spend_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        predecessor: AttemptId,
        successor: AttemptId,
        input: &AgentDispatchInput,
        now: u64,
    ) -> Result<Option<SpendScope>> {
        let agent = input.target.agent_definition_ref()?;
        let Some(failed) = self.attempt_spend_scope_in_txn(txn, predecessor)? else {
            self.require_continuation_join_in_txn(txn, input, agent, None)?;
            return Ok(None);
        };
        let Some(parent) = failed.parent.as_ref() else {
            return Err(refused(CONTINUATION_UNFUNDED));
        };
        let funded = match SCOPE.get(&self.vault.store, txn, &parent.0)? {
            Some(row) if row.state == SpendState::Open => true,
            // FIX 10541: a child keeps a closed parent, which books at its
            // nearest open ancestor; one with none open is unfunded.
            Some(_) => self.effective_scope_in_txn(txn, parent)?.state == SpendState::Open,
            None => false,
        };
        if !funded {
            return Err(refused(CONTINUATION_UNFUNDED));
        }
        let units = input
            .budget
            .or_else(|| input.launch.as_ref().map(|launch| launch.reserved_units))
            .unwrap_or(failed.cap_units);
        let ask = if failed.hard {
            ChildSpend::Carve { cap_units: units }
        } else {
            ChildSpend::Hold {
                expected_units: units,
            }
        };
        let scope = match self.reserve_agent_in_txn(txn, parent, &successor, Some(agent), ask, now)
        {
            Ok(scope) => scope,
            Err(SpendRefused::Engine(error)) => return Err(error),
            Err(SpendRefused::OverCap { .. } | SpendRefused::Start(_)) => {
                return Err(refused(CONTINUATION_UNFUNDED));
            }
        };
        // The successor spends under its own row, never the failed one its
        // `retry_of` walk would reach.
        if self.scope_for_attempt_in_txn(txn, successor)?.as_ref() != Some(&scope.scope) {
            return Err(Error::InvariantViolation(
                "a continuation's own spend scope must precede its retry lineage",
            ));
        }
        self.require_continuation_join_in_txn(txn, input, agent, Some(&scope.scope))?;
        Ok(Some(scope))
    }

    /// The failed launch's room join, proved again under `scope`. No room,
    /// no join to prove; a join that no longer holds, or room-bound work
    /// with no payer's scope, is unfunded.
    fn require_continuation_join_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        input: &AgentDispatchInput,
        agent: EntityId,
        scope: Option<&SpendScopeId>,
    ) -> Result<()> {
        if input.room.is_none() {
            return Ok(());
        }
        match self.require_room_join_in_txn(txn, input.room.as_ref(), agent, scope) {
            Ok(_) => Ok(()),
            Err(Error::Claim(_) | Error::Artifact(_)) => Err(refused(CONTINUATION_UNFUNDED)),
            Err(error) => Err(error),
        }
    }
}

/// The dispatch input `record` froze, decoded strictly: a row that is not an
/// agent dispatch is refused, and a malformed dispatch is an error.
fn frozen_dispatch(record: &AttemptRecord) -> Result<AgentDispatchInput> {
    if record.kind != DREAMER_RUNNER_ATTEMPT_KIND {
        return Err(refused("the card's attempt is not an agent run"));
    }
    let payload = decode_dreamer_attempt_payload(&record.payload)?;
    if payload.attempt_type != AGENT_DISPATCH_ATTEMPT_TYPE {
        return Err(refused("the card's attempt is not an agent run"));
    }
    decode_agent_dispatch_input(&payload.input)
}

/// An approval's fingerprint and id: BLAKE3 over a domain tag, the failed
/// attempt, the card, the ask, the diagnostic, the checkpoint's id and the
/// prompt's BLAKE3, its first 16 bytes the id.
fn approval_identity(approval: &PromptInjectApproval<'_>) -> Result<([u8; 32], EntityId)> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(APPROVAL_DOMAIN);
    hasher.update(approval.predecessor.as_bytes());
    for text in [approval.card, approval.ask] {
        hasher.update(&(text.len() as u64).to_le_bytes());
        hasher.update(text.as_bytes());
    }
    match approval.diagnostic {
        Some(diagnostic) => {
            hasher.update(&[1]);
            hasher.update(diagnostic.as_bytes());
        }
        None => {
            hasher.update(&[0]);
        }
    }
    hasher.update(approval.checkpoint.id()?.as_bytes());
    hasher.update(blake3::hash(approval.prompt.as_bytes()).as_bytes());
    let fingerprint = *hasher.finalize().as_bytes();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&fingerprint[..16]);
    Ok((fingerprint, EntityId::from_bytes(bytes)?))
}

/// A refusal the owner reads: exactly `why`, a continuation code included.
fn refused(why: &str) -> Error {
    Error::InvalidConfig(why.to_owned())
}
