//! Lease-fenced host ports for one retained workflow tool round.

use heed::{RoTxn, RwTxn};

use super::{
    CheckpointRow, TABLE, WorkflowToolProgress, WorkflowToolTranscript, check_progress_in_txn,
    identity_in_txn, invalid, key, prepare, put_in_txn, release_in_txn, transcript_in_txn,
};
use crate::agent_dispatch::AgentDispatcher;
use crate::attempt_queue::{
    AttemptId, AttemptQueue, AttemptRecord, AttemptResumePoint, AttemptState, HoldAttemptForHook,
};
use crate::runtime_hooks::InvocationId;
use crate::runtime_hooks::verb::VerbHookWaitStatus;
use crate::task_verb::sdk::AgentVerb;
use crate::{Result, Vault};

/// The original admitted transcript and its exact settled cursor. Reading
/// this does not grant permission to run its pending verb.
pub struct WorkflowToolContinuation {
    pub transcript: WorkflowToolTranscript,
    pub progress: WorkflowToolProgress,
}

fn leased_row(vault: &Vault, txn: &RoTxn<'_>, leased: &AttemptRecord) -> Result<AttemptRecord> {
    let actual = AttemptQueue::new(vault)
        .get_in_txn(txn, leased.id)?
        .ok_or_else(|| invalid("workflow checkpoint leaf is missing"))?;
    if actual.state != AttemptState::Leased
        || actual.lease_owner.is_none()
        || actual.lease_owner != leased.lease_owner
        || actual.attempt_count != leased.attempt_count
    {
        return Err(invalid("workflow checkpoint lease is stale"));
    }
    Ok(actual)
}

fn checked_content<'a>(
    vault: &Vault,
    txn: &RoTxn<'_>,
    actual: &AttemptRecord,
    row: &'a CheckpointRow,
) -> Result<&'a super::CheckpointContent> {
    if row.attempt != actual.id || row.generation != actual.attempt_count {
        return Err(invalid("workflow checkpoint generation is stale"));
    }
    let content = row
        .content
        .as_ref()
        .ok_or_else(|| invalid("workflow checkpoint is unavailable"))?;
    let (actor, room) = identity_in_txn(vault, txn, actual)?;
    if content.actor != actor.entity_ref()
        || content.actor_class != actor.actor_class()
        || content.room != room
    {
        return Err(invalid("workflow checkpoint actor has changed"));
    }
    check_progress_in_txn(vault, txn, actual, actor, &content.progress)?;
    for source in content.progress.known_sources.iter().copied().chain(room) {
        if crate::ports::owner_gone_in_txn(&vault.store, txn, &source)? {
            return Err(invalid("workflow checkpoint source is erased"));
        }
    }
    Ok(content)
}

impl AgentDispatcher<'_> {
    /// Load only this current lease's retained transcript. Custody and the
    /// body pin precede its snapshot and outlive any spilled-file read.
    /// An erased or mismatched checkpoint is an error, never a fresh start.
    pub fn workflow_tool_checkpoint(
        &self,
        leased: &AttemptRecord,
    ) -> Result<Option<WorkflowToolContinuation>> {
        let _custody = self.vault.store.gate_custody_read_guard()?;
        let k = key(leased.id)?;
        let expected = {
            let txn = self.vault.store.env.read_txn()?;
            TABLE
                .get(&self.vault.store, &txn, &k)?
                .and_then(|row| row.content.map(|content| content.body))
        };
        let _pin = expected.map(|body| self.vault.pin_result_body(body.hash));
        let txn = self.vault.store.env.read_txn()?;
        let actual = leased_row(self.vault, &txn, leased)?;
        let Some(row) = TABLE.get(&self.vault.store, &txn, &k)? else {
            return if expected.is_none() {
                Ok(None)
            } else {
                Err(invalid("workflow checkpoint changed during its read"))
            };
        };
        let content = checked_content(self.vault, &txn, &actual, &row)?;
        if expected != Some(content.body) {
            return Err(invalid("workflow checkpoint body changed during its read"));
        }
        let transcript = transcript_in_txn(self.vault, &txn, &row)?
            .ok_or_else(|| invalid("workflow checkpoint body is unavailable"))?;
        Ok(Some(WorkflowToolContinuation {
            transcript,
            progress: content.progress.clone(),
        }))
    }

    /// Save a completed tool's transcript and next cursor while this same
    /// lease holds. The host has booked all settled spend before calling.
    pub fn save_workflow_tool_progress(
        &self,
        leased: &AttemptRecord,
        transcript: &WorkflowToolTranscript,
        progress: WorkflowToolProgress,
    ) -> Result<()> {
        if progress.wait.is_some() {
            return Err(invalid("a pending workflow tool must park its leaf"));
        }
        self.write_workflow_tool_progress(leased, transcript, progress, None)
    }

    /// Publish the full transcript and its exact invocation pause in one
    /// writer. A later person's pause, landing or stale lease is untouched.
    /// The host must finish book_rest and checkpoint its settled guard first.
    pub fn park_workflow_tool(
        &self,
        leased: &AttemptRecord,
        transcript: &WorkflowToolTranscript,
        progress: WorkflowToolProgress,
        now: u64,
    ) -> Result<()> {
        let invocation = progress
            .wait
            .as_ref()
            .ok_or_else(|| invalid("workflow tool park has no pending invocation"))?
            .invocation;
        self.write_workflow_tool_progress(leased, transcript, progress, Some((invocation, now)))
    }

    fn write_workflow_tool_progress(
        &self,
        leased: &AttemptRecord,
        transcript: &WorkflowToolTranscript,
        progress: WorkflowToolProgress,
        park: Option<([u8; 16], u64)>,
    ) -> Result<()> {
        let prepared = prepare(self.vault, transcript)?;
        let mut txn = self.vault.store.env.write_txn()?;
        let actual = leased_row(self.vault, &txn, leased)?;
        put_in_txn(self.vault, &mut txn, &actual, progress, prepared)?;
        if let Some((invocation, now)) = park {
            AttemptQueue::new(self.vault).hold_for_hook_in_txn(
                &mut txn,
                HoldAttemptForHook {
                    id: actual.id,
                    lease_owner: actual
                        .lease_owner
                        .ok_or_else(|| invalid("workflow lease is missing"))?,
                    attempt_count: actual.attempt_count,
                    invocation,
                    resume_point: AttemptResumePoint::new("workflow-step:tool-hook", now),
                    now,
                },
            )?;
        }
        txn.commit()?;
        if park.is_some() {
            self.vault.store.notify_attempt_observers();
        }
        Ok(())
    }

    /// Inspect only this workflow's active hook pause on the existing pump
    /// wake/startup/recheck. True keeps that existing recheck while waiting.
    /// A wake hint never authorizes the body: the retained caller must still
    /// cross the required-saved hook boundary with a fresh actual HostBinding.
    pub fn resume_workflow_tool(&self, root: AttemptId, now: u64) -> Result<bool> {
        let queue = AttemptQueue::new(self.vault);
        let retained = {
            let txn = self.vault.store.env.read_txn()?;
            let wrapper = queue
                .get_in_txn(&txn, root)?
                .ok_or_else(|| invalid("workflow wrapper is missing"))?;
            let workflow = self.read_workflow(&txn, &wrapper)?;
            if wrapper.state != AttemptState::Paused {
                return Ok(false);
            }
            let active = queue.retry_tip_in_txn(&txn, workflow.active)?;
            let Some(row) = TABLE.get(&self.vault.store, &txn, &key(active.id)?)? else {
                return Ok(false);
            };
            let Some(content) = &row.content else {
                return Ok(false);
            };
            let Some(wait) = &content.progress.wait else {
                return Ok(false);
            };
            if !active.hook_wait_for(wait.invocation) {
                return Ok(false);
            }
            checked_content(self.vault, &txn, &active, &row)?;
            (
                active.id,
                row.generation,
                content.actor,
                content.actor_class,
                wait.clone(),
            )
        };
        let (attempt, generation, actor, class, wait) = retained;
        let status = self.vault.verb_hook_wait_status(
            InvocationId(wait.invocation),
            AgentVerb::SelfUse.as_str(),
            actor,
            crate::runtime_hooks::hook_class(class),
            wait.ask,
        )?;
        if status == VerbHookWaitStatus::Waiting {
            return Ok(true);
        }
        let mut txn = self.vault.store.env.write_txn()?;
        let Some(row) = TABLE.get(&self.vault.store, &txn, &key(attempt)?)? else {
            return Ok(false);
        };
        // Recheck the exact metadata after observing the ask outside the
        // writer. The boundary, not this hint, settles any answer race.
        if row.generation != generation
            || row
                .content
                .as_ref()
                .and_then(|content| content.progress.wait.as_ref())
                != Some(&wait)
        {
            return Ok(false);
        }
        let resumed =
            queue.resume_hook_in_txn(&mut txn, attempt, wait.invocation, generation, now)?;
        if resumed {
            txn.commit()?;
            self.vault.store.notify_attempt_observers();
        }
        Ok(false)
    }
}

/// The queue has just point-claimed this same leaf. Keep the checkpoint's
/// generation join atomic with N -> N+1; no old host may save after it.
pub(crate) fn adopt_claim_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    before: &AttemptRecord,
    claimed: &AttemptRecord,
) -> Result<()> {
    let k = key(before.id)?;
    let Some(mut row) = TABLE.get(&vault.store, txn, &k)? else {
        return Ok(());
    };
    checked_content(vault, txn, before, &row)?;
    if claimed.id != before.id
        || before.attempt_count.checked_add(1) != Some(claimed.attempt_count)
        || claimed.state != AttemptState::Leased
    {
        return Err(invalid("workflow checkpoint claim has foreign generation"));
    }
    row.generation = claimed.attempt_count;
    TABLE.put(vault, txn, &k, &row)
}

/// Called before the native lease-fenced completion, in its same writer.
/// Any failure rolls back both the release and the terminal transition.
pub(crate) fn clear_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    leased: &AttemptRecord,
) -> Result<()> {
    let k = key(leased.id)?;
    let Some(row) = TABLE.get(&vault.store, txn, &k)? else {
        return Ok(());
    };
    let actual = leased_row(vault, txn, leased)?;
    if row.attempt != actual.id || row.generation != actual.attempt_count {
        return Err(invalid(
            "workflow checkpoint completion has foreign generation",
        ));
    }
    if let Some(content) = &row.content {
        release_in_txn(&vault.store, txn, content)?;
    }
    TABLE.delete(&vault.store, txn, &k)?;
    Ok(())
}
