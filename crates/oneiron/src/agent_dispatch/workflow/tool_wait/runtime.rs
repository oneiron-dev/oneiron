//! Lease-fenced host ports for one retained workflow tool round.

use heed::{RoTxn, RwTxn};

use super::{
    TABLE, WorkflowToolProgress, WorkflowToolTranscript, check_progress_in_txn, fence,
    identity_in_txn, invalid, key, prepare, put_in_txn, release_in_txn,
    session::{LocatedCheckpoint, locate_in_txn},
};
use crate::agent_dispatch::AgentDispatcher;
use crate::attempt_queue::{
    AttemptId, AttemptQueue, AttemptRecord, AttemptResumePoint, AttemptState, HoldAttemptForHook,
    RequeueAttempt, RetryAttempt,
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

pub(super) fn leased_row(
    vault: &Vault,
    txn: &RoTxn<'_>,
    leased: &AttemptRecord,
) -> Result<AttemptRecord> {
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
    located: &'a LocatedCheckpoint<'_>,
) -> Result<&'a super::CheckpointContent> {
    let row = &located.row;
    if !located.generation_matches(actual) {
        return Err(invalid("workflow checkpoint generation is stale"));
    }
    fence::require(&vault.store, txn, actual.id, actual.attempt_count)?;
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
        self.vault.store.authorization_now()?;
        let _custody = self.vault.store.gate_custody_read_guard()?;
        let expected = {
            let txn = self.vault.store.env.read_txn()?;
            let actual = leased_row(self.vault, &txn, leased)?;
            locate_in_txn(self.vault, &txn, &actual)?
                .and_then(|located| located.row.content.map(|content| content.body))
        };
        let _pin = expected.map(|body| self.vault.pin_result_body(body.hash));
        let txn = self.vault.store.env.read_txn()?;
        let actual = leased_row(self.vault, &txn, leased)?;
        let Some(located) = locate_in_txn(self.vault, &txn, &actual)? else {
            return if expected.is_none() && !fence::check(&self.vault.store, &txn, &actual)? {
                Ok(None)
            } else {
                Err(invalid("workflow checkpoint changed during its read"))
            };
        };
        let content = checked_content(self.vault, &txn, &actual, &located)?;
        if !self.workflow_tool_sources_readable_in_txn(
            &txn,
            &actual,
            &content.progress.known_sources,
        )? {
            return Err(invalid("workflow checkpoint source is no longer readable"));
        }
        if expected != Some(content.body) {
            return Err(invalid("workflow checkpoint body changed during its read"));
        }
        let transcript = located
            .transcript_in_txn(self.vault, &txn)?
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
        self.workflow_tool_checkpoint_writer(leased)?
            .save(transcript, progress, None)
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
        if progress.wait.is_none() {
            return Err(invalid("workflow tool park has no pending invocation"));
        }
        self.workflow_tool_checkpoint_writer(leased)?
            .save(transcript, progress, Some(now))
    }

    pub(super) fn write_workflow_tool_progress(
        &self,
        leased: &AttemptRecord,
        transcript: &WorkflowToolTranscript,
        progress: WorkflowToolProgress,
        park: Option<u64>,
    ) -> Result<()> {
        let progress_wait = progress.wait.as_ref().map(|wait| wait.invocation);
        let prepared = prepare(self.vault, transcript)?;
        let mut txn = self.vault.store.env.write_txn()?;
        let actual = leased_row(self.vault, &txn, leased)?;
        put_in_txn(self.vault, &mut txn, &actual, progress, prepared)?;
        if let Some(now) = park {
            let invocation =
                progress_wait.ok_or_else(|| invalid("workflow tool park has no wait"))?;
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
        self.vault.store.authorization_now()?;
        let queue = AttemptQueue::new(self.vault);
        let retained = {
            let mut txn = self.vault.store.env.write_txn()?;
            let wrapper = queue
                .get_in_txn(&txn, root)?
                .ok_or_else(|| invalid("workflow wrapper is missing"))?;
            let workflow = self.read_workflow(&txn, &wrapper)?;
            if wrapper.state != AttemptState::Paused {
                return Ok(false);
            }
            let active = queue.retry_tip_in_txn(&txn, workflow.active)?;
            if super::settle_erased_in_txn(self.vault, &mut txn, &active, now)? {
                txn.commit()?;
                self.vault.store.notify_attempt_observers();
                self.vault.store.notify_notification_updates();
                return Ok(false);
            }
            let Some(located) = locate_in_txn(self.vault, &txn, &active)? else {
                return Ok(false);
            };
            let Some(content) = &located.row.content else {
                return Ok(false);
            };
            let Some(wait) = &content.progress.wait else {
                return Ok(false);
            };
            if !active.hook_wait_for(wait.invocation) {
                return Ok(false);
            }
            checked_content(self.vault, &txn, &active, &located)?;
            (
                active.id,
                active.attempt_count,
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
        let Some(actual) = queue.get_in_txn(&txn, attempt)? else {
            return Ok(false);
        };
        let Some(located) = locate_in_txn(self.vault, &txn, &actual)? else {
            return Ok(false);
        };
        let row = &located.row;
        // Recheck the exact metadata after observing the ask outside the
        // writer. The boundary, not this hint, settles any answer race.
        if actual.attempt_count != generation
            || !located.generation_matches(&actual)
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
    let Some(located) = locate_in_txn(vault, txn, before)? else {
        return if fence::check(&vault.store, txn, before)? {
            Err(invalid("workflow checkpoint payload is unavailable"))
        } else {
            Ok(())
        };
    };
    checked_content(vault, txn, before, &located)?;
    if claimed.id != before.id
        || before.attempt_count.checked_add(1) != Some(claimed.attempt_count)
        || claimed.state != AttemptState::Leased
    {
        return Err(invalid("workflow checkpoint claim has foreign generation"));
    }
    if located.session.is_none() {
        let mut row = located.row;
        row.generation = claimed.attempt_count;
        TABLE.put(vault, txn, &k, &row)?;
    }
    fence::put(&vault.store, txn, claimed)
}

/// Called before the native lease-fenced completion, in its same writer.
/// Any failure rolls back both the release and the terminal transition.
pub(crate) fn clear_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    leased: &AttemptRecord,
) -> Result<()> {
    let k = key(leased.id)?;
    let Some(located) = locate_in_txn(vault, txn, leased)? else {
        return if fence::check(&vault.store, txn, leased)? {
            Err(invalid("workflow checkpoint payload is unavailable"))
        } else {
            Ok(())
        };
    };
    let actual = leased_row(vault, txn, leased)?;
    if !located.generation_matches(&actual) {
        return Err(invalid(
            "workflow checkpoint completion has foreign generation",
        ));
    }
    fence::require(&vault.store, txn, actual.id, actual.attempt_count)?;
    if located.session.is_some() {
        // No canonical occurrence exists for session bytes. The terminal
        // queue transition in this writer ends access; native close owns
        // the overlay rows and spill cleanup, with no durable session facts.
        return Ok(());
    }
    let mut row = located.row;
    if let Some(content) = row.content.take() {
        release_in_txn(&vault.store, txn, &content)?;
        row.retained = Some(content.binding());
    }
    let retained = row.retained.clone();
    TABLE.admit(vault, txn, &k, &mut row)?;
    if row.retained != retained {
        return Err(invalid(
            "workflow checkpoint binding changed during admission",
        ));
    }
    TABLE.put(vault, txn, &k, &row)
}

/// The failure ladder has already selected Retry. A positive checkpoint
/// keeps the same leaf, authority, tool ordinals and run meter; ordinary
/// dispatch retries continue through their existing new-row path.
pub(crate) fn requeue_failure_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    source: &AttemptRecord,
    input: &RetryAttempt,
) -> Result<Option<AttemptRecord>> {
    let Some(located) = locate_in_txn(vault, txn, source)? else {
        return if fence::check(&vault.store, txn, source)? {
            Err(invalid("workflow checkpoint payload is unavailable"))
        } else {
            Ok(None)
        };
    };
    let actual = leased_row(vault, txn, source)?;
    if !located.generation_matches(&actual) {
        return Err(invalid("workflow checkpoint retry has foreign generation"));
    }
    let row = &located.row;
    if input.id != actual.id
        || input.attempt_count != actual.attempt_count
        || actual.lease_owner.as_deref() != Some(input.lease_owner.as_str())
    {
        return Err(invalid("workflow checkpoint retry has foreign lease"));
    }
    // Erasure can race a paid provider failure. Requeue the fenced leaf,
    // never its body; the next pump cancels its erased form before claim.
    if row.content.is_some()
        && checked_content(vault, txn, &actual, &located)?
            .progress
            .wait
            .is_some()
    {
        return Err(invalid("workflow checkpoint retry has pending wait"));
    }
    let reason = input
        .last_error
        .clone()
        .ok_or_else(|| invalid("workflow checkpoint retry has no failure"))?;
    AttemptQueue::new(vault)
        .requeue_in_txn(
            txn,
            RequeueAttempt {
                id: actual.id,
                lease_owner: input.lease_owner.clone(),
                attempt_count: actual.attempt_count,
                reason,
                due_at: input.backoff_until,
            },
        )
        .map(Some)
}

/// History counts failures, not claims or successful tool checkpoints.
/// The erased form still binds the same leaf/generation: erasing its body
/// must not reset its already recorded failure ordinal.
fn failure_count_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    actual: &AttemptRecord,
) -> Result<Option<usize>> {
    let Some(row) = TABLE.get(&vault.store, txn, &key(actual.id)?)? else {
        // An ordinal does not open session content. Its current canonical
        // fence and the actual queue's history survive session close.
        return Ok(fence::check(&vault.store, txn, actual)?.then_some(actual.history.len()));
    };
    if row.attempt != actual.id || row.generation != actual.attempt_count {
        return Err(invalid("workflow checkpoint failure history is stale"));
    }
    Ok(Some(actual.history.len()))
}

impl AgentDispatcher<'_> {
    /// Additional past failures on a positively retained workflow leaf.
    /// This is an ordinal read, not permission to read or run its body.
    pub fn workflow_tool_failure_count(&self, attempt: &AttemptRecord) -> Result<usize> {
        let txn = self.vault.store.env.read_txn()?;
        let Some(count) = failure_count_in_txn(self.vault, &txn, attempt)? else {
            return Ok(0);
        };
        let actual = AttemptQueue::new(self.vault)
            .get_in_txn(&txn, attempt.id)?
            .ok_or_else(|| invalid("workflow failure leaf is missing"))?;
        if actual.attempt_count != attempt.attempt_count || actual.history != attempt.history {
            return Err(invalid("workflow failure history changed"));
        }
        Ok(count)
    }
}

/// A provider-recovery hint only cuts the existing backoff. The next
/// claim/read still checks the checkpoint and the retained verb boundary.
pub(crate) fn advance_saved_retry_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    actual: &AttemptRecord,
    now: u64,
) -> Result<bool> {
    if actual.state != AttemptState::Scheduled || actual.history.is_empty() {
        return Ok(false);
    }
    let Some(located) = locate_in_txn(vault, txn, actual)? else {
        return Ok(false);
    };
    let row = &located.row;
    // The workflow pump settles erased rows; one such row must not abort
    // the provider's recovery pass for unrelated retained retries.
    if row.content.is_none() {
        return Ok(false);
    }
    let content = checked_content(vault, txn, actual, &located)?;
    if content.progress.wait.is_some() {
        return Ok(false);
    }
    AttemptQueue::new(vault).advance_requeued_retry_in_txn(txn, actual.id, now)
}
