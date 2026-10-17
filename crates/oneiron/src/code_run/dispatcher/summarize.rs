//! `summarize` at the dispatcher (code-mode-summary-sdk-v1): one summary of
//! a run's results, memoised by its members' occurrences and its recipe, and
//! made by a reader job of the run on its route, never inside a step. The
//! model call is the runner's; the step only reads the memo, queues the job,
//! and answers or parks.

use super::{ExecutorCallSite, HostSelfDispatcher};
use crate::code_run::storage::{NewReaderJob, SpawnAdmission};
use crate::code_run::types::{
    SelfDispatchOutcome, SelfDurableWait, SelfDurableWaitReason, SelfEffect, SelfFailedResult,
};
use crate::code_run::{
    ReaderActor, ReaderJob, ReaderJobKind, ReaderJobState, ReaderRoute, SelfSummarizeCall,
    SummarizeRecipe, SummarizeReply, reader_attempt_id, reader_run_id, summary_memo_key,
    summary_task_id, vault_ref,
};
use crate::limit_ask::EngineLimit;
use crate::{EntityId, Result};

/// What the wait a summary not yet made parks on says, before its task.
const SUMMARIZE_PROMPT: &str = "summarize:";

/// The most members one summary takes.
const SUMMARIZE_MAX_MEMBERS: usize = 256;

/// The ask a summary job's row keeps, in place of a reader child's.
const SUMMARIZE_JOB_ASK: &str = "summarize";

impl HostSelfDispatcher<'_> {
    /// `summarize`: the members the host bound, in order, by the call's
    /// recipe. A memo hit answers the summary's card. Otherwise the run's
    /// summary job over them is queued (or found), under the seat a spawn
    /// takes, and the call answers `{task, state}` at once with `defer`, or
    /// parks on the job's task until it settles.
    pub(super) fn dispatch_summarize(
        &self,
        call: SelfSummarizeCall,
        site: Option<ExecutorCallSite<'_>>,
    ) -> Result<SelfDispatchOutcome> {
        let failed = |code: &str| {
            SelfDispatchOutcome::Failed(SelfFailedResult {
                effect: SelfEffect::Summarize,
                error: code.to_owned(),
            })
        };
        let (Some(seat), Some(site)) = (&self.reader_spawn, site) else {
            return Ok(failed("summarize_unbound"));
        };
        let Some(members) = call.bound else {
            return Ok(failed("summarize_unresolved"));
        };
        if members.is_empty() || members.len() > SUMMARIZE_MAX_MEMBERS {
            return Ok(failed("summarize_invalid_group"));
        }
        let parent_run = site.run_id;
        let recipe = SummarizeRecipe::new(call.effort.unwrap_or_default());
        let memo = summary_memo_key(&members, &recipe)?;
        let task = summary_task_id(parent_run, &memo)?;
        if let Some(card) = self.summary_card(parent_run, task, &memo)? {
            return Ok(SelfDispatchOutcome::Summarize(SummarizeReply::Done {
                task,
                card,
            }));
        }
        let new = NewReaderJob {
            task,
            attempt: reader_attempt_id(task)?,
            run: reader_run_id(task)?,
            parent_run,
            actor: ReaderActor::of(self.actor),
            source: members[0].clone(),
            route: ReaderRoute {
                vault: vault_ref(self.vault_id()),
                session_ref: self.session_ref().map(str::to_owned),
                participant: self.participant(),
            },
            kind: ReaderJobKind::Summarize {
                members,
                recipe,
                memo,
                window_tokens: seat.window_tokens,
            },
            ask: SUMMARIZE_JOB_ASK.to_owned(),
        };
        let job = match self
            .storage
            .spawn_reader_job(seat, new, crate::unix_millis_now())?
        {
            SpawnAdmission::Queued { job, queued } => {
                // The backlog row asks on its crossing edge and keeps
                // queueing: it never refuses.
                let watch = self.storage.limit_watch();
                let bound = watch.bound(EngineLimit::CodeReaderBacklog);
                if queued == bound.saturating_add(1) {
                    watch.crossed(EngineLimit::CodeReaderBacklog, bound, queued);
                }
                self.storage.wake_reader_runner(job.task);
                job
            }
            SpawnAdmission::Existing(job) => job,
            SpawnAdmission::PastCutoff => return Ok(failed("summarize_past_cutoff")),
            SpawnAdmission::Unmetered => return Ok(failed("summarize_unmetered")),
        };
        if call.defer || job.state.is_settled() {
            return Ok(SelfDispatchOutcome::Summarize(pending(&job)));
        }
        Ok(SelfDispatchOutcome::DurableWait(SelfDurableWait {
            wait_id: task,
            effect: SelfEffect::Summarize,
            reason: SelfDurableWaitReason::PeerResult,
            prompt: Some(format!("{SUMMARIZE_PROMPT}{}", task.to_hex())),
        }))
    }

    /// The card of the summary `memo` names, when it was made by this run's
    /// job `task`: its text, a result of the job's run, read as the run's
    /// children's findings are, with the task it was made by.
    fn summary_card(
        &self,
        parent_run: EntityId,
        task: EntityId,
        memo: &[u8; 32],
    ) -> Result<Option<serde_json::Value>> {
        let Some(found) = self
            .storage
            .code_run_summary_memo(memo)?
            .filter(|found| found.task == task)
        else {
            return Ok(None);
        };
        if !self
            .storage
            .reader_job(task)?
            .is_some_and(|job| job.binding.parent_run == parent_run)
        {
            return Ok(None);
        }
        self.storage
            .summary_output_card(found.owner, &found.path, &found.handle, task)
    }
}

/// A summary job's `{task, state}`, and why it settled short.
fn pending(job: &ReaderJob) -> SummarizeReply {
    let reason = match &job.state {
        ReaderJobState::Partial { reason } | ReaderJobState::Failed { reason } => {
            Some(reason.clone())
        }
        _ => None,
    };
    SummarizeReply::Pending {
        task: job.task,
        job: job.state.word().to_owned(),
        reason,
    }
}
