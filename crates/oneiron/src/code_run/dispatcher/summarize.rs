//! `summarize` at the dispatcher (code-mode-summary-sdk-v1): one summary of
//! a run's results, memoised by its members' occurrences and its recipe, and
//! made by a reader job of the run on its route, never inside a step. The
//! model call is the runner's; the step only reads the memo, queues the job,
//! and answers or parks.

use super::{ExecutorCallSite, HostSelfDispatcher};
use crate::claim::ClaimReadStatus;
use crate::code_run::storage::{ExecutorStorage, NewReaderJob, SpawnAdmission};
use crate::code_run::types::{
    RunCall, SelfDispatchOutcome, SelfDurableWait, SelfDurableWaitReason, SelfEffect,
    SelfFailedResult,
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

/// The ask a summary job's row keeps, in place of a reader child's.
const SUMMARIZE_JOB_ASK: &str = "summarize";

/// The refusal a summarize call answers when it names a NOTE its caller
/// does not read. A missing id, a withheld or held row and a record that is
/// not a NOTE answer it alike, so it tells nothing of what the vault holds.
pub(crate) const SUMMARIZE_NOTE_UNREADABLE: &str = "summarize_note_unreadable";

/// The refusal a summarize call answers when it names NOTEs from a run
/// bound to an off-record session: a room NOTE reads through the room's
/// view, which this read does not take.
pub(crate) const SUMMARIZE_NOTES_OFF_RECORD: &str = "summarize_notes_off_record";

/// The reason a NOTE a summarize call names is read with, where a private
/// or diary NOTE's read asks for one.
const SUMMARIZE_NOTE_READ_REASON: &str = "summarize";

impl HostSelfDispatcher<'_> {
    /// The whole live text of the NOTE `note_ref` names, as this run's
    /// caller reads it through `vault.notes.read`: on the key its door
    /// admits a summarize with (the run's own turn key when it binds no
    /// door), with the NOTE's kind policy, grants and diary gate, its lifted
    /// keys masked as the run's actor reads them. `Err` is the refusal the
    /// whole call answers: the door's own, [`SUMMARIZE_NOTE_UNREADABLE`] for
    /// an id that names no NOTE the caller reads, or
    /// [`SUMMARIZE_NOTES_OFF_RECORD`] in an off-record run.
    ///
    /// # Errors
    ///
    /// The store's own errors, and a door's refusal spelled as a gate's.
    pub(crate) fn summarize_note_text(
        &self,
        note_ref: &str,
    ) -> Result<std::result::Result<(EntityId, String), String>> {
        let unreadable = || Ok(Err(SUMMARIZE_NOTE_UNREADABLE.to_owned()));
        let ExecutorStorage::Canonical(vault) = &self.storage else {
            return Ok(Err(SUMMARIZE_NOTES_OFF_RECORD.to_owned()));
        };
        let key = match self.admit_run_call(RunCall::Bridge(SelfEffect::Summarize))? {
            Ok(read_as) => read_as.unwrap_or_else(|| self.host_turn_read_key()),
            Err(refusal) => return Ok(Err(refusal.code)),
        };
        let Ok(note) = crate::vault::entity_refs::resolve_entity_ref(vault, note_ref) else {
            return unreadable();
        };
        let lane = vault
            .scoped_read(key)
            .with_claim_status(ClaimReadStatus::Recorded);
        let _pins = lane.prepare_point_read::<crate::Error>()?;
        let memory = vault.memory(self.actor.entity_ref(), self.actor.actor_class());
        // The snapshot closes before the diary gate finishes the read.
        let prepared = {
            let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
            memory.read_live_note_in_txn(
                &lane,
                &txn,
                note,
                SUMMARIZE_NOTE_READ_REASON,
                &vault.store.pending_scan_checks,
            )
        };
        match prepared.and_then(|prepared| prepared.finish(&memory)) {
            Ok(read) => match read.value {
                Some(view) => Ok(Ok((note, view.markdown))),
                None => unreadable(),
            },
            Err(_) => unreadable(),
        }
    }

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
                code: None,
                disk_floor: None,
            })
        };
        let (Some(seat), Some(site)) = (&self.reader_spawn, site) else {
            return Ok(failed("summarize_unbound"));
        };
        let Some(members) = call.bound else {
            return Ok(failed("summarize_unresolved"));
        };
        if members.is_empty() {
            return Ok(failed("summarize_invalid_group"));
        }
        let parent_run = site.run_id;
        let recipe = call
            .recipe
            .unwrap_or_else(|| SummarizeRecipe::new(call.effort.unwrap_or_default()));
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
            parent_lease: None,
            // A summary child spawns nothing: it answers to its agent's grant.
            powers: None,
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
