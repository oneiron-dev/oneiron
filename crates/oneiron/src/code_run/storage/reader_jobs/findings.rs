//! A run's reader findings at the store (ARCH-0079 #reader-forks): a child's
//! finding report, fenced by its generation; a summary job's text, stored as
//! a result of its own run and reported as its finding; and the card a done
//! summary's reply carries. Each write goes through the run's one reader
//! transaction door. A finding keeps the origins frozen at its first report
//! (FIX 7084).

use super::{ReportOutcome, finding_key};
use crate::code_run::{ExecutorStorage, ReaderFindingRef, ReaderJobState, ResultOrigins};
use crate::{EntityId, Result};

/// The one name a summary job's run binds its text to.
const SUMMARY_RESULT_NAME: &str = "summary";

impl ExecutorStorage<'_> {
    /// The card of the summary `owner` committed at `path` under `handle`,
    /// made by job `task`: read as a child's finding is, with the task that
    /// made it. `None` once that record no longer holds it.
    pub(crate) fn summary_output_card(
        &self,
        owner: EntityId,
        path: &str,
        handle: &str,
        task: EntityId,
    ) -> Result<Option<serde_json::Value>> {
        let Some(output) = self.get_code_run_replay_record(&owner)?.and_then(|record| {
            record
                .outputs
                .into_iter()
                .find(|output| output.path == path && output.handle == handle)
        }) else {
            return Ok(None);
        };
        let mut card = crate::code_run::result_card(self, owner, &output, None)?;
        card["task"] = serde_json::json!(task.to_hex());
        Ok(Some(card))
    }

    /// The reply a parked `summarize` comes back with: a done summary's
    /// card, as the same call made again answers its memo hit, in place of
    /// the `{task, state, ref}` its settle delivered. A summary settled
    /// short, or one whose text is gone, keeps the delivered reply.
    pub(crate) fn delivered_summary_reply(
        &self,
        reply: serde_json::Value,
    ) -> Result<serde_json::Value> {
        let task = reply
            .get("task")
            .and_then(serde_json::Value::as_str)
            .filter(|_| reply.get("state").and_then(serde_json::Value::as_str) == Some("done"))
            .and_then(|task| EntityId::from_hex(task).ok());
        let Some(task) = task else {
            return Ok(reply);
        };
        let Some(found) = self.reader_job(task)?.and_then(|job| job.finding) else {
            return Ok(reply);
        };
        Ok(self
            .summary_output_card(found.owner, &found.path, &found.handle, task)?
            .unwrap_or(reply))
    }

    /// A child's finding report, fenced by its generation: it replaces the
    /// child's latest finding, and the same finding again is a replay. A
    /// settled child, or one claimed again since, keeps what it has; a
    /// scoped child whose borrowed parent lease is gone settles at `now_ms`
    /// with what it had committed before, and this finding does not land.
    /// A replay keeps the origins frozen at the first report (FIX 7084).
    pub(crate) fn report_reader_finding(
        &self,
        task: EntityId,
        generation: u32,
        finding: &ReaderFindingRef,
        now_ms: u64,
    ) -> Result<ReportOutcome> {
        self.reader_txn(|tx| {
            let Some(mut job) = tx.job(task)? else {
                return Ok(ReportOutcome::Settled);
            };
            if job.state != ReaderJobState::Active || job.generation != generation {
                return Ok(ReportOutcome::Settled);
            }
            if !tx.scoped_parent_lease_holds(&job)? {
                tx.settle_lease_lost(job, now_ms)?;
                return Ok(ReportOutcome::Settled);
            }
            if job
                .finding
                .as_ref()
                .is_some_and(|held| held.reports_same(finding))
            {
                return Ok(ReportOutcome::Replay);
            }
            let parent_run = job.binding.parent_run;
            if let Some(previous) = job.finding.take() {
                tx.drop_finding_row(parent_run, &previous, task)?;
            }
            let reference = finding.reference()?;
            tx.put_index(&finding_key(parent_run, &reference), task.as_bytes())?;
            let key = finding_key(parent_run, &finding.handle);
            if tx.index(&key)?.is_none() {
                tx.put_index(&key, task.as_bytes())?;
            }
            job.finding = Some(finding.clone());
            tx.put_job(&job)?;
            Ok(ReportOutcome::Kept)
        })
    }

    /// Stores `text` as summary job `task`'s finding while it is live at
    /// `generation`: a stored value of the job's own run (a record with no
    /// executor, its one name `summary`), marked with its members' taint,
    /// then reported as the job's finding. Its replay save stamps the
    /// spawning actor's response ownership in the same transaction. The
    /// run's end settles it. The text is made from its members alone, so its
    /// origins are the union of theirs, unknown when any member's are (FIX
    /// 7084).
    pub(crate) fn store_summary_job_text(
        &self,
        task: EntityId,
        generation: u32,
        text: &str,
    ) -> Result<std::result::Result<(), String>> {
        let Some((job, members)) = self.live_summary(task, generation)? else {
            return Ok(Err("reader_task_settled".to_owned()));
        };
        let held = self.get_code_run_replay_record(&job.run)?;
        let expected = held
            .as_ref()
            .map(crate::code_run::CodeRunReplayRecord::generation)
            .transpose()?;
        let mut record = held.unwrap_or_else(|| {
            crate::code_run::CodeRunReplayRecord::new(
                job.run,
                crate::code_run::CodeRunDeterminism::new(
                    0,
                    [0; crate::code_run::CODE_RUN_RNG_SEED_LEN],
                ),
            )
        });
        let ordinal = record.outputs.len();
        let mut sink = self.code_run_output_sink()?;
        sink.write(text.as_bytes())?;
        // The path names the digest the body is published under (FIX 5399b).
        sink.finalize_sweep()?;
        let path = crate::engine_executor::store_result_output_path(&sink.digest()?, ordinal);
        let output = self.publish_code_run_output(path, sink, true, job.run)?;
        let mut from = Vec::with_capacity(members.len());
        for member in &members {
            if let Some(held) = self.recorded(member.owner, &member.path, &member.handle)? {
                from.push((member.owner, held));
            }
        }
        self.inherit_code_run_result_marks(job.run, &output, &from)?;
        if !record.outputs.iter().any(|held| held.path == output.path) {
            record.outputs.push(output.clone());
        }
        let binding = crate::code_run::CodeRunResultBinding::new(
            SUMMARY_RESULT_NAME,
            output.handle.clone(),
            output.path.clone(),
        );
        match record
            .bindings
            .iter_mut()
            .find(|held| held.name == binding.name)
        {
            Some(held) => *held = binding,
            None => record.bindings.push(binding),
        }
        self.put_owned_code_run_replay_record(
            &record,
            expected,
            job.run,
            job.binding.actor.entity,
        )?;
        let rows = members.iter().try_fold(Vec::new(), |mut all, member| {
            all.extend(member.rows.clone()?);
            Some(all)
        });
        let finding = ReaderFindingRef {
            owner: job.run,
            path: output.path,
            handle: output.handle,
            bytes: output.raw_len,
            rows,
            origins: ResultOrigins::of_sources(&members),
        };
        let reported =
            self.report_reader_finding(task, generation, &finding, crate::unix_millis_now())?;
        Ok(match reported {
            ReportOutcome::Kept | ReportOutcome::Replay => Ok(()),
            ReportOutcome::Settled => Err("reader_task_settled".to_owned()),
        })
    }
}
