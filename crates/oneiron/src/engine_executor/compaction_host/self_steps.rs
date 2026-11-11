//! A flight's self-written passes, filed before any of them lands (FIX 4465
//! B): every paid call, a try the gate refused too, becomes one step of the
//! model-step family on the route the run captured at entry, and each pass's
//! receipt names its filed steps and the retained evidence its window was
//! cut from. A refused landing keeps its paid steps; no call is filed twice.
//! An accepted pass that wore its home also marks its run's read-world
//! ledger before it lands (FIX 7087).

use super::super::compaction::FinishedFlight;
use super::super::driver::EngineNativeExecutor;
use crate::code_run::{CodeRunReplayRecord, ReadWorldUnknown};
use crate::compaction::{
    CompactionEvidence, CompactionExecution, GatedCompaction, compaction_home_worn_parts,
};
use crate::edge::EdgeActorClass;
use crate::entity_id::bytes_to_hex_lower;
use crate::{EntityId, WriteActor};

/// Why a pass's calls were not filed: its route refused the write. The
/// receipt keeps their usage either way.
const STEP_FILING_REFUSED: &str = "step_filing_refused";

impl EngineNativeExecutor<'_> {
    /// Files the flight's self-written passes and pins each receipt to its
    /// steps and, for an accepted pass, to the revision of the evidence its
    /// window was cut from.
    pub(in crate::engine_executor) fn file_self_passes(&self, finished: &mut FinishedFlight) {
        let mut records: Vec<(EntityId, Option<CodeRunReplayRecord>)> = Vec::new();
        let mut record_of = |run: EntityId| -> Option<CodeRunReplayRecord> {
            if let Some((_, record)) = records.iter().find(|(id, _)| *id == run) {
                return record.clone();
            }
            let record = self.storage.get_code_run_replay_record(&run).ok().flatten();
            records.push((run, record.clone()));
            record
        };
        if let (Some(execution), Some(run)) = (finished.epoch_execution.as_mut(), self.output_run) {
            let span = match &finished.epoch {
                Some(Ok(gated)) => window_span(gated),
                _ => None,
            };
            let record = span.and_then(|_| record_of(run));
            self.file_pass(run, span, record.as_ref(), execution);
        }
        for (job, answer) in &mut finished.folds {
            let Some(execution) = job.execution.as_mut() else {
                continue;
            };
            let span = answer.is_ok().then_some((job.from, job.through));
            let record = span.and_then(|_| record_of(job.run_id));
            self.file_pass(job.run_id, span, record.as_ref(), execution);
        }
    }

    /// Marks the read-world ledger of each run that an accepted self-written
    /// pass of the flight summarizes, when the pass wore a home part whole
    /// (FIX 7087). The pass wrote from the home's rows: the voice, the
    /// self-model, the diary or the lessons, read under the agent's Grant.
    /// No capture of the run noted those rows, and once the summary lands its
    /// words reach the run's later context. The mark comes before anything
    /// lands, so no landing reaches the context unmarked. A landing refused
    /// after it leaves the ledger marked, which is the safe side. A
    /// house-written summary, or a pass that wore no home part, marks
    /// nothing. The mark never refuses the run; a mark that fails leaves the
    /// epoch open, as every failed ledger write does.
    pub(in crate::engine_executor) fn mark_self_written_summaries(
        &self,
        finished: &FinishedFlight,
    ) {
        let epoch = match (&finished.epoch, &finished.epoch_execution, self.output_run) {
            (Some(Ok(_)), Some(execution), Some(run)) => Some((run, execution)),
            _ => None,
        };
        let folds = finished
            .folds
            .iter()
            .filter(|(_, answer)| answer.is_ok())
            .filter_map(|(job, _)| Some((job.run_id, job.execution.as_ref()?)));
        for (run, execution) in epoch.into_iter().chain(folds) {
            if compaction_home_worn_parts(&execution.home).next().is_some() {
                let cause = ReadWorldUnknown::SelfWrittenSummary;
                self.gated_write.read_worlds_unknown(run, cause);
            }
        }
    }

    /// The run seat's report, with every self-written summary the run
    /// landed read back from its rows. A failed read leaves that list empty
    /// and says so in the log; the report itself still answers.
    pub(in crate::engine_executor) fn compaction_report(
        &self,
    ) -> Option<super::super::compaction::CompactionReport> {
        let mut report = self.compaction.as_ref()?.report().clone();
        if let Some(run) = self.output_run {
            match self.storage.code_run_self_receipts(run) {
                Ok(receipts) => report.landed_self = receipts,
                Err(error) => tracing::warn!(
                    kind = ?error.kind(),
                    "a run's self-written compaction receipts did not read back"
                ),
            }
        }
        Some(report)
    }

    fn file_pass(
        &self,
        run: EntityId,
        span: Option<(u64, u64)>,
        record: Option<&CodeRunReplayRecord>,
        execution: &mut CompactionExecution,
    ) {
        let calls = std::mem::take(&mut execution.calls);
        // The run's authenticated actor is an agent: the self writer holds
        // any other actor's flight before it calls (`no_identity`).
        let writer = WriteActor::new(execution.writer, EdgeActorClass::Agent);
        // FIX 3103: the filed steps are the run's own writes, under its token.
        let _run_writes =
            crate::skill_attribution::enter_run_write_token(self.gated_write.run_write_token());
        match self.storage.file_compaction_steps(
            self.gated_write.run_ref(),
            run,
            writer,
            &calls,
            now_ms(),
        ) {
            Ok(mut steps) => {
                // The answering try ran last; a pass the gate never accepted
                // has only refused tries.
                if execution.snapshot().is_some() {
                    execution.step = steps.pop();
                }
                execution.rejected_steps = steps;
            }
            Err(error) => {
                tracing::warn!(
                    kind = ?error.kind(),
                    "a self-written compaction pass's calls were not filed"
                );
                execution.step_unfiled = Some(STEP_FILING_REFUSED.to_owned());
            }
        }
        if let (Some((first, last)), Some(record)) = (span, record) {
            execution.evidence = evidence_of(record, run, first, last);
        }
    }
}

/// The first and last step a gated epoch window covers.
fn window_span(gated: &GatedCompaction) -> Option<(u64, u64)> {
    let request = gated.request();
    let last = request.window.last()?.turn;
    Some((request.turn_start, last))
}

/// The span's retained evidence by revision: the chained state hash its
/// last step's checkpoint committed, which pins every step through it.
fn evidence_of(
    record: &CodeRunReplayRecord,
    run: EntityId,
    first: u64,
    last: u64,
) -> Option<CompactionEvidence> {
    let checkpoint = record
        .step_checkpoints
        .iter()
        .find(|checkpoint| checkpoint.seq == last)?;
    (record.run_id == run && first <= last).then(|| CompactionEvidence::Executor {
        run,
        first,
        last,
        revision: bytes_to_hex_lower(&checkpoint.state_hash),
    })
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}
