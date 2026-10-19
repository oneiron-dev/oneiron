//! A flight's self-written passes, filed before any of them lands (FIX 4465
//! B): every paid call, a try the gate refused too, becomes one step of the
//! model-step family on the route the run captured at entry, and each pass's
//! receipt names its filed steps and the retained evidence its window was
//! cut from. A refused landing keeps its paid steps; no call is filed twice.

use super::super::compaction::FinishedFlight;
use super::super::driver::EngineNativeExecutor;
use crate::code_run::CodeRunReplayRecord;
use crate::compaction::{CompactionEvidence, CompactionExecution, GatedCompaction};
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
