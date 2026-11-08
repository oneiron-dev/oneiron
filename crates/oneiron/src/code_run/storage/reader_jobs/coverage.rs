//! The delivery witness of a scoped reader child (FIX 7735): the ranges of
//! its primary source that its reads were shown, committed on its job row
//! through the run's one reader transaction door. Its claim starts it empty
//! and its settlement freezes it (`ReaderTxn::settle`); a fold reads it as
//! `ReaderJob::delivered_source_ranges`.

use crate::code_run::{CodeRunRawOutput, ExecutorStorage, ReaderJobState, SourceDeliveryWitness};
use crate::{EntityId, Result};

impl ExecutorStorage<'_> {
    /// Commits `delivered` to the witness of scoped child `task`, claimed at
    /// `generation`, at `now_ms` (FIX 7735). `delivered` are the ranges of
    /// run `owner`'s occurrence of `output`, in whole-body offsets, that one
    /// successful read reply showed the child. Each range is cut to the job's
    /// delegated primary range and merged with the ranges held.
    ///
    /// Nothing is written, and the answer is `false`, when the job is not a
    /// scoped child active at `generation`, its cutoff has passed, its
    /// borrowed parent lease no longer holds, or the occurrence is not its
    /// primary source. A stale generation thus adds nothing, and a settled
    /// job's witness stays as its settlement froze it.
    pub(crate) fn commit_source_delivery(
        &self,
        task: EntityId,
        generation: u32,
        owner: EntityId,
        output: &CodeRunRawOutput,
        delivered: &[(u64, u64)],
        now_ms: u64,
    ) -> Result<bool> {
        if delivered.is_empty() {
            return Ok(false);
        }
        self.reader_txn(|tx| {
            let Some(mut job) = tx.job(task)? else {
                return Ok(false);
            };
            let source = &job.binding.source;
            let primary = source.owner == owner
                && source.path == output.path
                && source.handle == output.handle;
            let within = source.range;
            if job.state != ReaderJobState::Active
                || job.generation != generation
                || job.scoped_spec().is_none()
                || !primary
                || now_ms >= job.binding.child_cutoff_unix_ms
                || !tx.scoped_parent_lease_holds(&job)?
            {
                return Ok(false);
            }
            let mut witness = match &job.delivery_witness {
                Some(held) if held.generation == generation => held.clone(),
                _ => SourceDeliveryWitness::of_claim(&job),
            };
            witness.add(delivered, within);
            if job.delivery_witness.as_ref() != Some(&witness) {
                job.delivery_witness = Some(witness);
                tx.put_job(&job)?;
            }
            Ok(true)
        })
    }
}
