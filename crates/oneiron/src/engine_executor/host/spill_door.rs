//! A test door running the host's pre-record spill on one outcome.
//! Compiled only under `--cfg oneiron_test_support`; never API.

use crate::code_run::{
    CodeRunDeterminism, CodeRunRawOutput, CodeRunReplayRecord, ExecutorStorage, GatedActorWrite,
    SelfDispatchOutcome,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

use super::RecordingJsHost;

/// Runs the host's pre-record spill on `outcome` as `dispatch_call` runs it
/// before its replay row: a large typed wait set spills to its card with its
/// program feedback typed beside it. Answers the outcome to record and the
/// spilled body when one was stored.
pub(crate) fn spill_before_record(
    gated_write: &GatedActorWrite<'_>,
    storage: &ExecutorStorage<'_>,
    run_id: EntityId,
    seq: u64,
    outcome: SelfDispatchOutcome,
) -> Result<(SelfDispatchOutcome, Option<CodeRunRawOutput>)> {
    let determinism = CodeRunDeterminism::new(1_719_000_001_000, [0xAB; 32]);
    let record = CodeRunReplayRecord::new(run_id, determinism);
    let mut host = RecordingJsHost::new(gated_write, run_id, seq, determinism, None)
        .with_recoverable_outputs(storage, &record, Vec::new())
        .map_err(|error| Error::InvalidConfig(format!("spill host: {error}")))?;
    let spilled = host.store_large_answer(seq, outcome)?;
    let output = host.captured.last().cloned();
    Ok((spilled, output))
}
