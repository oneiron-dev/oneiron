//! The caller's own task of an MCP `execute_code` run, kept as a body the
//! run owns (FIX 4606).
//!
//! Such a run captures no step capsule, so no start body keeps its task,
//! and its config marker keeps only a hash of it. A host that enters the
//! run again after a restart needs the exact text. So the run's first
//! entry keeps the task as one of the run's outputs, at
//! [`CALLER_TASK_OUTPUT_PATH`], through the run's own body store: an
//! occurrence the run owns, with its descriptor and marks, that an erase of
//! the run's actor releases as it releases the run's other replies. The
//! wait row keeps no copy.
//!
//! Only the host's declaration writes it: the exact text the host declared
//! the caller's own (FIX 7087), which is the admitted request's task, as
//! the host checked it against the run's config before the entry. No guest
//! value reaches it. A read takes it only while the run still holds that
//! occurrence, so an erased, withheld or drifted body is no task. Each
//! later entry still runs under the config marker's task, and the marker
//! refuses any other.

use super::super::store::record_text_output;
use super::super::types::{EngineExecutorConfig, EngineExecutorResult};
use crate::code_run::{CodeRunReplayRecord, ExecutorStorage, continuation_seed_body_in_txn};
use crate::{Result, Vault};

/// Where a run keeps its caller's own task (FIX 4606). A control path of
/// the run, never one a guest reads back.
const CALLER_TASK_OUTPUT_PATH: &str = "executor/repl/run.caller-task.txt";

/// Keeps `config.task` as the caller-task body of `record`, a canonical run
/// at its first entry, when `declared` is exactly that text: the task its
/// host declared the caller's own (FIX 7087). A run its host declared no
/// task for, or another text, and a run on an off-record session's storage
/// keep none (FIX 4606).
///
/// # Errors
///
/// Storage errors writing the body.
pub(in crate::engine_executor) fn record_caller_task(
    storage: &ExecutorStorage<'_>,
    record: &mut CodeRunReplayRecord,
    config: &EngineExecutorConfig,
    declared: Option<&str>,
) -> EngineExecutorResult<()> {
    if !matches!(storage, ExecutorStorage::Canonical(_)) || declared != Some(config.task.as_str()) {
        return Ok(());
    }
    record_text_output(
        storage,
        record,
        CALLER_TASK_OUTPUT_PATH.to_owned(),
        &config.task,
    )
}

/// The caller's own task `record`'s run keeps (FIX 4606), read in `txn`
/// through the run's own held occurrence of the body. `None` when the run
/// keeps no caller task, or its body is released, withheld, drifted or not
/// UTF-8.
///
/// # Errors
///
/// Storage errors reading the body.
pub(crate) fn caller_task_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    record: &CodeRunReplayRecord,
) -> Result<Option<String>> {
    let Some(output) = record
        .outputs
        .iter()
        .find(|output| output.path == CALLER_TASK_OUTPUT_PATH)
    else {
        return Ok(None);
    };
    let Some(bytes) = continuation_seed_body_in_txn(vault, txn, record.run_id, output)? else {
        return Ok(None);
    };
    Ok(String::from_utf8(bytes).ok())
}
