//! The native report that supplied a closed workflow's Done judge.

use super::super::runner_refusal;
use super::*;

pub(crate) fn workflow_done_judge_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    attempt: AttemptId,
    generation: u32,
    task: EntityId,
) -> Result<Option<String>> {
    let via = TaskVia::Host(HostBinding::new(
        attempt,
        WORKFLOW_TRY_OWNER.to_owned(),
        generation,
        None,
    ));
    let key = qualified_key(&via, &RunEnd::Completed.report_key(), "report key")
        .map_err(runner_refusal)?;
    crate::task_verb::report_journal::done_judge_in_txn(vault, txn, attempt, generation, task, &key)
}
