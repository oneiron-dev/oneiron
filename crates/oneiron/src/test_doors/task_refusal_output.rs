//! Door for `tests/run_row_door_scoped_reads_tasks.rs` (FIX
//! [RUN-ROW-DOOR-TESTS-ABSENT]): the reason body a declining `tasks.refuse`
//! released to its run. The dispatcher holds it for its host, and no reply
//! carries it.
//! Compiled only under `--cfg oneiron_test_support`; never API.

use crate::code_run::HostSelfDispatcher;

/// Takes the reason body `dispatcher`'s last call released: the bytes a
/// declining `tasks.refuse` read on the key its door admitted the call with,
/// or `None` when that key did not read the reason. A second take reads
/// `None`.
#[must_use]
pub fn take_released_reason(dispatcher: &HostSelfDispatcher<'_>) -> Option<Vec<u8>> {
    dispatcher.take_task_refusal_output()
}
