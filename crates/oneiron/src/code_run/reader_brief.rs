//! The task text a reader child's run is given: a read child's names its
//! one source; a scoped child's (FIX 7507) names every input and port its
//! parent lent it, and nothing of the vault around them.

use super::{ReaderJob, ReaderJobKind, ScopedChildSpec};

/// The child's task text: its ask, its source, the protocol it answers by,
/// the shape of its finding, and its cutoff. A scoped child's names its
/// inputs and its lent ports in place of the one source.
#[must_use]
pub fn reader_task_brief(job: &ReaderJob) -> String {
    if let ReaderJobKind::ScopedAgent { spec } = &job.kind {
        return scoped_task_brief(job, spec);
    }
    let source = &job.binding.source;
    let (start, end) = source.range;
    format!(
        "You are a reader child of a code run. Read one result of your parent and answer \
         one question about it.\n\
         Question: {ask}\n\
         Source: the result named `src` (handle {handle}), bytes {start} to {end} of your \
         parent's body. Read it with describe, slice, search, query and chunks on `src` or on a \
         range ref inside it, `{handle}#<start>-<end>`; every offset is your parent's. No other \
         result, verb or write is yours.\n\
         Protocol: store your finding with `store(finding)`, then call \
         `tasks.update({{task_ref: \"{task}\", resultRef: <its name>}})`. A later report \
         replaces an earlier one; the latest one stands when your run ends.\n\
         Finding: one JSON object, {{\"answer\": ..., \"cites\": [[start, end], ...], \
         \"coverage\": [[start, end], ...], \"partial\": true|false}}, its spans in your \
         parent's byte offsets: `cites` what the answer rests on, `coverage` what you read. Set \
         `partial` when you did not read the whole source.\n\
         Cutoff: unix ms {cutoff}. Report before it; a report after it is refused.",
        ask = job.ask,
        handle = source.handle,
        task = job.task.to_hex(),
        cutoff = job.binding.child_cutoff_unix_ms,
    )
}

/// A scoped child's task text: its ask, each lent input by its name, handle
/// and range, its lent ports, the protocol it answers by, and its cutoff.
fn scoped_task_brief(job: &ReaderJob, spec: &ScopedChildSpec) -> String {
    let inputs: String = spec
        .inputs
        .iter()
        .map(|(name, source)| {
            let (start, end) = source.range;
            let handle = &source.handle;
            format!("\n- `{name}` (handle {handle}), bytes {start} to {end} of your parent's body")
        })
        .collect();
    let ports = if spec.ports.is_empty() {
        "none".to_owned()
    } else {
        spec.ports
            .iter()
            .map(|port| format!("`{port}`"))
            .collect::<Vec<_>>()
            .join(", ")
    };
    format!(
        "You are a scoped child of a code run. Your parent lent you the inputs and ports below \
         and nothing else.\n\
         Task: {ask}\n\
         Inputs: read each with describe, slice, search, query and chunks on its name or on a \
         range ref inside it, `<handle>#<start>-<end>`; every offset is your parent's.{inputs}\n\
         Ports: {ports}. No other result, verb or write is yours.\n\
         Protocol: store your result, one JSON object, with `store(result)`, then call \
         `tasks.update({{task_ref: \"{task}\", resultRef: <its name>}})`. A later report \
         replaces an earlier one; the latest one stands when your run ends.\n\
         Cutoff: unix ms {cutoff}. Report before it; a report after it is refused.",
        ask = job.ask,
        task = job.task.to_hex(),
        cutoff = job.binding.child_cutoff_unix_ms,
    )
}
