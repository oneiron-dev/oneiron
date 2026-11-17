//! Door for `tests/remote_task_cancel.rs` (L8-29): one pass of the served
//! poll of remote MCP tasks, as the connector settler runs it.

use crate::server::SyncServer;

/// Runs one pass of the served poll of remote MCP tasks over `server`'s
/// vault and `[connectors]`: each due Deferred send's task is polled, the
/// owner's stop sent first when asked for. Blocking: it sends, so call it
/// on a blocking worker.
pub fn poll_remote_tasks_once(server: &SyncServer) {
    crate::connector_call_host::poll_remote_tasks(server);
}
