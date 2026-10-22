//! The direct Linear mirror's decode memory on the server's retained-memory
//! line (FIX 8610): the narrow host port through which the adapter takes the
//! bytes a tracker body's decode allocates, on the same fair `ByteLine` and
//! `[limits]` row the server's other retained state takes them from. A body
//! larger than the whole line waits to run alone and is never refused for
//! its size; a wait that runs out leaves the body kept for a later pass.

use std::sync::Arc;
use std::time::Duration;

use crate::byte_line::ByteLine;
use crate::wire_telemetry::LimitQuestions;

/// The server's retained-memory line, as the Linear adapter's
/// [`oneiron_linear::LinearBodyLine`].
pub(super) struct ServerBodyLine {
    line: Arc<ByteLine>,
    questions: Arc<LimitQuestions>,
    /// The host's queue wait (`limits.queue_wait_timeout_ms`).
    wait: Duration,
    runtime: tokio::runtime::Handle,
}

impl ServerBodyLine {
    /// The line `server` holds, waiting at most its queue wait. Built on the
    /// runtime whose handle a pass's blocking thread waits through.
    pub(super) fn of(server: &crate::server::SyncServer) -> Self {
        Self {
            line: Arc::clone(&server.retained),
            questions: Arc::clone(server.wire_telemetry.limit_questions()),
            wait: server.config.limits.queue_wait(),
            runtime: tokio::runtime::Handle::current(),
        }
    }
}

impl oneiron_linear::LinearBodyLine for ServerBodyLine {
    fn hold(&self, bytes: u64) -> Option<Box<dyn Send>> {
        let bytes = usize::try_from(bytes).unwrap_or(usize::MAX);
        // Called only from a pass's blocking thread, never on the runtime.
        let held =
            self.runtime
                .block_on(self.line.reserve_alone(bytes, self.wait, &self.questions))?;
        Some(Box::new(held))
    }
}
