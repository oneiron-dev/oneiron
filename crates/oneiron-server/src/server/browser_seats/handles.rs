//! A run browser's live-handle registry, charged to the host's
//! retained-memory line (`limits.retained_memory_bytes`, C013). The
//! session's driver resizes its charge before the registry grows and
//! shrinks it once the registry prunes; a read whose new handles the line
//! will not admit fails `MemoryFloor`, and the session stays.

use std::sync::Arc;

use oneiron_browser::HandleRetention;

use super::SyncServer;
use crate::byte_line::{ByteLine, HeldBytes};
use crate::wire_telemetry::LimitQuestions;

/// Where a browser session's live-handle charge is taken: the server's
/// retained line, and the questions a crossing asks.
#[derive(Clone)]
pub(crate) struct HandleLine {
    line: Arc<ByteLine>,
    questions: Arc<LimitQuestions>,
}

impl HandleLine {
    pub(crate) fn of(server: &SyncServer) -> Self {
        Self {
            line: Arc::clone(&server.retained),
            questions: Arc::clone(server.wire_telemetry.limit_questions()),
        }
    }

    /// One session's charge, holding nothing yet.
    pub(crate) fn charge(&self) -> Box<dyn HandleRetention> {
        Box::new(HandleCharge {
            held: self.line.empty(),
            line: Arc::clone(&self.line),
            questions: Arc::clone(&self.questions),
        })
    }
}

/// One session's charge on the line; it drops with the session's driver and
/// gives its bytes back.
struct HandleCharge {
    line: Arc<ByteLine>,
    questions: Arc<LimitQuestions>,
    held: HeldBytes,
}

impl HandleRetention for HandleCharge {
    fn resize(&mut self, bytes: usize) -> bool {
        self.line.try_resize(&mut self.held, bytes, &self.questions)
    }
}
