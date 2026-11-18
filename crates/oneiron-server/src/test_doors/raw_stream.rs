//! Doors for `tests/caller_deadline.rs` (review round 2 of #7831): the raw
//! stream door's model stream, opened as the door opens it and left
//! unpolled.

use oneiron::{LlmRequest, LlmStream};

use crate::server::SyncServer;

/// The model stream `POST /v1/llm/stream` opens for the owner's `request`
/// on `deadline_ms`, from now: the owner's admission, the first rung
/// admitted and the deadline the door's ladder walk runs on. No rung is
/// sent until the stream is polled.
///
/// # Errors
///
/// The door's refusal before its stream starts, as text.
pub fn opened_unpolled(
    server: &SyncServer,
    request: LlmRequest,
    deadline_ms: u64,
) -> Result<LlmStream<'static>, String> {
    crate::api::raw_stream_opened_unpolled(server, request, deadline_ms)
}
