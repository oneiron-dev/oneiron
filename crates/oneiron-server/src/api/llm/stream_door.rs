//! The raw stream door's model stream, opened as `POST /v1/llm/stream` opens
//! it and left unpolled, for `tests/caller_deadline.rs` (review round 2 of
//! #7831): the test polls it first only once the caller's deadline has
//! passed, as the door's relay does when the runtime suspends it past the
//! deadline. Compiled only under `--cfg oneiron_test_support`;
//! `crate::test_doors::raw_stream` opens it.

use oneiron::{LlmRequest, LlmStream};
use tokio::time::Instant;

use super::{RawCall, admit_owner};
use crate::server::SyncServer;

/// The model stream the raw stream door opens for the owner's `request` on
/// `deadline_ms`: the owner's admission, the first rung admitted, and the
/// deadline the door's ladder walk runs on, from now. No rung is sent until
/// the stream is polled. The door's owner check is not made here.
///
/// # Errors
///
/// The door's refusal before its stream starts, as text.
pub(crate) fn raw_stream_opened_unpolled(
    server: &SyncServer,
    request: LlmRequest,
    deadline_ms: u64,
) -> Result<LlmStream<'static>, String> {
    let call = RawCall {
        request,
        deadline_ms: Some(deadline_ms),
    };
    let (mut request, _clock, deadline) = call.into_call(Instant::now());
    let deadline = deadline.map_err(|error| format!("{error:?}"))?;
    let (ladder, run) = admit_owner(server, &mut request)
        .map_err(|refused| format!("refused with status {}", refused.status()))?;
    ladder
        .stream_recorded_by(&run, request, None, deadline)
        .map(|(stream, _binding)| stream)
        .map_err(|error| format!("{error:?}"))
}
