//! The media sibling of `call_as_step` (FIX 465, FIX 2245): a durable
//! step's media call keyed by its attempt and its request's canonical hash.
//! The host keeps what the call was given under the key: a call's answer,
//! or a video job's ticket and never its clip, which a later poll of the
//! ticket answers. The step sent again in the same attempt answers from
//! there and is not paid for or rendered again.
use super::DurableStepContext;
use crate::entity_id::bytes_to_hex_lower;
use crate::llm::media::{MediaReplayKey, MediaRequest};

/// The replay key of `request`, sent as `ctx`'s step.
///
/// # Errors
///
/// A request whose canonical bytes do not encode.
pub fn media_step_key(
    ctx: &DurableStepContext<'_>,
    request: &MediaRequest,
) -> Result<MediaReplayKey, serde_json::Error> {
    MediaReplayKey::step(bytes_to_hex_lower(ctx.attempt_id.as_bytes()), request)
}
