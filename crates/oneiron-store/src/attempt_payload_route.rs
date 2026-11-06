//! The routing probe that tells an agent dispatch's attempt row apart
//! without the strict reader: its record version, the Dreamer kind and its
//! payload's attempt type, and the family test checkpoint carriage routes
//! on. The attempt queue's response carriage
//! (`attempt_queue::payload_erase::response`) decodes, scans and retires
//! the rows it finds.
use serde::Deserialize;

use crate::attempt_id::AttemptId;
use crate::dispatch_attempt_kind::AGENT_DISPATCH_ATTEMPT_TYPE;
use crate::dreamer_attempt_kind::DREAMER_RUNNER_ATTEMPT_KIND;

/// The Dreamer attempt payload's pinned key naming its attempt type.
pub const PAYLOAD_ATTEMPT_TYPE_KEY: &str = "job_type";

/// What the routing probe reads of a queue row: its kind and payload, past
/// every validator the strict reader runs.
#[derive(Deserialize)]
pub struct Routing {
    pub kind: String,
    pub payload: Vec<u8>,
}
