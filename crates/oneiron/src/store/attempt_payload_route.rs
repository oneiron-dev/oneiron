//! The routing probe that tells an agent dispatch's attempt row apart
//! without the strict reader: its record version, the Dreamer kind and its
//! payload's attempt type, and the family test checkpoint carriage routes
//! on. The attempt queue's response carriage
//! (`attempt_queue::payload_erase::response`) decodes, scans and retires
//! the rows it finds.
use serde::Deserialize;

use crate::store::attempt_id::AttemptId;
use crate::store::attempt_record::ATTEMPT_RECORD_VERSION;
use crate::store::dispatch_attempt_kind::AGENT_DISPATCH_ATTEMPT_TYPE;
use crate::store::dreamer_attempt_kind::DREAMER_RUNNER_ATTEMPT_KIND;
use crate::store::is_opaque_erased;

/// The Dreamer attempt payload's pinned key naming its attempt type.
const PAYLOAD_ATTEMPT_TYPE_KEY: &str = "job_type";

/// What the routing probe reads of a queue row: its kind and payload, past
/// every validator the strict reader runs.
#[derive(Deserialize)]
struct Routing {
    kind: String,
    payload: Vec<u8>,
}

/// Whether `raw` reads, by the routing probe alone, as a Dreamer agent
/// dispatch's row: its record version, the Dreamer kind, and a payload map
/// naming the agent dispatch attempt type.
fn routed_dispatch(raw: &[u8]) -> bool {
    let Some((&version, body)) = raw.split_first() else {
        return false;
    };
    let Ok(routing) = rmp_serde::from_slice::<Routing>(body) else {
        return false;
    };
    version == ATTEMPT_RECORD_VERSION
        && routing.kind == DREAMER_RUNNER_ATTEMPT_KIND
        && matches!(
            rmpv::decode::read_value(&mut routing.payload.as_slice()),
            Ok(rmpv::Value::Map(entries)) if entries.iter().any(|(name, value)| {
                name.as_str() == Some(PAYLOAD_ATTEMPT_TYPE_KEY)
                    && value.as_str() == Some(AGENT_DISPATCH_ATTEMPT_TYPE)
            })
        )
}

/// Whether the queue row `key` holding `raw` is a Dreamer agent dispatch's:
/// its family, even once an erase took its text, and the erased marker an
/// opaque one's retirement leaves (FIX 9390).
pub(crate) fn attempt_payload_family(key: &[u8], raw: &[u8]) -> bool {
    AttemptId::from_bytes(key).is_ok() && (is_opaque_erased(raw) || routed_dispatch(raw))
}
