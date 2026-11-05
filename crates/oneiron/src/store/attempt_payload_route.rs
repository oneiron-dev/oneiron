//! Core half of `store::attempt_payload_route`: its store-layer items live in `oneiron_store::attempt_payload_route` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::attempt_payload_route::*;

use crate::store::attempt_id::AttemptId;
use crate::store::attempt_record::ATTEMPT_RECORD_VERSION;
use crate::store::dispatch_attempt_kind::AGENT_DISPATCH_ATTEMPT_TYPE;
use crate::store::dreamer_attempt_kind::DREAMER_RUNNER_ATTEMPT_KIND;
use crate::store::is_opaque_erased;
use serde::Deserialize;

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
