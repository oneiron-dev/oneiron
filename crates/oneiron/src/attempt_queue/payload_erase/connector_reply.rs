//! Event-scoped kept-body reach for a participant's hard erase.

use std::collections::BTreeSet;

use crate::attempt_queue::AttemptRecord;
use crate::connector_key::events::ConnectorEvent;
use crate::dreamer_runner::connector_event::{CONNECTOR_EVENT_FACET, CONNECTOR_EVENT_QUEUE_KIND};
use crate::dreamer_runner::decode_dreamer_attempt_payload;
use crate::entity_id::EntityId;

/// A frozen connector wake naming an erased participant reaches its bodies
/// even when the reply never acquired a job or result row.
pub(super) fn frozen_connector_event_id_for_erase(
    record: &AttemptRecord,
    actors: &BTreeSet<EntityId>,
) -> Option<String> {
    if record.kind != CONNECTOR_EVENT_QUEUE_KIND {
        return None;
    }
    let payload = decode_dreamer_attempt_payload(&record.payload).ok()?;
    if payload.attempt_type != CONNECTOR_EVENT_FACET {
        return None;
    }
    let rmpv::Value::Map(fields) = &payload.input else {
        return None;
    };
    let json = fields
        .iter()
        .find(|(key, _)| key.as_str() == Some("connector_event"))?
        .1
        .as_str()?;
    let event: ConnectorEvent = serde_json::from_str(json).ok()?;
    crate::outbound::connector_event_participant_ids(&event)
        .iter()
        .any(|id| actors.contains(id))
        .then_some(event.event_id)
}
