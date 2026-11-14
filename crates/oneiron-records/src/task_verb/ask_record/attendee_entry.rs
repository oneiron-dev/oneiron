//! Moved from `crates/oneiron/src/task_verb/ask_record/attendee_entry.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::conversation::attendee::ContainerAttendee;
use crate::task_verb::ask_record::*;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use rmpv::Value;
use serde::Deserialize;
use serde::Serialize;

pub const ENTRY_ID_DOMAIN: &[u8] = b"oneiron.tasks.attendee_entry.v1";

/// The entry fact id of `attendee` in `container`.
pub fn attendee_entry_id(container: EntityId, attendee: &ContainerAttendee) -> Result<EntityId> {
    match attendee {
        ContainerAttendee::Person(person) => EntityId::derive(
            ENTRY_ID_DOMAIN,
            &[container.as_bytes(), b"person", person.as_bytes()],
        ),
        ContainerAttendee::Speaker {
            session_key,
            speaker_key,
        } => EntityId::derive(
            ENTRY_ID_DOMAIN,
            &[
                container.as_bytes(),
                b"speaker",
                session_key.as_bytes(),
                speaker_key.as_bytes(),
            ],
        ),
    }
}
