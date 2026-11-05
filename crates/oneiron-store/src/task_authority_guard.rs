//! Immutable task-authority fact row and edge deletion guards.

use crate::write_envelope::task_body::TaskRole;
use crate::write_envelope::task_body::task_role_from_body_bytes;
use oneiron_base::edge::EdgeKind;
use oneiron_base::error::Error;
use oneiron_base::error::RecordError;
use oneiron_base::error::Result;
use oneiron_base::registry::ENTITY_TYPE_TASK;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::record_layout::ENTITY_METADATA_HEADER_LEN;
use oneiron_contracts::record_layout::EntityMetadataHeader;

pub fn fact_removal_refused() -> Error {
    Error::Record(RecordError::InvalidTaskBody(
        "task authority facts are immutable",
    ))
}
