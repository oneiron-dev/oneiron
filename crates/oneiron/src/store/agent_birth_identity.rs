//! The derived id of the asset that carries a birthed agent's captured
//! source. The agent definition layer (`agent_def`) writes that asset; the
//! store's export and archive paths derive the same id to find it.
use crate::{entity_id::EntityId, error::Result};

pub(crate) fn birth_source_id(child: &EntityId) -> Result<EntityId> {
    crate::store::code_snapshot::entity_id_from_hash_material(
        b"oneiron.agent-birth-source.v1",
        &[child.as_bytes()],
    )
}
