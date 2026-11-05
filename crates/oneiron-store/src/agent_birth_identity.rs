//! The derived id of the asset that carries a birthed agent's captured
//! source. The agent definition layer (`agent_def`) writes that asset; the
//! store's export and archive paths derive the same id to find it.
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;

pub fn birth_source_id(child: &EntityId) -> Result<EntityId> {
    crate::code_snapshot::ids::entity_id_from_hash_material(
        b"oneiron.agent-birth-source.v1",
        &[child.as_bytes()],
    )
}
