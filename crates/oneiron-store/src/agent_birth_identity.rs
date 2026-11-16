//! The derived id of the asset that carries a birthed agent's captured
//! source. The agent definition layer (`agent_def`) writes that asset; the
//! store's export and archive paths derive the same id to find it.
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::fingerprint::purposes;

pub fn birth_source_id(child: &EntityId) -> Result<EntityId> {
    EntityId::derive_legacy_material(purposes::agent_def::BIRTH_SOURCE, &[child.as_bytes()])
}
