//! Fixed base-agent principal rows and their immutable write guards.

use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::temporal::TimeRange;

/// The seeded MACHINE row's body; the row itself carries seed time 0.
pub const ACTOR_BODY: &[u8] = b"Dreamer authority";
/// The Coach's seeded MACHINE row body, seeded like the Dreamer's at time 0.
pub const COACH_BODY: &[u8] = b"Coach authority";
pub fn dreamer_actor_id() -> Result<EntityId> {
    crate::code_snapshot::ids::entity_id_from_hash_material(b"oneiron.dreamer.authority.v1", &[])
}
pub fn coach_actor_id() -> Result<EntityId> {
    crate::code_snapshot::ids::entity_id_from_hash_material(b"oneiron.coach.authority.v1", &[])
}
/// The fixed body of a base-agent principal row; `None` for any other id.
pub fn base_agent_body(id: EntityId) -> Result<Option<&'static [u8]>> {
    Ok(if id == dreamer_actor_id()? {
        Some(ACTOR_BODY)
    } else if id == coach_actor_id()? {
        Some(COACH_BODY)
    } else {
        None
    })
}
/// Whether `id` is one of the two fixed base-agent principal rows, which every
/// replica seeds identically and no write, delete or tombstone may change.
pub fn is_base_agent_actor(id: &EntityId) -> Result<bool> {
    Ok(base_agent_body(*id)?.is_some())
}

pub fn guard_actor_put(
    id: EntityId,
    entity_type: u8,
    data: &[u8],
    occurred: TimeRange,
    learned_at: u64,
) -> Result<()> {
    let Some(body) = base_agent_body(id)? else {
        return Ok(());
    };
    if entity_type != oneiron_base::registry::ENTITY_TYPE_MACHINE
        || data != body
        || occurred.start != 0
        || occurred.end != 0
        || learned_at != 0
    {
        return Err(Error::Registry(
            oneiron_base::error::RegistryError::DreamerActorImmutable,
        ));
    }
    Ok(())
}

pub fn guard_actor_delete(id: &EntityId) -> Result<()> {
    if is_base_agent_actor(id)? {
        return Err(Error::Registry(
            oneiron_base::error::RegistryError::DreamerActorImmutable,
        ));
    }
    Ok(())
}
