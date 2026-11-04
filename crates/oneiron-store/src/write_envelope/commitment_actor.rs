//! Deterministic identity used by commitment projection writes.

use crate::write_envelope::WriteActor;
use oneiron_base::edge::EdgeActorClass;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::entity_id::derived_domains::COMMITMENT_PROJECTION_ACTOR;

/// The pinned System actor for engine projection writes.
///
/// Derived, not minted (`EntityId::derive` over a fixed domain): the
/// projector's identity must survive a reopen and be the same on every device.
pub fn commitment_projection_actor() -> oneiron_contracts::error::Result<WriteActor> {
    Ok(WriteActor::new(
        EntityId::derive(COMMITMENT_PROJECTION_ACTOR, &[])?,
        EdgeActorClass::System,
    ))
}
