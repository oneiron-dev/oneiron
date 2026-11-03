//! Deterministic identity used by commitment projection writes.

use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::entity_id::derived_domains::COMMITMENT_PROJECTION_ACTOR;
use crate::write_envelope::WriteActor;

/// The pinned System actor for engine projection writes.
///
/// Derived, not minted (`EntityId::derive` over a fixed domain): the
/// projector's identity must survive a reopen and be the same on every device.
pub fn commitment_projection_actor() -> crate::Result<WriteActor> {
    Ok(WriteActor::new(
        EntityId::derive(COMMITMENT_PROJECTION_ACTOR, &[])?,
        EdgeActorClass::System,
    ))
}
