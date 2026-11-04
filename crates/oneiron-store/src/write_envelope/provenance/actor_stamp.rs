//! Opaque actor stamp identity.

use oneiron_base::edge::EdgeActorClass;
use oneiron_contracts::entity_id::EntityId;

/// What a commit stamp names of its writer (FIX 10930): the opaque token in
/// the actor's place, and the actor's class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActorStamp {
    /// The id of the actor's `actor.stamp_token` claim.
    pub token: EntityId,
    /// The writing actor's class, which a stamp spells after its token.
    pub class: EdgeActorClass,
}
