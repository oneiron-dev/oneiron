//! The write actor every write path stamps. The envelope, provenance and candidate types
//! stay in `oneiron::write_envelope`, which re-exports [`WriteActor`].

use crate::authority::AuthorityEntryHash;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;

/// Actor metadata required by `oneiron::write_envelope::WriteEnvelope`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriteActor {
    entity_ref: EntityId,
    actor_class: EdgeActorClass,
    authority_frontier: Option<AuthorityEntryHash>,
}

impl WriteActor {
    /// Creates a write actor from an entity id plus its caller-asserted class.
    #[must_use]
    pub const fn new(entity_ref: EntityId, actor_class: EdgeActorClass) -> Self {
        Self {
            entity_ref,
            actor_class,
            authority_frontier: None,
        }
    }

    /// Binds this write to an authority state observed by its author.
    #[must_use]
    pub const fn with_authority_frontier(mut self, frontier: AuthorityEntryHash) -> Self {
        self.authority_frontier = Some(frontier);
        self
    }

    /// The observed causal state, never inferred from the write timestamp.
    #[must_use]
    pub const fn authority_frontier(self) -> Option<AuthorityEntryHash> {
        self.authority_frontier
    }

    /// Actor entity reference stamped into candidate writes.
    #[must_use]
    pub const fn entity_ref(self) -> EntityId {
        self.entity_ref
    }

    /// Actor class stamped into candidate writes and supplied to the Gate evaluator.
    #[must_use]
    pub const fn actor_class(self) -> EdgeActorClass {
        self.actor_class
    }
}
