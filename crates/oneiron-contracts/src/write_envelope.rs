//! The write actor every write path stamps. The envelope, provenance and candidate types
//! stay in `oneiron::write_envelope`, which re-exports [`WriteActor`].

use crate::authority::AuthorityEntryHash;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;

/// Actor metadata required by `oneiron::write_envelope::WriteEnvelope`.
///
/// Equality is the actor's identity: its entity, class and observed
/// authority state. The run attempt a delegated agent's write is bound to
/// ([`Self::run_attempt`]) and the mark of a credential handed on to another
/// key ([`Self::with_handed_on_credential`]) are write context, not
/// identity, so two writes of one agent under different runs are the same
/// actor.
#[derive(Debug, Clone, Copy)]
pub struct WriteActor {
    entity_ref: EntityId,
    actor_class: EdgeActorClass,
    authority_frontier: Option<AuthorityEntryHash>,
    run_attempt: Option<[u8; 16]>,
    handed_on_credential: bool,
}

impl PartialEq for WriteActor {
    fn eq(&self, other: &Self) -> bool {
        self.entity_ref == other.entity_ref
            && self.actor_class == other.actor_class
            && self.authority_frontier == other.authority_frontier
    }
}

impl Eq for WriteActor {}

impl WriteActor {
    /// Creates a write actor from an entity id plus its caller-asserted class.
    #[must_use]
    pub const fn new(entity_ref: EntityId, actor_class: EdgeActorClass) -> Self {
        Self {
            entity_ref,
            actor_class,
            authority_frontier: None,
            run_attempt: None,
            handed_on_credential: false,
        }
    }

    /// Binds this write to the agent-dispatch attempt whose run makes it
    /// (FIX 10537), by the attempt's 16 id bytes: the Gate meets the run's
    /// ceiling with its delegation ancestors' live ceilings at the write.
    #[must_use]
    pub const fn with_run_attempt(mut self, attempt: [u8; 16]) -> Self {
        self.run_attempt = Some(attempt);
        self
    }

    /// The agent-dispatch attempt whose run makes this write, when its host
    /// bound one ([`Self::with_run_attempt`]).
    #[must_use]
    pub const fn run_attempt(self) -> Option<[u8; 16]> {
        self.run_attempt
    }

    /// Marks this write as made under a credential its mint handed on to
    /// another key (`VerifiedSlip::is_transferred`). The class still names
    /// the mint's, but the act is the key holder's, never the person's: a
    /// person gate refuses it and it stamps no person's provenance (rulings
    /// HANDED-ON-SLIP-PERSON Q1 = A, Q2 = A, 15 Nov; canon
    /// `#credential-read-key-built`: a narrower credential "never takes the
    /// owner's floor").
    #[must_use]
    pub const fn with_handed_on_credential(mut self) -> Self {
        self.handed_on_credential = true;
        self
    }

    /// Whether this actor acts as a person in its own right: its class is
    /// Human, and no credential handed on to another key makes the write
    /// ([`Self::with_handed_on_credential`]).
    #[must_use]
    pub const fn acts_as_own_person(self) -> bool {
        matches!(self.actor_class, EdgeActorClass::Human) && !self.handed_on_credential
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
