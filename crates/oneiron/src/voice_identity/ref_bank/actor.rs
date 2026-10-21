//! Who acts on a voice through the bank's typed doors (FIX 4393). A real
//! person acts on their own voice on their own person proof, revalidated as
//! a live person in the acting transaction, owner of the vault or not: the
//! same consent the owner gives, applied to that subject. A designed
//! (synthetic) voice belongs to the entity that created it, the owner by
//! default: its creator acts on it on its own credential-bound read key and
//! the actor binding every write checks, with no person proof, since no real
//! person is its subject. A creator without a person's proof never acts on a
//! real person's voice, and nobody acts on another's.
use super::{VoiceRefSubjectKind, invalid, read_identity, render_history::read_render_consent};
use crate::claim::ScopedReadActorKey;
use crate::consent::AuthenticatedOwner;
use crate::edge::EdgeActorClass;
use crate::error::{Error, GateError, Result};
use crate::memory::{Memory, MemoryResult, verify_actor_binding_in_txn};
use crate::{EntityId, Vault};

/// Who acts on a voice: a live person on their own proof, or a designed
/// voice's creator on its credential.
#[derive(Debug, Clone)]
pub enum VoiceBankActor {
    /// A live person on their own proof: a real voice's subject, or a
    /// designed voice's creator. The vault owner acts as one.
    Person(AuthenticatedOwner),
    /// A designed voice's creator on its own credential, with no person
    /// proof: it acts on designed voices alone.
    Creator(VoiceCreator),
}

/// A designed voice's creator: the actor a handle is bound to, with the read
/// key its credential gives it. Only [`VoiceBankActor::creator`] builds one.
#[derive(Debug, Clone)]
pub struct VoiceCreator {
    entity: EntityId,
    class: EdgeActorClass,
    key: ScopedReadActorKey,
}

/// The actor of one act, revalidated in its transaction: the entity it is,
/// and whether a person's proof carried it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct VoiceParty {
    pub(super) entity: EntityId,
    person: bool,
}

impl VoiceBankActor {
    /// `memory`'s bound actor as a designed voice's creator, on the read key
    /// its credential gives it.
    ///
    /// # Errors
    ///
    /// As [`Memory::read_key`] refuses: the actor does not hold its class,
    /// or its credential grants it no read.
    pub fn creator(memory: &Memory<'_>) -> MemoryResult<Self> {
        Ok(Self::Creator(VoiceCreator {
            entity: memory.actor(),
            class: memory.actor_class(),
            key: memory.read_key()?,
        }))
    }

    /// The entity this actor is, for a pure read or to stamp an input: never
    /// for an act, which takes it from [`Self::revalidate_in_txn`].
    pub fn entity_for_read(&self, vault: &Vault) -> Result<EntityId> {
        match self {
            Self::Person(person) => person.actor_for_read(vault),
            Self::Creator(creator) => Ok(creator.entity),
        }
    }

    /// The actor, revalidated in `txn`: a person's proof as a live person's
    /// (never the owner tier), a creator's actor binding and credential as
    /// live.
    pub(super) fn revalidate_in_txn(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
    ) -> Result<VoiceParty> {
        match self {
            Self::Person(person) => Ok(VoiceParty {
                entity: person.revalidate_person_in_txn(vault, txn)?,
                person: true,
            }),
            Self::Creator(creator) => {
                let lapsed = || {
                    Error::Gate(GateError::ConsentOwnerNotAuthenticated(
                        "the designed voice's creator or its credential is no longer live",
                    ))
                };
                verify_actor_binding_in_txn(vault, txn, creator.entity, creator.class)
                    .map_err(|_| lapsed())?;
                if !vault.scoped_read(creator.key.clone()).proof_live_in(txn)? {
                    return Err(lapsed());
                }
                Ok(VoiceParty {
                    entity: creator.entity,
                    person: false,
                })
            }
        }
    }
}

/// The refusal of an act on a voice that is another's.
pub(super) fn others_voice() -> Error {
    invalid(
        "the voice is another's: only its subject, or a designed voice's creator, banks, \
         consents to or provisions it",
    )
}

impl VoiceParty {
    /// Refuses a voice of `kind` this party may not act on: a real person's
    /// voice takes that person's own proof.
    pub(super) fn admits(self, kind: VoiceRefSubjectKind) -> Result<()> {
        if kind == VoiceRefSubjectKind::Person && !self.person {
            return Err(invalid(
                "a real person's voice takes their own person proof: a creator's credential acts \
                 on designed voices alone",
            ));
        }
        Ok(())
    }

    /// Refuses unless this party is `voice_id`'s subject or creator as the
    /// bank holds it, and may act on its kind. The voice's subject and kind
    /// as the bank holds them: its identity's, or before its first pack its
    /// render decision's; None when the bank holds nothing of the voice.
    pub(super) fn bind_in(
        self,
        store: &crate::store::Store,
        txn: &heed::RoTxn<'_>,
        voice_id: &str,
    ) -> Result<Option<(EntityId, VoiceRefSubjectKind)>> {
        let held = match read_identity(store, txn, voice_id)? {
            Some(identity) => Some((identity.owner, identity.subject_kind)),
            None => read_render_consent(store, txn, voice_id)?
                .map(|consent| (consent.decision.subject, consent.decision.subject_kind)),
        };
        if let Some((subject, kind)) = held {
            if subject != self.entity {
                return Err(others_voice());
            }
            self.admits(kind)?;
        }
        Ok(held)
    }
}
