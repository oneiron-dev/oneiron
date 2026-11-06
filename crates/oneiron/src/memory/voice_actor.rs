//! Credential-bound voice actors and their transaction-local proof values.

use crate::claim::ScopedReadActorKey;
use crate::consent::AuthenticatedOwner;
use crate::edge::EdgeActorClass;
use crate::error::{Error, GateError, Result};
use crate::memory::{Memory, MemoryResult, verify_actor_binding_in_txn};
use crate::{EntityId, Vault};
use serde::{Deserialize, Serialize};

/// Whose voice a banked identity is (FIX 4393). Its owner/subject id is that
/// entity either way; the kind is bound when the bank first holds the voice
/// and never relabelled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum VoiceRefSubjectKind {
    /// A real person's own voice: its subject consents to its rendering on
    /// their own person proof, under a consent basis.
    Person,
    /// A designed (synthetic) voice: it belongs to the entity that created
    /// it, the owner by default. No real person is its subject, so no person
    /// proof or consent basis is asked of it.
    Designed,
}

impl VoiceRefSubjectKind {
    /// The kind a render decision's input names when it names none: a
    /// person's. Only an input wire defaults it; a stored row never does.
    #[must_use]
    pub const fn input_default() -> Self {
        Self::Person
    }
}

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
pub(crate) struct VoiceParty {
    pub(crate) entity: EntityId,
    pub(crate) person: bool,
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
    pub(crate) fn revalidate_in_txn(
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

pub(crate) fn invalid(message: &str) -> Error {
    Error::InvalidConfig(message.into())
}
pub(crate) fn valid_id(id: &str) -> Result<()> {
    if id.trim().is_empty() || id.len() > 128 || id.contains('\0') {
        return Err(invalid("invalid voice reference id"));
    }
    Ok(())
}
impl VoiceParty {
    /// Refuses a voice of `kind` this party may not act on: a real person's
    /// voice takes that person's own proof. A managed vault's non-owner
    /// consents on their own forwarded slip (FIX 8969, 5122) like any other
    /// person: "own" is the voice the bank's record binds to the person that
    /// proof names ([`Self::bind_in`]), never a voice the request claims, so
    /// every other person's voice stays out of reach.
    pub(crate) fn admits(self, kind: VoiceRefSubjectKind) -> Result<()> {
        if kind == VoiceRefSubjectKind::Person && !self.person {
            return Err(invalid(
                "a real person's voice takes their own person proof: a creator's credential acts \
                 on designed voices alone",
            ));
        }
        Ok(())
    }
}
