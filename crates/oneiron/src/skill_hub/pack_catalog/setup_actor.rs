//! Who works a pack's guided setup (OF-378): the owner on their own proof,
//! or an authenticated agent acting for the owner. An agent works the
//! owner's session: it opens, reads and checks it, and pins the credential
//! or connector key the owner stored or registered. Allowing a connection's
//! permissions mints the owner's standing grants, so an agent's `allow` is
//! put to the owner as an ask
//! ([`Vault::ask_owner_to_allow_pack_connection`]), whose yes lands it.

use heed::RoTxn;

use super::invalid;
use crate::consent::AuthenticatedOwner;
use crate::write_envelope::WriteActor;
use crate::{EdgeActorClass, EntityId, Vault, error::Result};

/// One setup door's actor.
#[derive(Debug, Clone, Copy)]
pub enum PackSetupActor<'a> {
    /// The owner, on the owner's own proof: the session keyed to them.
    Owner(&'a AuthenticatedOwner),
    /// An agent acting for the owner, verified as a writer in each snapshot
    /// it reads or writes in: the owner's session.
    Agent(WriteActor),
}

impl PackSetupActor<'_> {
    /// The principal whose session a read in `txn` works on: the owner's
    /// own, or for an agent the owner's (`agent_setup_principal_in_txn`).
    pub(crate) fn principal_for_read(
        self,
        vault: &Vault,
        txn: &RoTxn<'_>,
        pack: &str,
        content_hash: Option<&str>,
    ) -> Result<String> {
        match self {
            Self::Owner(owner) => Ok(owner.principal_ref_for_read(vault)?.to_owned()),
            Self::Agent(agent) => {
                vault.agent_setup_principal_in_txn(txn, agent, pack, content_hash)
            }
        }
    }

    /// The principal whose session a write in `txn` works on: the owner's
    /// proof revalidated in that snapshot, or the agent verified in it.
    pub(crate) fn principal_in_txn(
        self,
        vault: &Vault,
        txn: &RoTxn<'_>,
        pack: &str,
        content_hash: Option<&str>,
    ) -> Result<String> {
        match self {
            Self::Owner(owner) => Ok(owner.principal_ref_in_txn(vault, txn)?.to_owned()),
            Self::Agent(agent) => {
                vault.agent_setup_principal_in_txn(txn, agent, pack, content_hash)
            }
        }
    }

    /// The entity this actor is: the owner's person, or the agent.
    pub(crate) fn entity_for_read(self, vault: &Vault) -> Result<EntityId> {
        match self {
            Self::Owner(owner) => owner.actor_for_read(vault),
            Self::Agent(agent) => Ok(agent.entity_ref()),
        }
    }
}

impl Vault {
    /// The owner whose session `agent` works, read in `txn` once the agent
    /// is verified there as a bound writer: of the vault's live owners, the
    /// one whose session over the exact source moved last, or before any
    /// such session, the first live owner (a personal vault's one owner).
    fn agent_setup_principal_in_txn(
        &self,
        txn: &RoTxn<'_>,
        agent: WriteActor,
        pack: &str,
        content_hash: Option<&str>,
    ) -> Result<String> {
        if agent.actor_class() != EdgeActorClass::Agent {
            return Err(invalid(
                "a pack setup is worked by its owner or by an agent acting for the owner",
            ));
        }
        self.verify_write_actor_in_txn(txn, &agent)?;
        let owners: Vec<String> = crate::policy_model::owners_in_txn(self, txn)?
            .iter()
            .map(EntityId::to_hex)
            .collect();
        let receipt = self.pack_setup_receipt_in_txn(txn, pack, content_hash)?;
        let worked = self
            .pack_setup_sessions_in_txn(txn, pack, &receipt.content_hash)?
            .into_iter()
            .filter(|session| owners.contains(&session.principal_ref))
            .max_by_key(|session| session.updated_at)
            .map(|session| session.principal_ref);
        worked
            .or_else(|| owners.into_iter().next())
            .ok_or_else(|| invalid("the vault has no live owner to set this pack up for"))
    }
}
