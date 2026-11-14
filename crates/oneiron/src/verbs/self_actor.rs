//! `self.actor` (FIX 1047): the caller's own bound actor and the person it
//! acts for, as refs a claim or note can take as its subject, so a plugin's
//! notes about itself or about its person outlive the one conversation it
//! wrote them in.
use serde::{Deserialize, Serialize};

use crate::memory::MemoryResult;
use crate::{EdgeActorClass, EntityId, Error, Vault};

#[doc(hidden)]
pub use oneiron_verb_wire::verbs::self_actor::SelfActorRefs;

/// The refs of `actor`, bound as `class`, on `vault` ([`SelfActorRefs`]).
pub fn self_actor_refs(
    vault: &Vault,
    actor: EntityId,
    class: EdgeActorClass,
) -> MemoryResult<SelfActorRefs> {
    let person = match class {
        EdgeActorClass::Human => Some(actor),
        EdgeActorClass::Agent | EdgeActorClass::System => {
            let txn = vault.store.env.read_txn().map_err(Error::from)?;
            match vault.shared_vault_creation_in_txn(&txn)? {
                Some(shared) => match class {
                    EdgeActorClass::Agent => {
                        agent_minting_member_in_txn(vault, &txn, actor, shared.vault_id)?
                    }
                    _ => None,
                },
                None => crate::policy_model::owners_in_txn(vault, &txn)?
                    .into_iter()
                    .next(),
            }
        }
    };
    Ok(SelfActorRefs {
        actor_ref: actor.to_hex(),
        actor_class: class.gate_actor_class().to_owned(),
        person_ref: person.map(|person| person.to_hex()),
    })
}

/// The member who minted `agent`'s credentials on shared vault `vault_id`
/// (FIX 11713): the one person every mint the authority fold keeps for it
/// names as its minting member, revoked, consumed and expired mints
/// included, while that person is live and still a member. `None` where no
/// mint names one, two name different people, or the person left.
fn agent_minting_member_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    agent: EntityId,
    vault_id: u64,
) -> crate::error::Result<Option<EntityId>> {
    let holder = agent.to_hex();
    let fold = vault.authority_view_readonly_in_txn(txn)?;
    let mut named = fold
        .slips
        .mints
        .values()
        .filter(|mint| mint.action.claims.holder_ref == holder)
        .filter_map(|mint| mint.action.minting_member);
    let Some(member) = named.next() else {
        return Ok(None);
    };
    if named.any(|other| other != member) {
        return Ok(None);
    }
    if !crate::consent::person_is_live_in_txn(vault, txn, &member)? {
        return Ok(None);
    }
    let still_member = vault
        .shared_members_in_txn(txn, vault_id)?
        .into_iter()
        .any(|(id, _)| id == member);
    Ok(still_member.then_some(member))
}
