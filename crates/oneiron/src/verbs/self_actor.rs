//! `self.actor` (FIX 1047): the caller's own bound actor and the person it
//! acts for, as refs a claim or note can take as its subject, so a plugin's
//! notes about itself or about its person outlive the one conversation it
//! wrote them in.
use serde::{Deserialize, Serialize};

use crate::memory::MemoryResult;
use crate::{EdgeActorClass, EntityId, Error, Vault};

/// `self.actor`'s answer: the actor the caller's credential binds, its
/// class, and the person it acts for, each a 32-hex entity ref.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SelfActorRefs {
    /// The actor every write of the caller is attributed to.
    pub actor_ref: String,
    /// `human`, `agent` or `system`.
    pub actor_class: String,
    /// The person the caller acts for: a person himself; an agent or system
    /// actor on a personal vault, the vault's live owner, who mints its
    /// credential. `None` where the vault records no such person: a shared
    /// vault, whose owners are several and none is named the actor's.
    pub person_ref: Option<String>,
}

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
            if vault.shared_vault_creation_in_txn(&txn)?.is_some() {
                None
            } else {
                crate::policy_model::owners_in_txn(vault, &txn)?
                    .into_iter()
                    .next()
            }
        }
    };
    Ok(SelfActorRefs {
        actor_ref: actor.to_hex(),
        actor_class: class.gate_actor_class().to_owned(),
        person_ref: person.map(|person| person.to_hex()),
    })
}
