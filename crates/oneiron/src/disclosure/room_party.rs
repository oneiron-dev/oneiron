//! The term one room member brings to the room's meet (ARCH-0067 §8: "the
//! grants behind the people and agents present").

use super::disclosable_set::contact_clearance_in;
use crate::Vault;
use crate::authority::AuthorityFold;
use crate::counterparty_contact::CounterpartyContactStatus;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::federation::Scope;
use crate::registry::{ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_PERSON};
use crate::vault::LiveEntityRow;

/// How the room meet sees a member.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RoomParty {
    /// The vault owner: the embedded owner, or a live human owner binding
    /// in a rooted vault. It adds no term.
    VaultOwner,
    /// One of the vault's own agents: an active `agent` binding in this
    /// vault's authority fold, or one of its AGENT_DEF rows. It acts for the
    /// owner and adds no clearance term; its own grant bounds what it reads.
    VaultAgent,
    /// A member that one contact is About, where that contact is About this
    /// member alone: the contact's clearance. An agent that represents
    /// another person is one.
    Contact(EntityId),
    /// Anyone else: bottom, so public-only.
    Unknown,
}

impl RoomParty {
    /// The term this party adds to the meet; `None` adds none.
    pub(crate) fn clearance_in(
        self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
    ) -> Result<Option<Scope>> {
        Ok(match self {
            Self::VaultOwner | Self::VaultAgent => None,
            Self::Contact(contact) => Some(contact_clearance_in(vault, txn, contact)?),
            Self::Unknown => Some(Scope::default()),
        })
    }
}

/// Whether `member` is positively known as the vault owner: the embedded
/// owner, or a live human owner binding in a rooted vault.
pub(crate) fn is_vault_owner(
    fold: &AuthorityFold,
    embedded_owner: EntityId,
    member: &EntityId,
) -> bool {
    *member == embedded_owner
        || (fold.vault_id.is_some()
            && crate::authority::actor_binding_is_active(fold, member, "human"))
}

/// `member` as `txn` and its authority `fold` read it. The vault owner comes
/// first. Then a contact link: a member with any contact is that contact's
/// party or, when the link is ambiguous or the contact is not Active,
/// unknown; never the vault's own agent. A contact names its member when its
/// identity head names that member, a PERSON or an AGENT_DEF. Contacts are
/// read from their claims (OF-272), so a dropped contact row changes nothing.
pub(crate) fn room_party_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    fold: &AuthorityFold,
    member: EntityId,
) -> Result<RoomParty> {
    if is_vault_owner(fold, crate::vault::embedded_owner_actor_id()?, &member) {
        return Ok(RoomParty::VaultOwner);
    }
    let contacts = vault.counterparty_contact_ids_for_identity_in_txn(txn, &member)?;
    if let [contact] = contacts.as_slice() {
        let actor = matches!(
            crate::vault::live_entity_row_in_txn(&vault.store, txn, &member)?,
            LiveEntityRow::Live {
                entity_type: ENTITY_TYPE_PERSON | ENTITY_TYPE_AGENT_DEF,
                ..
            }
        );
        if actor && active_contact_in(vault, txn, contact)? {
            return Ok(RoomParty::Contact(*contact));
        }
    }
    if !contacts.is_empty() {
        return Ok(RoomParty::Unknown);
    }
    let bound = fold.vault_id.is_some()
        && crate::authority::actor_binding_is_active(fold, &member, "agent");
    let defined = matches!(
        crate::vault::live_entity_row_in_txn(&vault.store, txn, &member)?,
        LiveEntityRow::Live {
            entity_type: ENTITY_TYPE_AGENT_DEF,
            ..
        }
    );
    Ok(if bound || defined {
        RoomParty::VaultAgent
    } else {
        RoomParty::Unknown
    })
}

/// Whether `contact` is a contact Active in `txn`, by its claims. A revoked
/// contact keeps its disclosure-scope row, so its status, not that row,
/// decides. A row of another kind is no contact.
fn active_contact_in(vault: &Vault, txn: &heed::RoTxn<'_>, contact: &EntityId) -> Result<bool> {
    match vault.get_counterparty_contact_in_txn(txn, contact) {
        Ok(record) => {
            Ok(record.is_some_and(|record| record.status == CounterpartyContactStatus::Active))
        }
        Err(crate::Error::InvalidEntityType(_)) => Ok(false),
        Err(error) => Err(error),
    }
}

impl Vault {
    /// How the room meet sees each of `members`, read in one snapshot; see
    /// [`RoomParty`].
    pub fn room_parties(&self, members: &[EntityId]) -> Result<Vec<RoomParty>> {
        let txn = self.store.env.read_txn()?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        members
            .iter()
            .map(|member| room_party_in(self, &txn, &fold, *member))
            .collect()
    }
}
