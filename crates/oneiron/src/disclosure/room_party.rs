//! The term one room member brings to the room's meet (ARCH-0067 §8: "the
//! grants behind the people and agents present").

use super::disclosable_set::contact_clearance_in;
use crate::Vault;
use crate::authority::AuthorityFold;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::federation::Scope;
use crate::ports::EdgeDirection;
use crate::registry::{
    ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_COUNTERPARTY_CONTACT, ENTITY_TYPE_PERSON,
};

/// How the room meet sees a member who is not the vault owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RoomParty {
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
            Self::VaultAgent => None,
            Self::Contact(contact) => Some(contact_clearance_in(vault, txn, contact)?),
            Self::Unknown => Some(Scope::default()),
        })
    }
}

/// `member` as `txn` and its authority `fold` read it. A contact link is
/// read first: a member with any contact is that contact's party or, when
/// the link is ambiguous, unknown, never the vault's own agent.
pub(crate) fn room_party_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    fold: &AuthorityFold,
    member: EntityId,
) -> Result<RoomParty> {
    let contacts = vault.filtered_edge_peers(
        txn,
        EdgeDirection::In,
        &member,
        EdgeKind::About,
        Some(ENTITY_TYPE_COUNTERPARTY_CONTACT),
        "room contacts",
    )?;
    if let [contact] = contacts.as_slice() {
        let people = vault.filtered_edge_peers(
            txn,
            EdgeDirection::Out,
            contact,
            EdgeKind::About,
            Some(ENTITY_TYPE_PERSON),
            "room contacts",
        )?;
        if people.as_slice() == [member] {
            return Ok(RoomParty::Contact(*contact));
        }
    }
    if !contacts.is_empty() {
        return Ok(RoomParty::Unknown);
    }
    let bound = fold.vault_id.is_some()
        && crate::authority::actor_binding_is_active(fold, &member, "agent");
    let defined = crate::vault::live_entity_row_in_txn(&vault.store, txn, &member)?.is_live()
        && vault
            .store
            .port_entity_record(txn, &member)?
            .is_some_and(|record| record.entity_type == ENTITY_TYPE_AGENT_DEF);
    Ok(if bound || defined {
        RoomParty::VaultAgent
    } else {
        RoomParty::Unknown
    })
}

impl Vault {
    /// How the room meet sees each of `members`, read in one snapshot; see
    /// [`RoomParty`]. Whether a member is the vault owner is the caller's
    /// question: this never answers it.
    pub fn room_parties(&self, members: &[EntityId]) -> Result<Vec<RoomParty>> {
        let txn = self.store.env.read_txn()?;
        let fold = self.authority_fold_readonly_in_txn(&txn)?;
        members
            .iter()
            .map(|member| room_party_in(self, &txn, &fold, *member))
            .collect()
    }
}
