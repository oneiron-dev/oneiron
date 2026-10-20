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
    /// The vault owner: the embedded owner, a live human owner binding in a
    /// rooted vault, or any live Owner member of the vault, co-Owners
    /// included (FIX 6526). It adds no term. `Vault::room_parties` and the
    /// callers that record or ask about one member read the first two alone.
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

/// Which members [`room_party_in`] calls the vault owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RoomPartyOwnerRule {
    /// [`is_vault_owner`]: the embedded owner, or a live human owner binding
    /// in a rooted vault. The rule before FIX 6526, which
    /// [`bound_room_party_in`] keeps.
    BoundOwner,
    /// [`Self::BoundOwner`], or any live Owner member of the vault, co-Owners
    /// included, by the live-Owner census the vault's Owner/Admin check
    /// reads (`policy_model::owners_in_txn`, as
    /// `workspace_roster::vault_owner_or_admin_in` does). An Owner member who
    /// is not live is none, and a pen of an Owner keeps its own class.
    LiveOwnerMember,
}

/// CALLS `FIX 6526 one notion of Owner`: the rule [`room_party_in`] reads.
/// Every live vault Owner is clearance-free in room and thread ceilings, the
/// same as the embedded owner; only an Admin narrows (FIX 6336, 6497).
const ROOM_PARTY_OWNER_RULE: RoomPartyOwnerRule = RoomPartyOwnerRule::LiveOwnerMember;

/// Whether `member` is the vault owner under `rule`, as `txn` and its
/// authority `fold` read it.
fn is_room_owner_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    fold: &AuthorityFold,
    member: &EntityId,
    rule: RoomPartyOwnerRule,
) -> Result<bool> {
    if is_vault_owner(fold, crate::vault::embedded_owner_actor_id()?, member) {
        return Ok(true);
    }
    Ok(match rule {
        RoomPartyOwnerRule::BoundOwner => false,
        // The census fails closed: one it cannot read (a shared vault whose
        // creating owner holds no live Owner grant) promotes no one, and the
        // member keeps the class it had before FIX 6526, never a refusal.
        RoomPartyOwnerRule::LiveOwnerMember => matches!(
            crate::policy_model::is_live_vault_owner_in_txn(vault, txn, member),
            Ok(true)
        ),
    })
}

/// `member` as `txn` and its authority `fold` read it. The vault owner comes
/// first, by [`ROOM_PARTY_OWNER_RULE`]: every live vault Owner, co-Owners
/// included (FIX 6526). Then a contact link: a member with any contact is
/// that contact's party or, when the link is ambiguous or the contact is not
/// Active, unknown; never the vault's own agent. A contact names its member
/// when its identity head names that member, a PERSON or an AGENT_DEF.
/// Contacts are read from their claims (OF-272), so a dropped contact row
/// changes nothing.
pub(crate) fn room_party_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    fold: &AuthorityFold,
    member: EntityId,
) -> Result<RoomParty> {
    room_party_under_in(vault, txn, fold, member, ROOM_PARTY_OWNER_RULE)
}

/// [`room_party_in`] with the vault owner read as before FIX 6526: the
/// embedded owner or a live human owner binding in a rooted vault alone, so
/// a co-Owner without that binding keeps its contact's party, or unknown.
/// For the callers that record or ask about one member rather than meet its
/// clearance, where the wider class would drop or narrow what they do: a new
/// room's first entries, an entry's contact the owner clears, and
/// [`Vault::room_parties`].
pub(crate) fn bound_room_party_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    fold: &AuthorityFold,
    member: EntityId,
) -> Result<RoomParty> {
    room_party_under_in(vault, txn, fold, member, RoomPartyOwnerRule::BoundOwner)
}

/// [`room_party_in`] with the vault owner read under `rule`.
fn room_party_under_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    fold: &AuthorityFold,
    member: EntityId,
    rule: RoomPartyOwnerRule,
) -> Result<RoomParty> {
    if is_room_owner_in(vault, txn, fold, &member, rule)? {
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
    /// How a room's members are classed, read in one snapshot; see
    /// [`RoomParty`]. The vault owner is read as before FIX 6526
    /// (`bound_room_party_in`): a context pack's interlocutors and a voice
    /// call's speaker candidates keep a co-Owner's contact.
    pub fn room_parties(&self, members: &[EntityId]) -> Result<Vec<RoomParty>> {
        let txn = self.store.env.read_txn()?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        members
            .iter()
            .map(|member| bound_room_party_in(self, &txn, &fold, *member))
            .collect()
    }
}
