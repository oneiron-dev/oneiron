//! The term one room member brings to the room's meet (ARCH-0067 §8: "the
//! grants behind the people and agents present").

use super::disclosable_set::contact_clearance_in;
use crate::Vault;
use crate::authority::AuthorityFold;
use crate::counterparty_contact::CounterpartyContactStatus;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::registry::{ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_PERSON};
use crate::vault::LiveEntityRow;
use oneiron_authority::federation::Scope;

/// How the room meet sees a member.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RoomParty {
    /// The vault owner: the embedded owner, a live human owner binding in a
    /// rooted vault, or any live Owner member of the vault, co-Owners
    /// included (FIX 6526, FIX 6558). It adds no term.
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

/// One member's room party with the facts the party alone no longer
/// carries since FIX 6558 moved every reader onto the one live-Owner
/// notion: the contact a roster or roster-like read names the member by,
/// and whether the member is one of the vault's own agents. Read in the
/// same snapshot as the party.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoomPartyEntry {
    /// How the room meet sees the member.
    pub party: RoomParty,
    /// The contact this member is known by in the room: its sole linked
    /// Active contact (the member a live PERSON or AGENT_DEF), the contact
    /// the pre-6558 binding-only classifier named. `None` for the embedded
    /// or binding owner, and when the link is absent, ambiguous or not
    /// Active. A live co-Owner classes [`RoomParty::VaultOwner`] and keeps
    /// its contact here, so a speaker roster, a pack's no-reader meet and
    /// an entry's clearable contact keep naming it.
    pub contact: Option<EntityId>,
    /// Whether the member is one of the vault's own agents in the sense the
    /// pre-6558 classifier's [`RoomParty::VaultAgent`] named: not the
    /// embedded or binding owner, no linked contacts, and an active `agent`
    /// binding or a live AGENT_DEF. A live co-Owner who is also agent-bound
    /// classes VaultOwner and stays agent-side here, so its own reads keep
    /// bounding what it is served.
    pub vault_agent: bool,
}

/// `member`'s entry as `txn` and its authority `fold` read it, with the
/// live-Owner census `owners` already read in the same snapshot (empty when
/// the census cannot be read: it fails closed, and the member keeps the
/// class it had before FIX 6526, never a refusal). `admits`, when given,
/// scopes the contact links to a caller's read (FIX 8150): a contact it
/// refuses is absent here, as a missing one is; it neither names the
/// member's party nor makes the member unknown.
///
/// The vault owner comes first: every live vault Owner, co-Owners included
/// (FIX 6526). Then a contact link: a member with any contact is that
/// contact's party or, when the link is ambiguous or the contact is not
/// Active, unknown; never the vault's own agent. A contact names its member
/// when its identity head names that member, a PERSON or an AGENT_DEF.
/// Contacts are read from their claims (OF-272), so a dropped contact row
/// changes nothing.
fn room_party_entry_with(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    fold: &AuthorityFold,
    owners: &[EntityId],
    admits: Option<&dyn Fn(&EntityId) -> Result<bool>>,
    member: EntityId,
) -> Result<RoomPartyEntry> {
    let bound_owner = is_vault_owner(fold, crate::vault::embedded_owner_actor_id()?, &member);
    if bound_owner {
        // The embedded/binding owner's entry is fixed (VaultOwner, no
        // roster contact, never agent-side), as the classifier's first arm
        // always read it, without the contact and row reads below.
        return Ok(RoomPartyEntry {
            party: RoomParty::VaultOwner,
            contact: None,
            vault_agent: false,
        });
    }
    let owner = owners.contains(&member);
    let mut contacts = Vec::new();
    for contact in vault.counterparty_contact_ids_for_identity_in_txn(txn, &member)? {
        match admits {
            Some(admits) if !admits(&contact)? => {}
            _ => contacts.push(contact),
        }
    }
    let (actor, defined) = match crate::vault::live_entity_row_in_txn(&vault.store, txn, &member)? {
        LiveEntityRow::Live {
            entity_type: ENTITY_TYPE_PERSON,
            ..
        } => (true, false),
        LiveEntityRow::Live {
            entity_type: ENTITY_TYPE_AGENT_DEF,
            ..
        } => (true, true),
        _ => (false, false),
    };
    let sole_contact = match contacts.as_slice() {
        [contact] if actor && active_contact_in(vault, txn, contact)? => Some(*contact),
        _ => None,
    };
    let agent_bound = fold.vault_id.is_some()
        && crate::authority::actor_binding_is_active(fold, &member, "agent");
    let party = if owner {
        RoomParty::VaultOwner
    } else if let Some(contact) = sole_contact {
        RoomParty::Contact(contact)
    } else if !contacts.is_empty() {
        RoomParty::Unknown
    } else if agent_bound || defined {
        RoomParty::VaultAgent
    } else {
        RoomParty::Unknown
    };
    Ok(RoomPartyEntry {
        party,
        contact: sole_contact,
        vault_agent: contacts.is_empty() && (agent_bound || defined),
    })
}

/// [`room_party_entry_with`]'s party alone, for classification that needs
/// no contact. A member the live-Owner census names short-circuits to
/// VaultOwner before the fallible roster-contact reads (FIX 6558 P1): a
/// damaged linked contact must not turn a live Owner's clearance into an
/// error, as the pre-6558 classifier never read it. Consumers that need the
/// contact keep reading the full entry.
fn room_party_only_with(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    fold: &AuthorityFold,
    owners: &[EntityId],
    admits: Option<&dyn Fn(&EntityId) -> Result<bool>>,
    member: EntityId,
) -> Result<RoomParty> {
    if owners.contains(&member) {
        return Ok(RoomParty::VaultOwner);
    }
    Ok(room_party_entry_with(vault, txn, fold, owners, admits, member)?.party)
}

/// [`room_party_entry_with`] reading the live-Owner census itself.
pub(crate) fn room_party_entry_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    fold: &AuthorityFold,
    member: EntityId,
) -> Result<RoomPartyEntry> {
    let owners = crate::policy_model::owners_in_txn(vault, txn).unwrap_or_default();
    room_party_entry_with(vault, txn, fold, &owners, None, member)
}

/// `member` as `txn` and its authority `fold` read it; see
/// [`room_party_entry_with`].
pub(crate) fn room_party_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    fold: &AuthorityFold,
    member: EntityId,
) -> Result<RoomParty> {
    let owners = crate::policy_model::owners_in_txn(vault, txn).unwrap_or_default();
    room_party_only_with(vault, txn, fold, &owners, None, member)
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
    /// [`RoomParty`]. The vault owner is every live vault Owner, co-Owners
    /// included (FIX 6526, FIX 6558); a co-Owner's contact rides on
    /// [`Self::room_party_entries`].
    pub fn room_parties(&self, members: &[EntityId]) -> Result<Vec<RoomParty>> {
        let txn = self.store.env.read_txn()?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        let owners = crate::policy_model::owners_in_txn(self, &txn).unwrap_or_default();
        members
            .iter()
            .map(|member| room_party_only_with(self, &txn, &fold, &owners, None, *member))
            .collect()
    }

    /// [`Self::room_parties`] with each member's full entry: its party, the
    /// contact a roster names it by, and whether it is one of the vault's
    /// own agents, all in one snapshot (the live-Owner census read once).
    pub fn room_party_entries(&self, members: &[EntityId]) -> Result<Vec<RoomPartyEntry>> {
        let txn = self.store.env.read_txn()?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        let owners = crate::policy_model::owners_in_txn(self, &txn).unwrap_or_default();
        members
            .iter()
            .map(|member| room_party_entry_with(self, &txn, &fold, &owners, None, *member))
            .collect()
    }

    /// [`Self::room_parties`] in `read`'s own snapshot (FIX 8150): each
    /// member's contact links are those `read` reads, so a contact the caller
    /// cannot read changes no member's class. Every member is classed in one
    /// snapshot, under one policy.
    pub fn room_parties_under(
        &self,
        read: &crate::claim::ScopedRead<'_>,
        members: &[EntityId],
    ) -> Result<Vec<RoomParty>> {
        read.persist_grant_clock()?;
        let txn = self.store.env.read_txn()?;
        let policy = read.live_policy_manifest_in(&txn)?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        let owners = crate::policy_model::owners_in_txn(self, &txn).unwrap_or_default();
        let admits = |id: &EntityId| read.is_ref_readable_with_policy_in(&txn, &policy, id);
        members
            .iter()
            .map(|member| room_party_only_with(self, &txn, &fold, &owners, Some(&admits), *member))
            .collect()
    }

    /// [`Self::room_party_entries`] in `read`'s own snapshot (FIX 8150): each
    /// member's party, roster contact and agent standing in one snapshot,
    /// under one policy, so a consumer never mixes a party from one read
    /// with a contact from another.
    pub fn room_party_entries_under(
        &self,
        read: &crate::claim::ScopedRead<'_>,
        members: &[EntityId],
    ) -> Result<Vec<RoomPartyEntry>> {
        read.persist_grant_clock()?;
        let txn = self.store.env.read_txn()?;
        let policy = read.live_policy_manifest_in(&txn)?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        let owners = crate::policy_model::owners_in_txn(self, &txn).unwrap_or_default();
        let admits = |id: &EntityId| read.is_ref_readable_with_policy_in(&txn, &policy, id);
        members
            .iter()
            .map(|member| room_party_entry_with(self, &txn, &fold, &owners, Some(&admits), *member))
            .collect()
    }
}
