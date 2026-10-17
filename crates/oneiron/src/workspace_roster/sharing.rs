//! Sharing reads (ONEIRON-ARCH-0063: the owner dials personal context per
//! contact; ONEIRON-ARCH-0067 §8: joining a room is never a widen).
//!
//! Two reads and one owner-confirmed set:
//!
//! * a room's effective scope, as every turn in it is clamped, with the
//!   reasons it is clamped and never whose clearance clamps it;
//! * one contact's stored and effective clearance, for the principal who
//!   controls the companion's source vault;
//! * that principal's standing yes to one frozen clearance offer for the
//!   contact (OF-417), through the authenticated change-and-confirm door.
//!
//! The dial is the per-contact clearance the disclosure module already
//! stores and the room meet already reads; this module adds no
//! `(room, companion)` grant and no second store. A missing or revoked
//! clearance reads as bottom, as it binds. The set confirms exactly the
//! offer the owner was shown, under the owner's own proof, in one write
//! transaction with every check; nothing here wraps the bare setter.

use super::*;
use crate::consent::{AuthenticatedOwner, ContactDisclosureOutcome};
use crate::disclosure::RoomParty;
use crate::error::RecordError;
use crate::federation::{Scope, ScopeAxis};
use crate::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};
use serde::{Deserialize, Serialize};

/// Why a room's scope is narrower than the vault's. Counts, never names: a
/// member learns that a contact's clearance binds the room, not which
/// contact's it is or what it allows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "clamp")]
pub enum RoomSharingClamp {
    /// The members' default worlds narrow what the room reads.
    Worlds,
    /// The room reads only its project's facets.
    Facets,
    /// `members` members are contacts: what may be disclosed here is met
    /// with each one's clearance.
    ContactClearance { members: usize },
    /// `members` members are no one this vault can tell (no contact, an
    /// ambiguous one, or one not active): only public content may be
    /// disclosed while they are in the room.
    Unknown { members: usize },
}

/// A room's sharing as its members read it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoomSharingView {
    pub room: EntityId,
    /// The room's Scope: its members' world ceiling met with their
    /// clearances, in the room's facets. Every member counts as present.
    pub effective: Scope,
    /// Why `effective` is narrower than the vault, in a fixed order.
    pub clamps: Vec<RoomSharingClamp>,
}

/// Whose dial: a companion, and the contact her source vault's clearance is
/// about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompanionSharingTarget {
    /// The companion's `PERSON`.
    pub companion: EntityId,
    /// The `COUNTERPARTY_CONTACT` the clearance is about.
    pub contact: EntityId,
}

/// A clearance as its owner set it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompanionSharingStored {
    pub scope: Scope,
    pub purpose: String,
    /// A revoked clearance keeps its row and binds as bottom.
    pub revoked: bool,
    pub updated_at: u64,
}

/// One contact's clearance, stored and as it binds now.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompanionSharingView {
    pub target: CompanionSharingTarget,
    /// `None` while no clearance is set.
    pub stored: Option<CompanionSharingStored>,
    /// What a room meet takes for this contact now: bottom while none is
    /// set, once it is revoked, or while the contact is not active.
    pub effective: Scope,
}

fn refused() -> Error {
    Error::Record(RecordError::ConversationDenied)
}

/// One contact's clearance as `txn` reads it, stored and as it binds now,
/// for a target whose controller is already proved.
fn sharing_view_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    target: &CompanionSharingTarget,
) -> Result<CompanionSharingView> {
    let crate::vault::LiveEntityRow::Live {
        entity_type: crate::registry::ENTITY_TYPE_COUNTERPARTY_CONTACT,
        body,
    } = crate::vault::live_entity_row_in_txn(&vault.store, txn, &target.contact)?
    else {
        return Err(Error::EntityNotFound);
    };
    let active =
        crate::counterparty_contact::decode_counterparty_contact_body(&body).is_ok_and(|record| {
            record.status == crate::counterparty_contact::CounterpartyContactStatus::Active
        });
    let stored = crate::disclosure::contact_clearance_in_txn(&vault.store, txn, &target.contact)?;
    let effective = match &stored {
        Some(clearance)
            if active && clearance.status == crate::disclosure::DisclosureScopeStatus::Active =>
        {
            clearance.scope.clone()
        }
        _ => Scope::default(),
    };
    Ok(CompanionSharingView {
        target: *target,
        stored: stored.map(|clearance| CompanionSharingStored {
            revoked: clearance.status == crate::disclosure::DisclosureScopeStatus::Revoked,
            scope: clearance.scope,
            purpose: clearance.purpose,
            updated_at: clearance.updated_at,
        }),
        effective,
    })
}

impl Memory<'_> {
    /// `room`'s effective scope and why it is clamped, for a member of the
    /// room. It reads the scope the room's turns are clamped to now, built
    /// in one snapshot as a turn builds it, and reports each clamp by count:
    /// no peer's clearance and no peer's party is named.
    pub fn rooms_sharing(&self, room: EntityId) -> MemoryResult<RoomSharingView> {
        if self.room_turn().is_some_and(|turn| turn.room != room)
            || !self.room_record_readable(room)?
        {
            return Err(refused().into());
        }
        let vault = self.vault();
        let txn = vault.store.env.read_txn().map_err(Error::from)?;
        let ceiling = crate::context_board::room_ceiling_in(vault, &txn, room, self.actor())?
            .ok_or_else(refused)?;
        let terms = ceiling.terms.get();
        let fold = vault.authority_view_readonly_in_txn(&txn)?;
        let (mut contacts, mut unknown) = (0, 0);
        for member in &ceiling.roster {
            match crate::disclosure::room_party_in(vault, &txn, &fold, *member)? {
                RoomParty::Contact(_) => contacts += 1,
                RoomParty::Unknown => unknown += 1,
                _ => {}
            }
        }
        let mut clamps = Vec::new();
        if terms.worlds.worlds != ScopeAxis::All {
            clamps.push(RoomSharingClamp::Worlds);
        }
        if terms.facets != ScopeAxis::All {
            clamps.push(RoomSharingClamp::Facets);
        }
        if contacts > 0 {
            clamps.push(RoomSharingClamp::ContactClearance { members: contacts });
        }
        if unknown > 0 {
            clamps.push(RoomSharingClamp::Unknown { members: unknown });
        }
        Ok(RoomSharingView {
            room,
            effective: terms.room_scope(),
            clamps,
        })
    }

    /// One contact's clearance in the companion's source vault, for the
    /// principal who controls that vault.
    ///
    /// Proved from stored bindings: the caller owns this vault, the
    /// companion is a model-backed PERSON here, and no workspace onboarding
    /// claimed her for another principal. A room host or admin reads
    /// nothing through it.
    pub fn companion_sharing_get(
        &self,
        target: &CompanionSharingTarget,
    ) -> MemoryResult<CompanionSharingView> {
        let vault = self.vault();
        let now = vault.store.clock.now_recorded_at();
        if vault.person_substrate(&target.companion, now)?
            != Some(crate::subject_model::PersonSubstrate::Model)
        {
            return Err(refused().into());
        }
        let txn = vault.store.env.read_txn().map_err(Error::from)?;
        if !crate::memory::actor_is_vault_owner_in_txn(
            vault,
            &txn,
            self.actor(),
            self.actor_class(),
        )? || companion_principal_in(vault, &txn, &target.companion)?
            .is_some_and(|principal| principal != self.actor())
        {
            return Err(refused().into());
        }
        Ok(sharing_view_in(vault, &txn, target)?)
    }

    /// The owner's standing yes to one frozen clearance offer for the
    /// contact `target` is about, from the owner's own direct request.
    ///
    /// Transport write access is not owner authority: only a surface the
    /// host bound to the owner's authenticated proof, naming this human
    /// actor, sets anything. Generated code, a room turn or an agent gets
    /// refused, never an offer filed or confirmed in its stead.
    pub fn companion_sharing_set(
        &self,
        target: &CompanionSharingTarget,
        proposal_ref: &str,
        expected_delta: &[u8],
    ) -> MemoryResult<CompanionSharingView> {
        let forbidden = || {
            MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "a contact's clearance changes only on the owner's own authenticated request",
                &["Confirm the offer from the owner's private surface."],
            )
        };
        let owner = self
            .owner_authorship()
            .filter(|_| {
                !self.writes_generated()
                    && self.room_turn().is_none()
                    && self.actor_class() == crate::EdgeActorClass::Human
            })
            .ok_or_else(forbidden)?;
        if owner.revalidate(self.vault())? != self.actor() {
            return Err(forbidden());
        }
        Ok(self
            .vault()
            .companion_sharing_set(owner, target, proposal_ref, expected_delta)?)
    }
}

impl Vault {
    /// The owner's standing yes to the frozen clearance offer `proposal_ref`
    /// (exactly `expected_delta`) for the contact `target` is about, and the
    /// clearance as it stands after, in one write transaction.
    ///
    /// The owner controls this source vault and this companion: she is a
    /// model-backed PERSON, and no workspace onboarding claimed her for
    /// another principal. The offer must be for `target.contact`. The confirm
    /// door then revalidates the owner, the offer, the active contact and its
    /// prior clearance, and writes the contact's one clearance row. Narrowing
    /// and revoking keep their own doors.
    pub fn companion_sharing_set(
        &self,
        owner: &AuthenticatedOwner,
        target: &CompanionSharingTarget,
        proposal_ref: &str,
        expected_delta: &[u8],
    ) -> Result<CompanionSharingView> {
        self.with_write_txn_grouped(|txn| {
            let actor = owner.revalidate_in_txn(self, txn)?;
            let now = crate::ports::recorded_at_in_txn(&self.store, txn)?;
            if crate::subject_model::person_substrate_in_txn(self, txn, &target.companion, now)?
                != Some(crate::subject_model::PersonSubstrate::Model)
                || companion_principal_in(self, txn, &target.companion)?
                    .is_some_and(|principal| principal != actor)
                || self
                    .contact_disclosure_offer_in_txn(txn, proposal_ref)?
                    .is_none_or(|proposal| proposal.offer.contact_ref != target.contact)
            {
                return Err(refused());
            }
            self.confirm_contact_disclosure_in_txn(
                txn,
                owner,
                proposal_ref,
                expected_delta,
                ContactDisclosureOutcome::Standing,
            )?;
            sharing_view_in(self, txn, target)
        })
    }
}
