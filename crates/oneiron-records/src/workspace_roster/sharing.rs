//! Moved from `crates/oneiron/src/workspace_roster/sharing.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_authority::federation::Scope;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

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
    /// A live call brings a listener the members do not cover: only public
    /// content may be disclosed while it is live.
    LiveCall,
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
