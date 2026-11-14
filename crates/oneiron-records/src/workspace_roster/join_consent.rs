//! Moved from `crates/oneiron/src/workspace_roster/join_consent.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::workspace_roster::project;
use crate::workspace_roster::rooms;
use oneiron_contracts::entity_id::EntityId;
pub use oneiron_contracts::room_join::ConsentNeed;
pub use oneiron_contracts::room_join::ConsentPart;
pub use oneiron_contracts::room_join::JoinSubject;
pub use oneiron_contracts::room_join::RequiredParty;
pub use oneiron_contracts::room_join::RoomJoinHold;
use oneiron_verb_wire::workspace_roster::join_receipt::RosterActor;
use serde::Deserialize;
use serde::Serialize;

/// The room a piece of work runs in, and its thread when the work is
/// narrower than the room.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoomWork {
    pub room: EntityId,
    pub branch: Option<EntityId>,
}

/// A party's recorded no. It stays a no once that party is erased, naming
/// no one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentDenial {
    pub party: RosterActor,
    pub answer_ref: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsentState<T> {
    Missing(ConsentNeed),
    Granted(T),
    Denied(ConsentDenial),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MembershipConsent {
    /// The owner of a personal vault.
    VaultOwner { person: EntityId },
    /// A live roster grant in a shared vault, a Delegate's included.
    Member { person: EntityId, grant: EntityId },
    /// A companion attends through its principal's membership. `grant` is
    /// `None` when the principal owns a personal vault.
    CompanionOfMember {
        companion: EntityId,
        principal: EntityId,
        grant: Option<EntityId>,
    },
    /// A live guest grant. It never counts as member standing and never
    /// enrolls anyone.
    ScopedGuest {
        person: EntityId,
        guest_grant: EntityId,
    },
    /// The workspace house mind, the org given a pen: institutional standing,
    /// read from the stored roster preset and valid only in its own
    /// workspace vault.
    HouseAgent { org: EntityId },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionBasis {
    /// The subject's own PERSON owns the room.
    RoomOwner,
    /// The subject's own PERSON holds the room's delegate action.
    DelegatedHost,
    /// The room is a project home room and the subject sits on the project's
    /// effective roster (home-room members are the project's roster): a
    /// person by its PERSON or by a seat that acts as that person.
    StandingHomeRoster,
    /// The room's owner or a delegated host answered yes for this join.
    HostAnswer { answer_ref: String },
    /// A companion attends the rooms her member attends (ARCH-0063): her
    /// live principal stands in the room, on the home room's roster or as
    /// the ordinary room's owner or a current ledger member. Decided again
    /// on every use, so the principal leaving or losing standing ends it.
    ThroughPrincipal { principal: EntityId },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionConsent {
    pub room: EntityId,
    pub branch: Option<EntityId>,
    pub subject: JoinSubject,
    /// The host that admitted, the subject itself as host, the project
    /// whose roster seats it, or the principal a companion attends through;
    /// no one once that host was erased.
    pub granted_by: RosterActor,
    pub basis: AdmissionBasis,
}
