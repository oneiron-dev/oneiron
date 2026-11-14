//! Moved from `crates/oneiron/src/check_in/role_preset.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::check_in::act_class::ActClass;
use crate::check_in::mode::CheckInMode;
use serde::Deserialize;
use serde::Serialize;

/// One cell of the role table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RoleDefault {
    /// The role holds the power; this is its default mode.
    Mode(CheckInMode),
    /// The role holds the power only when its Grant names it; then this mode.
    IfNamed(CheckInMode),
    /// The role acts on its own proof (the Owner on a catastrophe row).
    OwnProof,
    /// As [`Self::OwnProof`], with the veto window as the delay-window proof
    /// when the vault has two or more Owners.
    OwnProofWithVetoWindow,
    /// No power; the role may open a proposal to a holder.
    Propose,
    /// No verb.
    NoVerb,
    /// Not applicable: the Owner already holds every power.
    NotApplicable,
}

pub const GO: RoleDefault = RoleDefault::Mode(CheckInMode::NeverAsk);

pub const UNSURE: RoleDefault = RoleDefault::Mode(CheckInMode::AskWhenUnsure);

pub const ASK: RoleDefault = RoleDefault::Mode(CheckInMode::AlwaysAsk);

pub const NAMED_GO: RoleDefault = RoleDefault::IfNamed(CheckInMode::NeverAsk);

pub const NAMED_ASK: RoleDefault = RoleDefault::IfNamed(CheckInMode::AlwaysAsk);

pub const NAMED_UNSURE: RoleDefault = RoleDefault::IfNamed(CheckInMode::AskWhenUnsure);

pub const OWN: RoleDefault = RoleDefault::OwnProof;

pub const OWN_VETO: RoleDefault = RoleDefault::OwnProofWithVetoWindow;

pub const PROPOSE: RoleDefault = RoleDefault::Propose;

pub const NO_VERB: RoleDefault = RoleDefault::NoVerb;

pub const NA: RoleDefault = RoleDefault::NotApplicable;

/// ARCH-0082's role table: one row per act class in [`ActClass::ALL`] order,
/// one column per role in [`RolePreset::ALL`] order. Qualifiers the cells
/// carry in canon ("with step-up", "in scope", "own items", "named powers
/// only") are grant-scope and proof facts, not modes.
///
/// Rows canon leaves out: `Spawn` carries the shipped fan-out default (ask
/// when unsure) for every role but Guest; `RoomAdd` is ask when unsure for
/// every role that adds to rooms, as canon says of an agent's add (a Delegate
/// only when its Grant names it; a closed room's own ask is a room rule, not
/// a default); the four floor rows outside the main table follow the C rule
/// (`AlwaysAsk` for every role but Owner).
#[rustfmt::skip]
pub static ROLE_DEFAULTS: [[RoleDefault; 7]; 20] = [
    // Columns: Owner, Deputy, Admin, Steward, Member, Delegate, Guest.
    [GO, GO, GO, GO, GO, GO, PROPOSE],                    // ReversibleWork
    [UNSURE, UNSURE, UNSURE, UNSURE, UNSURE, UNSURE, NO_VERB], // Spawn
    [GO, UNSURE, PROPOSE, PROPOSE, PROPOSE, PROPOSE, NO_VERB], // SpendOverCap
    [GO, UNSURE, ASK, NO_VERB, ASK, NAMED_ASK, NO_VERB],  // OutboundSend
    [UNSURE, UNSURE, UNSURE, UNSURE, UNSURE, NAMED_UNSURE, NO_VERB], // RoomAdd
    [GO, UNSURE, GO, PROPOSE, NO_VERB, NO_VERB, NO_VERB], // MemberAdd
    [GO, ASK, GO, PROPOSE, NO_VERB, NO_VERB, NO_VERB],    // MemberRemove
    [GO, UNSURE, PROPOSE, NO_VERB, NO_VERB, NAMED_ASK, NO_VERB], // LegalSend
    [OWN, ASK, NO_VERB, NO_VERB, NO_VERB, NO_VERB, NO_VERB], // Sign
    [GO, UNSURE, PROPOSE, NO_VERB, NO_VERB, NO_VERB, NO_VERB], // Billing
    [GO, UNSURE, GO, PROPOSE, GO, NAMED_GO, NO_VERB],     // Delete
    [OWN_VETO, ASK, NO_VERB, NO_VERB, NO_VERB, NO_VERB, NO_VERB], // VaultDelete
    [OWN_VETO, ASK, PROPOSE, PROPOSE, PROPOSE, PROPOSE, PROPOSE], // Erase
    [OWN, ASK, NO_VERB, NO_VERB, NO_VERB, NO_VERB, NO_VERB], // OwnershipTransfer
    [OWN, ASK, ASK, ASK, ASK, ASK, ASK],                  // KeyRecovery
    [OWN, ASK, ASK, ASK, ASK, ASK, ASK],                  // SecurityControlDisable
    [OWN, ASK, ASK, ASK, ASK, ASK, ASK],                  // MassSecretExport
    [OWN, ASK, ASK, ASK, ASK, ASK, ASK],                  // WorldWiden
    [GO, UNSURE, GO, PROPOSE, PROPOSE, NO_VERB, NO_VERB], // GrantWiden
    [NA, ASK, ASK, ASK, ASK, NO_VERB, NO_VERB],           // GrantWidenOwn
];
