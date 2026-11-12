//! Moved from `crates/oneiron/src/settings/destination.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
use oneiron_base::error::RecordError;
use oneiron_base::error::Result;
use oneiron_base::machine_destination::Destination;
use oneiron_base::machine_destination::EffectiveRead;
use oneiron_contracts::entity_id::EntityId;
pub use oneiron_wake_contract::settings::destination::ReadDestination;

/// Where a read's caller sits relative to this device (DEC-0005). Only the
/// host decides it, from the connection the caller reached it on; nothing the
/// caller sends sets it. A device that forwards its caller's search to the
/// home states it there, signed with the request (FIX 3550).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum CallerLocality {
    /// On this device: the embedded host, or a caller on its local socket or
    /// loopback.
    OnDevice,
    /// Anywhere else.
    OffDevice,
}

/// The owner's recipient choice for a world, when it is a limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecipientChoice {
    /// One machine he named.
    OneMachine,
    /// Every machine he marked his.
    MyMachines,
}

/// Why a destination is not one the owner's choice admits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecipientWhy {
    /// No live machine proof names it.
    Unproved,
    /// It is a machine the owner did not mark his.
    NotMine,
    /// It is his, but not the machine he named.
    WrongMachine,
    /// He named different machines at once, so no machine reads the world
    /// until he picks again.
    Contended,
}

/// The owner's world recipient choice keeping a world from a destination
/// (L11-B (B)): named as his choice, and content-free, so a refusal that
/// carries it never names the world.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecipientLimit {
    pub choice: RecipientChoice,
    pub why: RecipientWhy,
}

impl RecipientLimit {
    /// The limit as a refusal states it.
    #[must_use]
    pub fn reason(self) -> &'static str {
        use RecipientChoice::{MyMachines, OneMachine};
        use RecipientWhy::{Contended, NotMine, Unproved, WrongMachine};
        match (self.choice, self.why) {
            (OneMachine, Unproved) => {
                "the owner chose one named machine; this destination has no live machine proof"
            }
            (OneMachine, NotMine) => {
                "the owner chose one named machine; this destination is not marked mine"
            }
            (OneMachine, WrongMachine) => {
                "the owner chose one named machine; this destination is not the named machine"
            }
            (OneMachine, Contended) => {
                "the owner chose one named machine; his picks conflict until he picks again"
            }
            (MyMachines, Unproved) => {
                "the owner chose machines marked mine; this destination has no live machine proof"
            }
            (MyMachines, NotMine | WrongMachine | Contended) => {
                "the owner chose machines marked mine; this destination is not marked mine"
            }
        }
    }

    /// The limit `read` puts on `destination`, or `None` when the world may
    /// be read there: the shared judge's rule, named.
    fn of(
        read: &EffectiveRead,
        destination: Destination,
        is_mine: impl Fn(EntityId) -> bool,
    ) -> Option<Self> {
        let choice = match read {
            EffectiveRead::Everywhere => return None,
            EffectiveRead::MyMachines => RecipientChoice::MyMachines,
            EffectiveRead::OneMachine(_) | EffectiveRead::Conflicted { .. } => {
                RecipientChoice::OneMachine
            }
        };
        let why = match destination {
            Destination::Unknown => RecipientWhy::Unproved,
            Destination::Machine(machine) if !is_mine(machine) => RecipientWhy::NotMine,
            Destination::Machine(machine) => match read {
                EffectiveRead::OneMachine(only) if *only != machine => RecipientWhy::WrongMachine,
                EffectiveRead::Conflicted { .. } => RecipientWhy::Contended,
                _ => return None,
            },
        };
        Some(Self { choice, why })
    }
}

impl std::fmt::Display for RecipientLimit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.reason())
    }
}

/// Why rows a read served may not leave for its destination now (mesh
/// PR2-reasons). Only [`Self::Recipient`] is the owner's choice; the rest
/// are integrity holds, which fail closed and say so.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseHold {
    /// The owner's recipient choice for a world a row lies in.
    Recipient(RecipientLimit),
    /// A row's world placement cannot be verified.
    Placement,
    /// The rows a retained result was derived from are unknown.
    ProducersUnknown,
    /// The vault root is conflicted, so no world's recipient policy can be
    /// judged.
    ConflictedRoot,
}

impl ReleaseHold {
    /// The hold as a refusal states it: content-free, with no world id.
    #[must_use]
    pub fn reason(self) -> &'static str {
        match self {
            Self::Recipient(limit) => limit.reason(),
            Self::Placement => "row/world placement cannot be verified",
            Self::ProducersUnknown => "retained result's producing rows are unknown",
            Self::ConflictedRoot => {
                "world recipient policy cannot be judged under a conflicted vault root"
            }
        }
    }

    /// Whether the owner's own choice holds the rows, rather than integrity.
    #[must_use]
    pub fn is_owner_choice(self) -> bool {
        matches!(self, Self::Recipient(_))
    }

    /// The typed refusal for a door that refuses rather than masks.
    #[must_use]
    pub fn into_error(self) -> Error {
        Error::Record(match self {
            Self::Recipient(_) => RecordError::WorldRecipientLimit(self.reason()),
            _ => RecordError::WorldPlacementUnverifiable(self.reason()),
        })
    }
}
