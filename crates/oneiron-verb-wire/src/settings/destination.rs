//! Moved from `crates/oneiron/src/settings/destination.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

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
