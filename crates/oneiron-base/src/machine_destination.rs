//! Machine destinations and folded read-location values.

use std::collections::BTreeSet;

use crate::entity_id::EntityId;

/// Where a world may be read, after every live edit is met.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum EffectiveRead {
    Everywhere,
    MyMachines,
    OneMachine(EntityId),
    /// Concurrent one-machine picks named different machines: readable
    /// nowhere until the owner re-picks from one of them.
    Conflicted {
        contenders: BTreeSet<EntityId>,
    },
}

/// A machine a world's rows may go to, or one nobody proved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Destination {
    Machine(EntityId),
    Unknown,
}

/// The machine at the other end of a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerMachine {
    /// A machine that proved, on this connection, the key it stands on here
    /// (the authority fold's machine proof key). The key stays with the proof:
    /// a later trusted identity under other keys is not this connection's.
    Proven { machine: EntityId, key: [u8; 32] },
    /// No proof, a proof that did not verify, or a machine not live here. It
    /// is never read as this machine or as one of the owner's.
    Unknown,
}
