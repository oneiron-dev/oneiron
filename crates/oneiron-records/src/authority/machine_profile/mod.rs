//! Moved from `crates/oneiron/src/authority/machine_profile/mod.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::authority::*;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::sync::Arc;

/// Who admitted a chain of a machine's revisions.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum MachineAdmitter {
    /// The vault's roster, under the owner-held rule for an owned mark.
    Roster,
    /// One valid owner root's anchor key (Ed25519).
    Anchor([u8; 32]),
}

/// Whose authority signed a revision.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum SignerClass {
    /// A key the owner holds.
    OwnerHeld,
    /// A cloud root, or a key in the host's custody on a hosted vault: it
    /// registers a bootstrap node and carries it under a successor root, and
    /// never demotes, removes or answers for the owner (FIX 7920).
    Custodial,
    /// A linked machine's install key carrying the owner's act (mesh PR1b):
    /// the act answers for the owner, never the key, and the label says
    /// nothing of who holds the key. A revision it signed stands only while
    /// its act does.
    Carrier,
}

/// The root this install pins: only its anchor's chain is trusted here, and
/// only while the fold holds the root as valid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PinnedRoot {
    pub id: RecoveryRootId,
    pub anchor_key: [u8; 32],
}

/// The identity a trusted chain gives a machine: the keys that may sign as
/// it and be wrapped to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustedMachine<'a> {
    pub chain: MachineAdmitter,
    pub profile: &'a MachineProfile,
}
