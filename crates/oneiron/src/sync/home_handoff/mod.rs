//! FIX 5661 C1: the typed home-to-home handoff carrier. Each node elects the
//! vault's MACRO home on its own fold, and election moves no node-local
//! table, so a home move opens fresh node-local state on the new home. This
//! carrier moves the tables a domain registers ([`HomeTable`]) from the old
//! home to the new one.
//!
//! The old home records a drain request when its election moves the home
//! ([`request_move_in_txn`]). Once every registered table is quiescent it
//! freezes them in its final writer, exports every table from that one view,
//! and seals the manifest, signed with its install key, to the new home's
//! machine key ([`freeze_export`]). The new home verifies the whole manifest
//! before any write, then adopts every section in one transaction and signs
//! an ack ([`adopt`]). The old home keeps its frozen rows and payload as
//! non-executable history after the ack ([`ack_in_txn`]).
//!
//! Rows travel as each table's own typed DTO, never as raw rows, and land
//! through the table's own typed writes. The carrier knows no domain.
//!
//! The election records its move request and L07-A's six tables register
//! ([`home_tables`]). C2a's delivery ([`delivery`]) carries the handoff: the
//! target's engine doors on the residence RPC lane
//! (`sync::residence::home_handoff`) and the source's connection worker
//! (`sync::connection::home_handoff`). C2b orders both ends and restore
//! around it: the new home adopts a staged handoff, or records that none
//! came, before its first free-time pass ([`arrival`]); the old home drives
//! its own started free-time tries to their end so it can freeze
//! ([`drain`]); a restore keeps every registered table's rows live
//! ([`restore`]).
#![allow(
    dead_code,
    unused_imports,
    reason = "the carrier's surface is wider than this build's callers"
)]

mod arrival;
mod delivery;
mod drain;
mod envelope;
mod lineage;
mod registry;
mod restore;
mod routes;
mod store;
mod table;
mod transfer;

use serde::{Deserialize, Serialize};

use crate::entity_id::EntityId;
use crate::error::Error;

pub(crate) use arrival::prepare_arrival;
pub(crate) use delivery::{
    DeliveryPlan, ElectionMark, FrozenHandoff, cancel_frozen, decode_ack, delivery_plan,
    drop_staged, election_mark, encode_ack, fence_handoff, fenced_here, frozen_part, record_ack,
    record_unresolved, replan_fenced, stage_part, staged_position, staged_sealed, supersede_export,
    target_receipt,
};
pub(crate) use drain::free_time_arming;
pub(crate) use envelope::{
    HomeAck, SealedHandoff, VerifiedHandoff, VerifiedHomeAck, open_handoff, verify_ack,
};
pub(crate) use registry::{
    froze_home_state_in_txn, home_tables, pending_move_in_txn, takes_home_write_in_txn,
};
pub(crate) use restore::{HomeManaged, keep_move_through, restore_managed_keys};
pub(crate) use routes::{feed_fallback_route, feed_routes};
pub(crate) use store::{handoff_status_in_txn, incomplete_in_txn, record_incomplete_in_txn};
pub(crate) use table::{HomeTable, HomeTableRegistration, ImageRows, TableAdopt};
pub(crate) use transfer::{ack_in_txn, adopt, freeze_export, guard_in_txn, request_move_in_txn};

/// The most sealed bytes one stored or delivered part carries (CALLS:
/// HOME_HANDOFF_PART_BYTES): the sealed bundle's upload part, so one part
/// moves within one residence call. The whole handoff has no cap beyond the
/// envelope's own codec bound (Rule 5).
pub(crate) const HOME_HANDOFF_PART_BYTES: usize =
    crate::sync::residence::SEALED_BUNDLE_PUT_PART_MAX;

/// A handoff's id: the hash of its signed header.
pub(crate) type HandoffId = [u8; 32];

/// One end of a home move: the owner's machine and the sync node it runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct HomeIdentity {
    pub(crate) machine: EntityId,
    pub(crate) node_id: u64,
}

/// Where a move stands in the vault's home-state lineage. Only the node that
/// holds the state advances it; each later generation names the one before.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct HomeGeneration {
    pub(crate) serial: u64,
    pub(crate) predecessor: Option<HandoffId>,
}

/// One home move: what the source signs and the target checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct HomeMove {
    pub(crate) vault_id: [u8; 32],
    pub(crate) source: HomeIdentity,
    pub(crate) target: HomeIdentity,
    pub(crate) generation: HomeGeneration,
    /// A digest of the election evidence the source read for this move.
    pub(crate) election_basis: [u8; 32],
}

/// The move a table exports for or adopts under. Only the carrier mints one,
/// in the writer that freezes or adopts, so no caller can claim a move.
pub(crate) struct HomeFence {
    movement: HomeMove,
}

impl HomeFence {
    fn new(movement: HomeMove) -> Self {
        Self { movement }
    }

    pub(crate) fn movement(&self) -> &HomeMove {
        &self.movement
    }
}

/// What a domain write asks the fence for: a new admission, or the
/// settlement of one already admitted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HomeWrite {
    Admit,
    Settle,
}

/// What one adoption did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum AdoptOutcome {
    /// Every section landed in one transaction; the ack is signed.
    Adopted(HomeAck),
    /// This handoff, with these bytes, landed before; its saved ack.
    AlreadyAdopted(HomeAck),
    /// Not yet: this node's election does not name it home, the lineage
    /// does not chain here, or this build registers other tables.
    Pending,
    /// A generation this node is already past, or another target.
    Stale,
    /// Rows or a handoff here conflict with it; nothing landed.
    Conflict,
}

/// Where one handoff stands on this node.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum HandoffStatus {
    /// The source froze its rows and sealed them; no ack yet.
    Frozen,
    /// The target acked; the source keeps its rows as history.
    Acked,
    /// The target adopted every section.
    Adopted,
    /// No carrier moved the state (CALLS: no carrier).
    Incomplete(IncompleteReason),
    /// The source froze it, its target provably never adopted it, and the
    /// source took its state back (FIX 5931). Kept as history.
    Cancelled,
}

/// Why a home move carried nothing. The new home keeps today's local
/// opening; nothing refuses for it (CALLS: no carrier).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum IncompleteReason {
    /// The old home was gone before it exported.
    SourceGone,
    /// The move's lineage does not chain to one this node knows.
    UnknownLineage,
    /// Rows or a handoff here conflict with the move.
    Conflict,
    /// The move's target has no machine or endpoint known here.
    NoRoute,
    /// The target's persisted answer could not be read: out of reach,
    /// refused, or another machine on its socket. Not a proof either way.
    Unresolved,
    /// The new home opened with no usable handoff for its move staged
    /// (FIX 6457): what it opens locally is not the lineage's state.
    NotArrived,
}

fn refused(reason: &'static str) -> Error {
    Error::InvalidConfig(format!("home handoff refused: {reason}"))
}

/// Byte strings as msgpack bin, not arrays of numbers.
mod bin {
    use serde::{Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(bytes: &[u8], out: S) -> Result<S::Ok, S::Error> {
        out.serialize_bytes(bytes)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(input: D) -> Result<Vec<u8>, D::Error> {
        struct Visitor;
        impl serde::de::Visitor<'_> for Visitor {
            type Value = Vec<u8>;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("bytes")
            }
            fn visit_bytes<E: serde::de::Error>(self, bytes: &[u8]) -> Result<Vec<u8>, E> {
                Ok(bytes.to_vec())
            }
            fn visit_byte_buf<E: serde::de::Error>(self, bytes: Vec<u8>) -> Result<Vec<u8>, E> {
                Ok(bytes)
            }
        }
        input.deserialize_bytes(Visitor)
    }
}
