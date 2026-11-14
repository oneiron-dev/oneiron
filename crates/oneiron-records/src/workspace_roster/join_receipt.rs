//! Moved from `crates/oneiron/src/workspace_roster/join_receipt.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
use oneiron_base::error::Result;
pub use oneiron_verb_wire::workspace_roster::join_receipt::RosterActor;
use serde::Deserialize;
use serde::Serialize;
use std::ops::Bound;

pub const JOIN_REF_DOMAIN: &str = "oneiron.rooms.join.v1";

pub const RECEIPT_PREFIX: &str = "rooms.join:";

/// A join ref: 64 lowercase hex.
pub fn is_join_ref(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub fn digest<T: Serialize>(value: &T) -> Result<String> {
    let bytes =
        serde_json::to_vec(value).map_err(|_| Error::InvariantViolation("join request encode"))?;
    Ok(blake3::hash(&bytes).to_hex().to_string())
}

/// What a Ready join committed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JoinParticipation {
    /// The person joined the ordinary room's membership ledger.
    LedgerSeat,
    /// The person already sat in the room's ledger; nothing was appended.
    AlreadySeated,
    /// A project home room: only its board seats members, so the join seats
    /// no one and this receipt is the participation evidence.
    HomeRoomReceipt,
    /// A thread keeps no ledger of its own, and seating the room would widen
    /// past the thread: this receipt is the participation evidence.
    BranchReceipt,
    /// An agent never takes a room seat: this receipt is its participation
    /// evidence.
    AgentReceipt,
    /// A companion attends through her principal's live standing: a seat of
    /// her own would outlive it, so this receipt, re-proved on each use, is
    /// her participation evidence.
    PrincipalReceipt,
}
