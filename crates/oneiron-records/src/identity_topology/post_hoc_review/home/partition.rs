//! Moved from `crates/oneiron/src/identity_topology/post_hoc_review/home/partition.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use heed::RoTxn;
use oneiron_base::error::Result;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;

/// One place a fact keeps: its value, or the place of an actor's piece.
#[derive(Serialize, Deserialize)]
pub enum Slot<T> {
    Fact(T),
    Actor,
}

/// Which row a decision receipt belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ReceiptOf {
    Selection,
    Result,
}

/// One piece of an actor's content, on the candidate it belongs to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TopologyAuditActorPiece {
    /// The actor is the candidate's subject at `index`.
    Subject { audit_id: [u8; 32], index: u32 },
    /// The actor is the record at `index` its review read.
    Evidence { audit_id: [u8; 32], index: u32 },
    /// The actor reviewed the candidate.
    Reviewer { audit_id: [u8; 32] },
    /// The actor is the principal of a decision receipt.
    ReceiptPrincipal { audit_id: [u8; 32], of: ReceiptOf },
    /// The evidence version at `index` of a decision receipt is of the
    /// actor's body, at this hash.
    ReceiptVersion {
        audit_id: [u8; 32],
        of: ReceiptOf,
        index: u32,
        body_hash: [u8; 32],
    },
}
