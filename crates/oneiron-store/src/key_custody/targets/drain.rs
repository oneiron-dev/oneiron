//! The journal's half of a member drain (FIX 5843, ruled 10-20): the owner's
//! door out of the required set, after the member's deletion ack, with a
//! set-history row at a new revision. Never a forced unpin, and no hosted
//! target or content backup is a member to drain.
//!
//! A begun drain is a durable fence (`drains/f.<target hex>`): the fenced
//! member takes no head and has no publication ack accepted, so no stale
//! publish or commit lands while it empties. The commit checks the ack
//! against the fence and writes the set once: the member out, the revision
//! up, and the history row with the drain's evidence beside it. Only then
//! go the fence and the member's ack bookkeeping. Nothing local is
//! deleted: custody's own keys, the keyless log and what a hold keeps all
//! stay. A pass never adds a drained member back; only the owner's
//! re-enrolment does, at a newer revision.

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use oneiron_base::error::Error;
use oneiron_base::error::Result;

use crate::key_custody::files::read_whole;
use crate::key_custody::files::replace_file;
use crate::key_custody::identity::hex_decode;
use crate::key_custody::log::CustodyPosition;
use crate::key_custody::protocol::TargetId;
use crate::key_custody::protocol::TargetKind;
use crate::key_custody::protocol::TargetSpec;
use crate::key_custody::protocol::drain::DRAIN_VERSION;
use crate::key_custody::protocol::drain::DrainToken;
use crate::key_custody::protocol::drain::drain_placement;
use crate::key_custody::protocol::hex;
use crate::key_custody::targets::ACKS;
use crate::key_custody::targets::Member;
use crate::key_custody::targets::RequiredSet;
use crate::key_custody::targets::TARGETS;
use crate::key_custody::targets::WIRE_VERSION;
use crate::key_custody::targets::decode;
use crate::key_custody::targets::encode;
use crate::key_custody::targets::journal_corrupt;
use crate::key_custody::targets::remove_quietly;
use crate::key_custody::targets::target_file;

pub const DRAINS: &str = "drains";

/// One owner change of the set's membership: its history, kept in the set
/// itself, so one write moves the members, the revision, the history and
/// the evidence together.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetEvent {
    /// The revision the change made.
    pub revision: u64,
    pub target: String,
    pub change: SetChange,
    /// A drain's evidence, from the member's accepted ack.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<DrainEvidence>,
    /// Unix seconds the change committed.
    pub at: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SetChange {
    Drained,
    Reenrolled,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DrainEvidence {
    /// The drain's operation id, 64 hex.
    pub operation_id: String,
    /// BLAKE3 (64 hex) of the accepted ack's named MessagePack.
    pub ack_digest: String,
    /// The member's post-deletion inventory digest, 64 hex.
    pub inventory_digest: String,
    /// Heads, stages and temporaries the member removed.
    pub superseded_removed: u64,
}

impl RequiredSet {
    /// Whether the owner drained `id` and has not re-enrolled it since.
    pub fn drained(&self, id: &TargetId) -> bool {
        self.history
            .iter()
            .rev()
            .find(|event| event.target == id.as_str())
            .is_some_and(|event| event.change == SetChange::Drained)
    }
}

pub fn refused(why: &str) -> Error {
    Error::InvalidConfig(format!("the custody member drain {why}"))
}

/// Whether two MACs are equal, every byte compared.
pub fn same_mac(left: &[u8], right: &[u8; 32]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .fold(0u8, |diff, (a, b)| diff | (a ^ b))
            == 0
}
