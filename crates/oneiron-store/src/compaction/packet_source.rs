//! The packet door's source bindings (FIX 4465). A conversation's packet
//! proves its turns through the witnessed TURN -> SESSION membership rows,
//! exactly as before. An executor run's log is numbered by its host: its
//! window's turns are the run's derived speech TURN in the run's derived
//! compaction session, which no membership row witnesses, and a derived id
//! is never passed off as a witnessed one. Its packet binds instead to the
//! run's retained replay record, read again here from the vault the summary
//! lands in: the span must be steps the run committed.

use oneiron_base::error::CompactionPacketError;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;

/// Where a packet's turns were cut from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompactionSource<'a> {
    /// A conversation: the witnessed membership checks.
    Conversation,
    /// An executor run's host-numbered log.
    HostLog(CompactionHostLog<'a>),
}

/// An executor run's retained steps `first..=last`, by its host-derived run
/// source and its run id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompactionHostLog<'a> {
    pub run_ref: &'a str,
    pub run_id: EntityId,
    pub first: u64,
    pub last: u64,
}

/// What a host-log packet was admitted against. The witness keeps it, so a
/// landing can check the packet is its gated request's own run and span.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostLogWitness {
    pub run_id: EntityId,
    pub first: u64,
    pub last: u64,
}
