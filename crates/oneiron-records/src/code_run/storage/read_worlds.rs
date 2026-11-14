//! Moved from `crates/oneiron/src/code_run/storage/read_worlds.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::ops::RangeBounds;

/// The byte a header row's key ends with, after the run.
pub const HEADER_TAG: u8 = 0;

/// The byte a served row's scope proof carries between the run and the row.
pub const ROW_TAG: u8 = 2;

/// The key bytes every scope proof of `row` served to `run` starts with.
pub fn row_scope_prefix(run: EntityId, row: EntityId) -> Vec<u8> {
    let mut prefix = run.as_bytes().to_vec();
    prefix.push(ROW_TAG);
    prefix.extend_from_slice(row.as_bytes());
    prefix
}

/// Why a run's ledger misses rows it was served (FIX 6130). Any one of them
/// keeps the ledger from reading complete, for good.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadWorldUnknown {
    /// The run had a record before its ledger began: a continuation's copied
    /// prefix its source's ledger does not prove (FIX 7085), or a run from
    /// before the ledger.
    NotFromStart,
    /// The run's task is its host's, which may carry rows no capture noted.
    HostTask,
    /// A call was answered from a read no capture covers.
    Uncaptured,
    /// A verb hook showed the guest a view of its own in place of a call's
    /// answer.
    HookView,
    /// A callable skill ran inside a call, from the stored skill it loaded.
    CallableSkill,
    /// The run read a result another run kept.
    RetainedResult,
    /// A wait's reply reached the run.
    WaitReply,
    /// A self-written summary carried words from its home's rows into the
    /// run (FIX 7087).
    SelfWrittenSummary,
    /// A served row's world could not be proved in the read that served it.
    Unproved,
    /// A ledger write failed.
    WriteFailed,
}
