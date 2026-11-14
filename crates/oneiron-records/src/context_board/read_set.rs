//! Moved from `crates/oneiron/src/context_board/read_set.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::claim::served_lifecycle::ServedLifecycle;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

/// Open own proposals one session watches; every board read checks each, so
/// a burst past it is not watched by this session.
pub const MAX_OWN_PROPOSALS: usize = 1024;

/// Byte ceilings for the free-text parts of one changed event, so one event
/// row stays far inside the board's row-byte limit whatever the stored or
/// deserialized inputs hold.
pub const MAX_EVENT_REF_BYTES: usize = 256;

pub const MAX_EVENT_DIAGNOSTIC_BYTES: usize = 1024;

/// Served rows one session keeps a why for; past it, the oldest key leaves.
pub const MAX_SERVED_WHY: usize = 4096;

/// Why one served row appeared: the retrieval run that served it and its
/// place there, and the MEMORIES tier and hook a board rendered it with. A
/// pinned row a run never ranked names no run.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServedWhy {
    /// Hex retrieval run id, when the serving pack's telemetry persisted.
    pub run_id: Option<String>,
    /// 1-based place among the run's primary results; `None` for a neighbor
    /// or a row no run served.
    pub rank: Option<u32>,
    /// Reached as a graph neighbor of a result, not ranked itself.
    pub neighbor: bool,
    /// `pinned`, `snippet` or `index_only`, when a board rendered it.
    pub tier: Option<String>,
    /// `<pack>/<hook>` when a hook block pinned it.
    pub hook: Option<String>,
}

/// The answer behind a proposal outcome, always by reference: the policy row
/// that decided it, or the gate receipt that records who answered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalReason {
    /// The person's own answer: the owner's resolution the decision rests on.
    PersonWord(String),
    RuleRow(String),
    Receipt(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposalChange {
    /// approved, rejected, retracted, superseded or erased.
    pub to: String,
    pub reason: Option<ProposalReason>,
    /// Set on every rejection; it rides the next wake with the outcome.
    pub diagnostic: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorChange {
    Installed,
    Changed,
    Removed,
}

/// One live connector mount: its key and a fingerprint of the terms it runs
/// under (manifest, slate and protocol revisions, charter, budgets).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectorMount {
    pub key: String,
    pub fingerprint: String,
}

/// Rows a session's read set holds past which each served snapshot asks the
/// owner's threshold row. Below it no observation costs a read.
pub const READ_SET_CHECKED_FROM: usize = 4096;

/// Cut `text` to at most `max` bytes on a character boundary.
pub fn clip(text: &str, max: usize) -> &str {
    if text.len() <= max {
        return text;
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

/// The rows one lifecycle row names: the row, and its successor if it was
/// superseded. An installed pack's row is the pack's name, however it reads,
/// and names no row: its source is named apart.
pub fn lifecycle_refs(id: &str, state: &ServedLifecycle) -> Vec<String> {
    row_refs(id, state).map(str::to_owned).collect()
}

pub fn row_refs<'a>(id: &'a str, state: &'a ServedLifecycle) -> impl Iterator<Item = &'a str> {
    let own = (!matches!(state, ServedLifecycle::Installed(_))).then_some(id);
    let successor = match state {
        ServedLifecycle::Superseded(next) => Some(next.as_str()),
        _ => None,
    };
    own.into_iter().chain(successor)
}
