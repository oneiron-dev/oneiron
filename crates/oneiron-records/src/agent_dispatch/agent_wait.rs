//! Moved from `crates/oneiron/src/agent_dispatch/agent_wait.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// What a stored row that does not read as a wait is.
pub const CORRUPT: &str = "agent child wait set";

/// One AGENT child a wait names, once it has ended.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentWaitChild {
    /// The child's attempt id, hex, as the wait named it.
    pub attempt: String,
    /// How it ended: `completed`, `failed`, `cancelled` or `abandoned`;
    /// `gone` when its row was pruned after it ended.
    pub state: String,
    /// The ref of the result it attached, when it attached one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_ref: Option<String>,
}

/// One reduction of a wait over a run's AGENT children.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentWaitSetResult {
    /// The wait's id, hex: the same for every call of its step key, and the
    /// id a run parked on the wait is parked under.
    pub wait: String,
    /// The children that have ended, in the order the wait named them.
    pub settled: Vec<AgentWaitChild>,
    /// The children still queued or running: their attempt ids, hex.
    pub pending: Vec<String>,
    /// Whether the wait is over. A done reduction is kept, and answers every
    /// later call of the same step key.
    pub done: bool,
    /// Why it is done: `all`, `quorum`, `impossible` or `cutoff` (its
    /// `until` passed first); `None` while it is not.
    pub reason: Option<String>,
}

/// How many children a wait waits for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AgentWaitPolicy {
    /// Every child has ended.
    All,
    /// This many children have completed.
    NOf { n: u32 },
}
