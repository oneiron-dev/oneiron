//! Moved from `crates/oneiron/src/agent_dispatch/run_task.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::HashMap;
use std::sync::PoisonError;

/// The executor of one agent run (FIX 4747; canon CROSS-ARCH-0019 item 03):
/// only the machine `node_id` names runs it, and only while the run TASK
/// still holds this holder at this `generation`. The holder renews
/// `held_until` while the run is its; a lease no pass renewed, or one its
/// holder released as it closed, is expired from `held_until` on, and the
/// reaper (`super::run_handover`) may hand it over at the next generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AgentRunExecutorLease {
    /// The holder's stable sync node id (`m:client_id`).
    pub node_id: u64,
    /// Raised by one on every handover and on every retake of an expired
    /// lease at a claim.
    pub generation: u64,
    /// Until when the holder holds it, vault clock seconds: expired at and
    /// after this instant.
    pub held_until: u64,
}

impl AgentRunExecutorLease {
    /// Whether `other` names this lease's holder at this generation,
    /// whatever either's `held_until`.
    #[must_use]
    pub fn same_holding(self, other: Self) -> bool {
        self.node_id == other.node_id && self.generation == other.generation
    }

    /// Whether the lease is expired at `now`.
    #[must_use]
    pub fn expired_at(self, now: u64) -> bool {
        now >= self.held_until
    }
}

/// How an agent run ended, as its TASK records it for every machine (FIX
/// 4747). `None` on the TASK while the run is live.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentRunOutcome {
    Completed,
    Failed,
    Cancelled,
}
