//! Moved from `crates/oneiron/src/fanout_auto.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use serde_json::json;
use std::collections::BTreeSet;

// ---------------------------------------------------------------------------
// The verdict vocabulary
// ---------------------------------------------------------------------------

/// What an ES-07 ask resolves to.
///
/// Closed at three arms with pinned wire tokens `allow`, `deny`, and
/// `escalate-to-human`. They are the ask's only options: any other answer, or
/// none, is no verdict and therefore escalates.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FanoutAskVerdict {
    /// The fan-out may start as asked.
    Allow,
    /// The fan-out should not start. Still surfaced, never a silent kill.
    Deny,
    /// Nobody here is entitled to rule; a human sees it.
    EscalateToHuman,
}

// ---------------------------------------------------------------------------
// The shared decision path
// ---------------------------------------------------------------------------

/// One past human ruling, flattened for a decision state that has no business
/// decoding ED-01's Δ.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FanoutHistoryRuling {
    /// A human approved the ask.
    Approve,
    /// A human denied it.
    Deny,
    /// A human changed it.
    Amend,
}

/// One `(scope, trigger)` pair's ruling history, as the decision sees it.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct FanoutDecisionHistory {
    /// Approvals recorded for the exact `(scope, trigger)` key.
    pub approve: u32,
    /// Denials recorded for the exact key.
    pub deny: u32,
    /// Amendments recorded for the exact key.
    pub amend: u32,
    /// ED-06's `last_rulings`, bounded by that lane's own
    /// `ESCALATION_LAST_RULINGS_BOUND`: the newest eight, oldest-to-newest.
    pub last_rulings: Vec<FanoutHistoryRuling>,
}
