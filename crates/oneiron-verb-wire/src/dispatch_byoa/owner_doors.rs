//! Moved from `crates/oneiron/src/dispatch_byoa/owner_doors.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::dispatch_byoa::seat_quota::RunnerSeatQuota;
use serde::Deserialize;
use serde::Serialize;

/// The named seats' quotas.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RunnerSeatQuotasView {
    /// Each seat's quota in the request's order; its `seat` is its index
    /// there.
    pub quotas: Vec<RunnerSeatQuota>,
}

/// What a top-up did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RunnerSeatTopUpEffect {
    /// The named credit spend is cleared: the seat may take work again.
    Cleared,
    /// The named reading is no spend: cleared already, by this owner or a
    /// completed run.
    AlreadyClear,
    /// The seat's last reading is not the capture named: a later reading,
    /// or none. Nothing changed.
    ObservationChanged,
    /// The named reading is a spend other than credit (a rate limit or a
    /// usage window), which comes back on its own. Nothing changed.
    NotCredit,
}

/// A top-up's effect and the seat's quota after it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RunnerSeatTopUpReceipt {
    /// What the top-up did.
    pub effect: RunnerSeatTopUpEffect,
    /// The seat's quota now; its `seat` is 0.
    pub quota: RunnerSeatQuota,
}

/// Which seat a resume takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RunnerWorkResumeChoice {
    /// The seat at this index, spent or not.
    Seat(usize),
    /// The first seat from this index in the policy's order that this
    /// runtime may run and whose quota is not spent.
    NextSeat { from: usize },
}

/// A fallback seat a resume passed over, and why, in words.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SkippedRunnerSeatView {
    /// The seat's index in the policy's order.
    pub seat: usize,
    /// The runner the seat names.
    pub runner: String,
    /// Why the resume passed it over.
    pub reason: String,
}
