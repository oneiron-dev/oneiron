//! Moved from `crates/oneiron/src/dispatch_byoa/seat_quota.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::dispatch_byoa::seat::SeatSpent;
use serde::Deserialize;
use serde::Serialize;

/// One seat's quota as its captures last read it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RunnerSeatQuota {
    /// The seat's index in the owner's order, or in a quota read's request.
    pub seat: usize,
    /// The runner the seat names.
    pub runner: String,
    /// The spent refusal last read on the seat. `None` when none was, or a
    /// completed run on the seat cleared it.
    pub spent: Option<SeatSpent>,
    /// When the last reading was taken: its capture's settle time.
    pub observed_at: Option<u64>,
    /// When a spent seat is back ([`SeatSpent::back_at`] at its reading).
    /// `None` while a spent seat waits for the owner, and for a seat not
    /// spent.
    pub back_at: Option<u64>,
    /// Whether the seat may take work now: not spent, or back by now.
    pub available: bool,
    /// The capture the last reading came from, in lower-case hex: the spent
    /// attempt an owner's top-up names. `None` when no capture recorded one.
    pub last_capture: Option<String>,
    /// When the owner said the seat's spent credit was topped up, when that
    /// cleared its last reading.
    pub topped_up_at: Option<u64>,
}
