//! Moved from `crates/oneiron/src/booking/constraint.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_verb_wire::booking::constraint::BookingError;
pub use oneiron_verb_wire::booking::constraint::CONSTRAINT_SCHEMA_VERSION;
pub use oneiron_verb_wire::booking::constraint::ConstraintWeekday;
pub use oneiron_verb_wire::booking::constraint::EventTypeKey;
pub use oneiron_verb_wire::booking::constraint::LocalMinuteWindow;
pub use oneiron_verb_wire::booking::constraint::RankedSlot;
use serde::Deserialize;
use serde::Serialize;

/// Exact host choice made by routing for one half-open slot. This travels to
/// confirmation, not to the public availability mask.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct SlotHostBinding {
    pub start_utc: u64,
    pub end_utc: u64,
    /// One host for Either, every participating host for Both; canonical hex.
    pub host_refs: Vec<String>,
    /// IANA zone per host, in the same order as `host_refs`. This travels
    /// with the solver choice into confirmation, not the public slot mask.
    pub host_zones: Vec<String>,
}

/// What the oracle returned. Host bindings belong to this solve, never to a
/// later configuration lookup. Confirmation refuses a slot without a binding.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct SolveResult {
    pub slots: Vec<RankedSlot>,
    pub flex_used: bool,
    pub host_bindings: Vec<SlotHostBinding>,
}

/// The final availability mask shape, settled from day one. There is no
/// artifact wrapper and no migration path: no consumer ships before it.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct SlotMask {
    pub event_type: EventTypeKey,
    pub window_start_utc: u64,
    /// Half-open `[window_start_utc, window_end_utc)`.
    pub window_end_utc: u64,
    pub slots: Vec<RankedSlot>,
    pub flex_used: bool,
}

/// Per-session dials. Caller-supplied values, not a new approval wall.
pub struct ConstraintSessionCaps {
    pub max_turns: u16,
    pub max_model_calls: u16,
}

/// Per-session counters. Admission is checked BEFORE an LLM request is built or
/// sent, and before the oracle is called.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConstraintSessionState {
    pub turns_used: u16,
    pub model_calls_used: u16,
}

impl ConstraintSessionState {
    pub fn admit_turn(&mut self, caps: &ConstraintSessionCaps) -> Result<(), BookingError> {
        self.turns_used = admit(self.turns_used, caps.max_turns)?;
        Ok(())
    }

    pub fn admit_model_call(&mut self, caps: &ConstraintSessionCaps) -> Result<(), BookingError> {
        self.model_calls_used = admit(self.model_calls_used, caps.max_model_calls)?;
        Ok(())
    }
}

pub fn admit(used: u16, cap: u16) -> Result<u16, BookingError> {
    used.checked_add(1)
        .filter(|next| *next <= cap)
        .ok_or(BookingError::SessionCapExhausted)
}
