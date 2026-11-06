//! Reserved actor tokens for queued-attempt holds.

/// The intervention actor of a budget hold. Reserved: no other intervention
/// may name it, so a person's pause never reads as a hold.
pub const BUDGET_HOLD_ACTOR: &str = "engine:budget_hold";
