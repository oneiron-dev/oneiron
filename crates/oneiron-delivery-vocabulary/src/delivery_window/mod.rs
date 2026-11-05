//! The delivery-window modules moved out of `oneiron::delivery_window`.
//!
//! - `types` — the claim keys, limits, verb classes, ladder rungs and decisions.
//! - `schedule_context` — the outbound schedule context a send is evaluated in.

pub mod schedule_context;
pub mod types;

// `schedule_context` names these through `super::`, as it did in `oneiron`.
pub use self::types::{DeliveryWindowApnsInterruptionLevel, DeliveryWindowResolvedLevel};
