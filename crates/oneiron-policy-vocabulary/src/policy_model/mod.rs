//! The policy-model modules moved out of `oneiron::policy_model`.
//!
//! - `contract` — the output contract and the rationale-notes reader.
//! - `pattern` — the substrate owner's pattern rules, compiled and matched.
//! - `goal_limits` — the thresholds a confirmed goal intake is counted against.

pub mod contract;
pub mod goal_limits;
pub mod pattern;
