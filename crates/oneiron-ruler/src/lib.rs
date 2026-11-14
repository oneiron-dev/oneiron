//! The retrieval ruler of the oneiron engine (RESEARCH-0651 Tier 0).
//!
//! A ruler is a fixed pack of queries with graded relevance and precomputed
//! vectors. This crate holds only the pack format and the LongMemEval-S
//! converter, and it depends on no engine crate. See [`pack`] for the format
//! and [`longmemeval`] for the converter.
//! The [`scorecard`] module grades one retrieval run; [`metrics`] holds its pure functions.

pub mod longmemeval;
pub mod metrics;
pub mod pack;
pub mod scorecard;
