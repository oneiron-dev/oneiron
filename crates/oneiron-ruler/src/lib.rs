//! The retrieval ruler of the oneiron engine (RESEARCH-0651 Tier 0).
//!
//! A ruler is a fixed pack of queries with graded relevance and precomputed
//! vectors. This crate depends on no engine crate. See [`pack`] for the format
//! and [`longmemeval`] and [`trec_collection`] for the converters.
//! The [`scorecard`] module grades one retrieval run; [`metrics`] holds its pure functions.
//! Acceptance: [`axes`] reads scorecard axis values, [`bootstrap`] runs the
//! paired bootstrap, [`ruler_paths`] lists the paths a candidate may not
//! touch, [`sealed`] holds the sealed-once markers and [`proposal`] the
//! write-once proposal records. The crate reads no wall clock.

pub mod axes;
pub mod bootstrap;
pub mod longmemeval;
pub mod metrics;
pub mod pack;
pub mod proposal;
pub mod ruler_paths;
pub mod scorecard;
pub mod sealed;
pub mod trec_collection;
