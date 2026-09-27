//! Consolidated integration-test binary for the vector suites.
//!
//! `tests/oracle.rs` stays a standalone target: it is gated on the
//! `seal-oracle` feature at the Cargo target level. `support` stays at
//! `tests/support/mod.rs` because both this binary and `oracle` include it.

#[path = "../support/mod.rs"]
mod support;

mod fetch_policy;
mod seal_vectors;
mod verify_vectors;
